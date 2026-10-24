"""Owned observer JSON-log capture for test-observer.py.

No Kubernetes mutation occurs here. kubectl log followers are local child
processes, tied to the run-owned Pod UID and an observed CRI container ID.
"""
import json
from pathlib import Path
import subprocess
import threading
import time

SYSTEM = "cmtc-system"
DS = "cmtc-bpf-observer"
OWNER = "security.cmtc.io/observer-run"
MAX_BYTES = 2_000_000
MAX_LINE = 65536
MAX_EVENTS = 1024


def check(condition, message):
    if not condition:
        raise AssertionError(message)


class ObserverLogFollower:
    """Bounded readers preserve original output and reap only their own child."""
    def __init__(self, argv, env, stdout_path, stderr_path):
        self.argv = argv
        self.stdout_path = Path(stdout_path)
        self.stderr_path = Path(stderr_path)
        self.lock = threading.Lock()
        self.events = []
        self.errors = []
        self.closed = False
        self.process = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, bufsize=0)
        self.threads = []
        for stream, destination, application in [(self.process.stdout, self.stdout_path, True),
                                                 (self.process.stderr, self.stderr_path, False)]:
            thread = threading.Thread(target=self._read, args=(stream, destination, application), daemon=True)
            self.threads.append(thread)
            thread.start()

    def _error(self, message):
        with self.lock:
            self.errors.append(message)
        # A broken/overflowing collector cannot silently continue qualification.
        if self.process.poll() is None:
            try: self.process.terminate()
            except ProcessLookupError: pass

    def _read(self, stream, destination, application):
        total = 0
        try:
            with destination.open("wb") as output:
                while True:
                    # Pipe is unbuffered. readline(size) bounds a malformed line.
                    raw = stream.readline(MAX_LINE + 1)
                    if not raw:
                        break
                    if len(raw) > MAX_LINE:
                        self._error("observer log line exceeds capture bound")
                        break
                    total += len(raw)
                    if total > MAX_BYTES:
                        self._error("observer log stream exceeds capture bound")
                        break
                    output.write(raw)
                    output.flush()
                    if application:
                        try: event = json.loads(raw)
                        except (json.JSONDecodeError, UnicodeDecodeError): continue
                        if isinstance(event, dict):
                            with self.lock:
                                if len(self.events) >= MAX_EVENTS:
                                    overflow = True
                                else:
                                    self.events.append(event)
                                    overflow = False
                            if overflow:
                                self._error("observer JSON event count exceeds capture bound")
                                break
        except Exception as error:
            self._error("observer reader failed: " + repr(error))
        finally:
            stream.close()

    def records(self):
        with self.lock:
            check(not self.errors, "observer log capture failed: " + "; ".join(self.errors))
            return list(self.events)

    def wait_event(self, predicate, description, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for event in self.records():
                if predicate(event):
                    return event
            # Read EOF may lag process exit; don't reject before reader drains.
            if self.process.poll() is not None and not any(t.is_alive() for t in self.threads):
                break
            time.sleep(0.05)
        raise AssertionError("missing observer log evidence: " + description + "; events=" + repr(self.records()))

    def stop(self, wait_for_eof=False):
        if self.closed:
            return
        if wait_for_eof and self.process.poll() is None:
            # Pod deletion/container exit normally ends kubectl's stream. Give
            # it a bounded chance to deliver the final deferred/error records.
            try: self.process.wait(timeout=2)
            except subprocess.TimeoutExpired: pass
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=4)
        for reader in self.threads:
            reader.join(timeout=3)
            check(not reader.is_alive(), "observer log reader did not exit")
        self.closed = True
        # Reader errors remain failures even after successful process reaping.
        self.records()


class ObserverLogCaptureMixin:
    """Requires existing Harness.out/env/report/run_id/owned/get/flush/poll."""
    def observer_log_init(self):
        self.observer_followers = {}
        self.active_observer_follower = {}
        self.observer_log_sequence = 0

    @staticmethod
    def _observer_status(pod):
        statuses = pod.get("status", {}).get("containerStatuses", [])
        selected = [status for status in statuses if status.get("name") == "observer"]
        check(len(selected) == 1 and selected[0].get("containerID"), "missing exact observer container identity")
        return selected[0]

    def _owned_observer(self, cluster, pod):
        check(pod["metadata"].get("labels", {}).get(OWNER) == self.run_id,
              "refuse logs from unowned observer Pod")
        ds_uids = {item[3] for item in self.owned.get(cluster, []) if item[0] == "DaemonSet" and item[2] == DS}
        owners = pod["metadata"].get("ownerReferences", [])
        check(any(owner.get("kind") == "DaemonSet" and owner.get("uid") in ds_uids
                  and owner.get("name") == DS for owner in owners), "observer Pod controller ownership mismatch")
        return self._observer_status(pod)

    def capture_observer_logs(self, cluster, pod, phase):
        status = self._owned_observer(cluster, pod)
        key = (cluster, pod["metadata"]["uid"], status["containerID"])
        check(key not in self.observer_followers, "duplicate log follower for same container")
        check(cluster not in self.active_observer_follower, "old observer follower must be retired before selecting a successor")
        self.observer_log_sequence += 1
        stem = f"{cluster}-observer-{self.observer_log_sequence:02d}-{phase}"
        stdout = self.out / (stem + ".jsonl")
        stderr = self.out / (stem + ".kubectl-stderr.log")
        argv = ["kubectl", "--context", "kind-" + cluster, "-n", SYSTEM, "logs",
                "-f", pod["metadata"]["name"], "-c", "observer", "--tail=-1", "--pod-running-timeout=10s"]
        follower = ObserverLogFollower(argv, self.env, stdout, stderr)
        metadata = {"phase": phase, "podName": pod["metadata"]["name"], "podUID": key[1],
                    "containerID": key[2], "restartCount": status["restartCount"], "argv": argv,
                    "stdout": stdout.name, "stderr": stderr.name, "status": "collecting"}
        self.observer_followers[key] = (follower, metadata)
        self.active_observer_follower[cluster] = key
        self.report["clusters"][cluster].setdefault("observerLogEvidence", []).append(metadata)
        self.flush()
        # The log API identifies the current container by Pod/name. Check the
        # observed container incarnation again; never label successor logs old.
        current = self.get(cluster, "pod", pod["metadata"]["name"], SYSTEM)
        now = self._owned_observer(cluster, current)
        check(current["metadata"]["uid"] == key[1] and now["containerID"] == key[2],
              "observer container changed while starting log follower")
        config = self.report["clusters"][cluster]["config"]
        startup = follower.wait_event(lambda event: event.get("msg") == "starting observe-only datapath",
                                      "owned startup context")
        check(startup.get("cluster") == cluster and startup.get("node") == config["node"]
              and startup.get("podUID") == config["podUID"] and startup.get("ifIndex") == config["ifIndex"]
              and startup.get("direction") == config["direction"] and startup.get("enforcementAvailable") is False,
              "startup JSON context differs from frozen configuration")
        attached = follower.wait_event(lambda event: event.get("msg") == "observer attached"
              and event.get("stage") == "attach", "attachment acknowledgment")
        check(attached.get("attempt") == 1 and "elapsed" in attached
              and attached.get("enforcementAvailable") is False,
              "attachment log lacks real stage/attempt/elapsed/Observe boundary")
        metadata["startup"] = startup
        metadata["attached"] = attached
        metadata["status"] = "attached-recorded"
        self.flush()
        return key

    def _finish_observer_follower(self, cluster, key, reason):
        follower, metadata = self.observer_followers[key]
        try:
            follower.stop(wait_for_eof=True)
        finally:
            # Preserve all decoded records, including failures, after draining.
            with follower.lock:
                metadata["events"] = list(follower.events)
                metadata["captureErrors"] = list(follower.errors)
            metadata["kubectlExit"] = follower.process.poll()
            metadata["stopReason"] = reason
            metadata["status"] = "closed" if not metadata["captureErrors"] else "capture-failed"
            if self.active_observer_follower.get(cluster) == key:
                del self.active_observer_follower[cluster]
            self.flush()

    def observer_log_after_sigkill(self, cluster, old_pod, restarted_pod):
        key = self.active_observer_follower[cluster]
        check(key[1] == old_pod["metadata"]["uid"] and key[2] == self._observer_status(old_pod)["containerID"],
              "SIGKILL log follower does not match killed container")
        self._finish_observer_follower(cluster, key, "deliberate-SIGKILL")
        old_events = self.observer_followers[key][1]["events"]
        check(not any(event.get("msg") == "observer detached" for event in old_events),
              "killed process unexpectedly reported graceful detach")
        return self.capture_observer_logs(cluster, restarted_pod, "post-sigkill")

    def observer_log_expect_detach(self, cluster, reason="graceful-uninstall"):
        key = self.active_observer_follower[cluster]
        follower, metadata = self.observer_followers[key]
        detached = follower.wait_event(lambda event: event.get("msg") == "observer detached"
              and event.get("stage") == "detach" and event.get("enforcementAvailable") is False,
              "graceful detach acknowledgment", timeout=10)
        metadata["detached"] = detached
        check(not any(event.get("msg") == "observer cleanup failed" for event in follower.records()),
              "observer reported failed cleanup")
        self._finish_observer_follower(cluster, key, reason)
        final_events = self.observer_followers[key][1]["events"]
        check(not any(event.get("level") in ["error", "fatal", "panic"] for event in final_events),
              "graceful uninstall emitted an application error: " + repr(final_events))

    def observer_log_expect_stale_failure(self, cluster):
        key = self.active_observer_follower[cluster]
        follower, metadata = self.observer_followers[key]
        stopped = follower.wait_event(lambda event: event.get("msg") == "observe-only datapath stopped"
              and "observer lifecycle verification failed" in str(event.get("error", "")),
              "old immutable configuration rejected on lifecycle check", timeout=10)
        metadata["staleConfigFailure"] = stopped
        # Existing image explicitly closes its owned link during this failure.
        detached = follower.wait_event(lambda event: event.get("msg") == "observer detached"
              and event.get("stage") == "detach" and event.get("enforcementAvailable") is False,
              "stale configuration detaches owned observer", timeout=5)
        metadata["detached"] = detached
        self._finish_observer_follower(cluster, key, "old-config-lifecycle-failure")

    def observer_log_close_all(self):
        """Call AFTER owned DS deletion in cleanup, even on a failed assertion."""
        for cluster, key in list(self.active_observer_follower.items()):
            try:
                self._finish_observer_follower(cluster, key, "finally-cleanup")
            except Exception as error:
                self.report["cleanupErrors"].append("observer log follower " + repr(key) + ": " + str(error))
        # Includes a follower whose assertion failed before active metadata was
        # fully updated. Idempotent stop reaps every child created by this mixin.
        for key, (follower, _) in self.observer_followers.items():
            try:
                follower.stop()
            except Exception as error:
                message = "observer follower final reap " + repr(key) + ": " + str(error)
                if message not in self.report["cleanupErrors"]:
                    self.report["cleanupErrors"].append(message)
        self.flush()
