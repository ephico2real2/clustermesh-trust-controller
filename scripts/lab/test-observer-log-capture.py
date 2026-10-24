"""Local subprocess-only smoke checks. No kubectl or cluster actions."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from observer_log_capture import ObserverLogFollower

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    follower = ObserverLogFollower([sys.executable, "-u", "-c", 'import json,time;print(json.dumps({"msg":"observer attached","stage":"attach","attempt":1,"elapsed":0.001,"enforcementAvailable":False}),flush=True);time.sleep(20)'], os.environ, root / "normal.jsonl", root / "normal.err")
    event = follower.wait_event(lambda x: x.get("stage") == "attach", "test attach", timeout=3)
    assert event["attempt"] == 1
    follower.stop(); follower.stop()
    assert follower.process.poll() is not None
    assert not any(t.is_alive() for t in follower.threads)
    print("PASS normal capture, bounded stop, idempotent reap")

    follower = ObserverLogFollower([sys.executable, "-u", "-c", 'print("x"*70000,flush=True)'], os.environ, root / "overflow.jsonl", root / "overflow.err")
    try:
        follower.wait_event(lambda _: False, "expected overflow", timeout=3)
    except AssertionError as error:
        assert "bound" in str(error)
    else:
        raise AssertionError("oversized output accepted")
    try: follower.stop()
    except AssertionError: pass
    assert follower.process.poll() is not None
    assert not any(t.is_alive() for t in follower.threads)
    print("PASS oversized-line rejection and child reap")

    follower = ObserverLogFollower([sys.executable, "-u", "-c", 'import json;print(json.dumps({"msg":"observer detached","stage":"detach","enforcementAvailable":False}),flush=True)'], os.environ, root / "eof.jsonl", root / "eof.err")
    event = follower.wait_event(lambda x: x.get("stage") == "detach", "EOF detach", timeout=3)
    follower.stop(); assert follower.process.returncode == 0
    assert event["enforcementAvailable"] is False
    print("PASS graceful EOF preserves final JSON acknowledgment")
