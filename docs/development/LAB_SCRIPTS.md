# Lab scripts: what to run, and in what order

This is the run order for the two-cluster kind lab (`cmtc-a`, `cmtc-b`) on the
Colima VM. Each step names the script, what it changes, and how to tell it
worked. Why each step exists is in the linked docs.

## Where to run them

| Where | Set first | Used by |
|---|---|---|
| macOS host | `export DOCKER_HOST="unix://$HOME/.colima/cmtc-cilium/docker.sock"` (or `docker context use colima-cmtc-cilium`) and a `KUBECONFIG` holding the `kind-cmtc-a` and `kind-cmtc-b` contexts | Recovery and the clock check ([KIND_CLUSTERMESH_RECOVERY.md](KIND_CLUSTERMESH_RECOVERY.md)) |
| Inside the VM | `colima -p cmtc-cilium ssh`, then `cd /private/tmp/cmtc-mac-qualification` and `export PATH="$PWD/.tmp/bin:$PATH"` | A fresh bootstrap ([CILIUM_IMAGES.md](CILIUM_IMAGES.md)) |

Check the Docker endpoint before running anything that creates or changes
clusters: `docker context show` and `kind get clusters`. On the host the default
context may be Docker Desktop, which is not the lab.

Never print or commit the kubeconfig.

## 1. Prepare the VM (once per VM, and after every VM restart)

| Order | Run | Changes | Worked when |
|---|---|---|---|
| 1.1 | `bash scripts/lab/colima-timekeeping.sh --apply` | Disables and masks the guest NTP clients and resets the kernel clock discipline, so Lima is the clock's only owner. Idempotent. `up.sh` runs it too. | It prints `Timekeeping OK`. Why: [COLIMA_TIMEKEEPING.md](COLIMA_TIMEKEEPING.md). |
| 1.2 | `colima -p cmtc-cilium ssh -- sysctl fs.inotify.max_user_instances fs.inotify.max_user_watches` | Nothing; this is a check. The values persist in `/etc/sysctl.d/99-cmtc-kind.conf` in the VM. | `8192` and `1048576`. At 128, a Cilium worker fails with `couldn't initialize inotify`. |

## 2. Create a fresh lab (inside the VM)

Run these in order. `make lab-up` refuses to touch existing `cmtc-a` or
`cmtc-b` clusters.

| Order | Run | Changes | Worked when |
|---|---|---|---|
| 2.1 | `GITHUB_PATH=$(mktemp) bash scripts/lab/ci-bootstrap.sh` | Downloads pinned, checksum-verified Linux `kind`, `kubectl`, `cilium` and `helm` into `.tmp/bin`. Linux only (it uses `sha256sum` and Linux binaries). | `.tmp/bin` holds four executables. |
| 2.2 | `make image` and `make capture-image` | Builds `cmtc:dev` and `cmtc-capture:dev`. | Both appear in `docker images`. |
| 2.3 | `make lab-up` (`scripts/lab/up.sh`) | 1. Applies the clock fix (1.1). 2. Renders the pinned Cilium chart (`scripts/cilium/prepare.sh`). 3. Creates both clusters. 4. Installs Cilium and cert-manager, and builds the mesh PKI with `scripts/lab/pki/mesh-pki.sh` ([MESH_PKI.md](../../MESH_PKI.md)). 5. Joins the ClusterMesh. 6. Deploys CMTC and monitoring. | `scripts/cilium/verify.py` passes, and Prometheus and Grafana roll out. |
| 2.4 | `make lab-test` (`scripts/lab/test.sh`) | Test namespaces and traffic. | Local and cross-cluster Service and Pod IP traffic passes on ports 80, 8080 and 31337. |
| 2.5 | `bash scripts/lab/load.sh start` | Starts bounded real traffic. | Load Jobs are running. |
| 2.6 | `make lab-capture` (`scripts/lab/capture.sh`) | Runs the `cmtc-capture:dev` browser walk against Grafana while the load runs. | Screenshots are under `artifacts/screenshots/`. |
| 2.7 | `bash scripts/lab/load.sh collect` | Collects the load results. | Result JSON is under `artifacts/load/`. |
| 2.8 | `make lab-evidence` (`scripts/lab/evidence.sh`) | Writes the node, Pod, image, policy, log and mesh status files to `artifacts/`. It never collects Secrets, kubeconfigs or keys. | The files exist. |

This baseline has `encryption.enabled=false` and no ztunnel. It is **not**
evidence of workload mTLS.

## 3. Bring an existing lab back (host or VM)

After a VM restart, a Docker restart or a node address change:

| Order | Run | Worked when |
|---|---|---|
| 3.1 | `bash scripts/lab/colima-timekeeping.sh --apply` | `Timekeeping OK`. |
| 3.2 | `python3 scripts/lab/kind-node-ips.py cmtc-a` and the same for `cmtc-b` | Prints each cluster's node addresses. |
| 3.3 | `bash scripts/lab/reconcile-clustermesh-endpoints.sh` | Both ClusterMesh links are ready. It upgrades the Helm releases only when the addresses changed, and is safe to rerun. |
| 3.4 | `bash scripts/lab/test.sh` | Same as 2.4. |

## 4. Update the mesh images on the running lab

The mTLS stack (the Cilium fork agent, ztunnel, SPIRE) is deployed by
operations, not by `up.sh`. The loop is:
1. Build each image with host Podman, under the build lease.
2. Export it as an OCI archive.
3. Stream it into every node with `ctr -n k8s.io images import`.
4. Check that every node holds the exact built image ID.
5. Change the DaemonSet images. Both use `updateStrategy: OnDelete`, so change
   only the image fields. ztunnel keeps `hostPID: true`; the Cilium agent has none.
6. Restart one node at a time, deleting each Pod with a UID precondition.

The scripts that did this on 2026-10-25 are kept in
[`docs/evidence/local-activation-20261025/operations/`](../evidence/local-activation-20261025/operations/).
They are records, not reusable tools:
- they contain machine-local paths;
- they check one exact old image;
- they include one-time bootstrap stages that must not be replayed against
  existing state.

Read the source pins and ownership guards in each one before adapting it.

| Order | What | Worked when |
|---|---|---|
| 4.1 | Build: `build_agent_overlay.sh`, `build_ztunnel_image.sh` (each checks the build lease and needs a clean tree) | `--version` names the source commit. |
| 4.2 | Import the image into all four nodes | `crictl inspecti` on every node returns the Podman image ID. |
| 4.2a | ztunnel only: `pin_digest.py <tag>` names the imported manifest `repo@sha256:…` on every node (the DaemonSet pins ztunnel by digest) | Every node reports the same digest, its manifest hashes to it and its config is the Podman image ID. |
| 4.3 | Patch the DaemonSet images with `test` operations on the old image | Before and after differ only in images (and, once, in the agent's dropped `hostPID`). |
| 4.4 | `restart_agent.py <cluster> <node>`, one node at a time | The new Pod is Ready and its `imageID` is the built ID. Restored endpoints are quarantined, then re-admitted (`Re-admitted restored Required endpoint`). |

Loading an image does not deploy it, and a Ready Pod does not mean mTLS. A
passing traffic matrix shows traffic outcomes only; workload mTLS also needs
per-connection peer-certificate evidence and passing recovery tests.

## 5. Checks you can run at any time

| Run | Answers |
|---|---|
| `bash scripts/lab/colima-timekeeping.sh --check --window 60` (host) | Does the clock have a single owner, with at most one backward Lima step in the last hour? |
| `python3 scripts/lab/clock-offset-sample.py cmtc-a-worker 30 2 colima-cmtc-cilium` | Guest minus host offset, with its error bound. |
| `cilium clustermesh status --context kind-cmtc-a` (and `kind-cmtc-b`) | Are both mesh links up? |
| `python3 scripts/cilium/verify.py` | Do the running Cilium images match the lock? |
| `venv/bin/python -m unittest discover -s scripts/lab -p 'test_*.py'` | Pure checks of the lab helpers. They use no cluster. The repository venv provides PyYAML, and 40 tests pass (run 2026-10-25T23:20Z). The system `python3` fails on `import yaml`. |

## 6. Remove the lab

`make lab-down` (`scripts/lab/down.sh`) deletes only the clusters this checkout
recorded in `.tmp/created-clusters` and its own PKI directory. It refuses
anything else.

## Do not run

- The drivers under `scripts/lab/mtls/` against `cmtc-a` or `cmtc-b`. They were
  written for the retired isolated `cmtc-mtls` fixture
  ([PODMAN_LOCAL_VALIDATION.md](PODMAN_LOCAL_VALIDATION.md)).
- `up.sh` to "repair" a lab. It refuses existing clusters by design. Recover
  with section 3.
- Any bootstrap stage in the evidence `operations/` scripts against a live lab.
  The guards there (UID and resourceVersion checks, one-time markers) are
  intentional. Do not reset checkpoints, replay floors or bootstrap markers to
  make a rerun pass.
