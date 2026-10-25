# Automatic application continuity check

All 36 Service and Pod-IP cases passed on TCP80, TCP8080 and TCP31337. The runner created and removed two owned clients. Existing application identities and baseline clients were preserved. Cleanup reported no errors.

`report.json` is the actual runner result. `raw-evidence.tar.gz` preserves all response bodies, HTTP headers and that report without changing line endings or HTTP header terminators. The report filenames resolve inside the archive. `sha256.json` records the raw file hashes.

This is ClusterMesh HTTP reachability evidence after diagnostic image verification. Ztunnel was disabled. It is not workload-mTLS evidence.
