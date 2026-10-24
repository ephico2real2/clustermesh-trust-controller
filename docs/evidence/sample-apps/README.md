# Sample application node-spread qualification

The local suite passed 36 Service and direct-Pod checks after the backend was
spread across both nodes of both clusters. Each direct response identified the
intended Pod in its response header. See `local-tests.log`, `results.json` and
`clustermesh-backends.tsv`. These are unencrypted reachability checks.

Header copies use LF line endings for review; original CRLF headers remain
under `artifacts/` on the development host. Local browser port forwards do not
prove mesh routing or mTLS.
