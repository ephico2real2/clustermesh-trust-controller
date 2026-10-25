# TLS metric contract qualification

Date: 2026-10-25. Status: query semantics and source qualification only. Ztunnel remains off in both clusters.

The contract maps the existing mTLS goals to the native source-tested ztunnel TLS families. Destination queries count one TLS reporting boundary. The active gauge counts verified TLS sessions. Identity failures count local verifier rejections. Missing live TLS series remain unavailable. All nine historical dashboard domains remain present.

- [Current inventory and TLS availability queries](current-queries.json). The six CMTC targets are up; no ztunnel targets or TLS series exist. The 181-family grouping comes from the existing full inventory, not a new family-count query.
- [Actual dashboard query validation](dashboard-query-evidence.json). The validator checks both clusters together and separately, implemented producer telemetry, existing pie partitions and absent-source behavior. It does not request native mTLS acceptance.
- [Local validation log](validation.log). Twenty dashboard tests, generated-source consistency and typed/static validation pass.
- [Instrumentation ownership and lifecycle](../../../observability/INSTRUMENTATION.md).

Commands:

```sh
python3 observability/build.py --check
python3 -m unittest discover -s observability -p 'test_*.py'
python3 observability/validate.py
python3 observability/validate.py --prometheus http://127.0.0.1:13000/api/datasources/proxy/uid/cmtc-prom --expect-producer --out artifacts/metrics-instrumentation-query-evidence.json
```

This change does not provision a new Grafana layout or claim new TLS collection. No image build is required for the Python/JSON contract change. Exact-image deployment, real TLS traffic, collection and during-load screenshots remain required before native metric activation.
