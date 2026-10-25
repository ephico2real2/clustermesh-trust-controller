# Historical source patches

These patches preserve earlier development increments. Apply them only to their recorded bases in an isolated checkout. They are not a patch bundle for current upstream.

`cilium-live-capture-retention.patch` records Cilium commit `f142e58d06a458b72cf7ea27999c093ca87c9c2b`. Its date and 127-test result belong to that increment. They do not qualify current fork source or cross-cluster workload mTLS.

Use [delivery status](../../agile/DELIVERY_STATUS.md) for current source, image pins and unmet security gates. The retired `cmtc-mtls` Python runners are disabled before any argument parsing, file creation or API call.
