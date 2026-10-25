# Feature-branch CI result

[Run40177163792](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40177163792) passed for CMTC `7b1f95cec93593853b8b09fa3e751b3a524dab22`. Both unit/build and deployed-lab jobs passed. The lab built the actual image, deployed two clusters, ran six minutes of application load, asserted measured HTTP results and captured dashboard/application images.

See [job metadata](run.json) and [artifact metadata](artifacts.json). This qualifies the existing Observe lab workflow. It does not prove the proposed combined ClusterMesh/ztunnel mTLS path. Documentation commit `4a93ca3` uses a CI skip marker to avoid a duplicate lab run for Markdown, images and evidence only.
