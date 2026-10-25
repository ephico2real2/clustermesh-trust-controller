# Documentation refresh checks

The complete SPIRE host helper suite passes 107 tests. It runs with one `unittest discover` command. It returns a nonzero exit code on failure. No test was excluded to obtain this pass.

The first invocation used a Python without `cryptography`. The next invocation used the qualified Python, but the sandbox blocked five loopback TLS tests. The final invocation allowed local loopback and passed all 107 cases. All three logs remain here.

The summary records the exact command and hashes of the current Python helper sources. Some helper files are not yet committed. This is host test evidence for those bytes, not a claim about a released runtime image or the registrar withdrawal fixture.

The diagram renderer checked light and dark themes, font loading, contrast, text bounds and mobile page width. The primary inspected the images. An initial sandbox Chromium launch failure is preserved.

Read [the documentation guide](../../../DOCUMENTATION_GUIDE.md), [PKI flow](../../../PKI_TRUST_FLOW.md) and [build steps](../../../LOCAL_IMAGE_BUILD.md). No workload mTLS or Protected claim follows from these checks.
