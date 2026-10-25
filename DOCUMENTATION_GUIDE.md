# Documentation guide

Use this guide to find the correct document and read its evidence level. Updated 2026-10-25.

## Start with current state

Read [README](README.md) for the component roles. Read [delivery status](docs/agile/DELIVERY_STATUS.md) for exact source, image and test pins.

| Document group | Meaning |
| --- | --- |
| Delivery status | Current implementation, runtime state and next dependency |
| Architecture and ADRs | Target design and decisions; proposed items remain proposed |
| `LOCAL_*.md` guides | Qualification of the stated source and fixture |
| Development runbooks | Commands and ownership rules for local work |
| Research notes | Findings for the source/version named in each note |
| Evidence and dated run folders | Immutable measurements for one recorded run |
| Handover history | Earlier states and decisions; use current status before resuming |

A historical pass remains useful evidence. It does not prove a newer image, a different topology or another encryption mode.

Read [the PKI trust flow](PKI_TRUST_FLOW.md) for the certificate hierarchy. Read [local image build](LOCAL_IMAGE_BUILD.md) for build, import and verification steps.

## Component names

| Term | Use this meaning |
| --- | --- |
| CMTC controller | The Go process for policy intent and trust coordination |
| CMTC node agent | The unprivileged inventory process in the standard DaemonSet |
| eBPF observer | The opt-in packet-counting prototype |
| eBPF fence | The opt-in packet-blocking prototype |
| SPIRE registrar | The experimental registration helper in the SPIRE server Pod |
| SPIRE server | The registration store and SVID issuer |
| SPIRE node agent | The node process that attests workloads |
| Cilium agent | The native network and policy owner |
| Ztunnel | The node process for workload TLS and delivered authorization |
| SVID | A SPIFFE certificate identity document |
| Receipt | Evidence for one stated operation and incarnation |
| Protected | A state that requires all applicable security gates |

Do not call the registrar image the CMTC DaemonSet image. Distinguish the server Admin socket from the agent Admin socket.

## Writing rules

Use the spirit of ASD-STE100. These rules do not claim formal STE certification.

- Use short sentences and direct verbs.
- Use one term for each concept.
- Define a technical term before using it.
- Give each procedural step one action.
- State the result before the detailed method.
- Mark each design as current, experimental, proposed or historical.
- Keep source qualification separate from runtime qualification.
- Record failures and recovery results.
- State the acceptance gate that remains open.
- Link to the evidence instead of repeating large logs.

Keep source pins in delivery status and the relevant evidence ledger. Link to those records from overview documents. This reduces conflicting copies.

## Security evidence terms

Registration readback proves that SPIRE stores the requested entry. SVID verification proves certificate identity and issuer checks. Neither result proves traffic capture or policy enforcement.

An empty or unusable SPIRE SVID response means no usable credential was returned. A delegate permission denial concerns the caller. A deadline gives no authorization verdict. Keep these outcomes separate.

A packet counter is not an HTTP request count. A TCP connection is not a TLS handshake. A missing metric is unavailable data, not a successful zero.

## Diagrams

Use a diagram when it makes the mechanism clearer. Use an interactive page when controls help explain a system or quantity. A simple status statement needs no diagram.

The component-role figure uses the local diagram-kit template and renderer:

```bash
~/.local/share/diagram-kit/.venv/bin/diagram-render \
  docs/diagrams/component-roles/source.html \
  docs/diagrams/component-roles component-roles
```

Inspect both images after rendering. Keep measured behavior separate from proposed behavior. Use the established Tableau palette for dashboards.

## Automated test records

A test runner must execute its assertions without operator interpretation. It must return a nonzero exit code for assertion, timeout or cleanup failure. Save commands, source pins, selected test counts and logs. Use bounded polling for asynchronous state. Keep the original failure when a corrected test passes.

Unit tests and real lab tests have separate results. A helper-unit pass cannot qualify the cluster. Manual inspection of screenshots can supplement the assertions; it cannot change a failed test to a pass.

## Update a document

1. Read the current source and evidence.
2. Check the deployed image separately.
3. Update the owning guide.
4. Update delivery status.
5. Check local links.
6. Render changed figures.
7. Inspect both themes.
8. Commit the document and its evidence together.

Keep dated run records and raw evidence intact. Add a current-state link to an old guide when its recorded scope still matters.
