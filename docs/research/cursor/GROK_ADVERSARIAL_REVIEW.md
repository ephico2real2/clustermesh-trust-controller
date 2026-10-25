# Cursor Grok adversarial source review

Reviewed immutable Cilium commit `d040a4bc9aeb045f84477541cbebdbd24ce7c130`. Model: Grok4.7ExtraHigh. No code or traffic was run by the reviewer. Findings1and3 have since been addressed by Opus commit `dbd2d32bd935b8b271141667e41546c904e74e8a` with retained semantic failure/race/vet evidence. Remaining findings require primary/Opus validation; proposed snippets are not qualified implementations.

The last review stopped at the node-name race. This pass attacks commit `d040a4bc` itself: the node projection, the stream lifecycle, and the new HBONE admission, using the committed tree rather than later edits.The working tree has moved past the commit. I’ll use the saved patch as the immutable source and keep later edits out of the verdict.The increment in `d040a4bc9aeb045f84477541cbebdbd24ce7c130` is not acceptable. One-batch node-name projection is fail-closed, and the new HBONE predicate drops plaintext application ports when a Required program has a real compiled address. Two confirmed paths still publish or forward under the conditions the new tests do not select. This review did not run code or traffic. `git show` was rejected in this session, so the commit body is `review/NODE_PORT_IMPLEMENTED.patch` (21 files). The workspace copy of `native_node_name.go` has later uncommitted edits; those edits are not this commit and are not accepted here.

## Finding 1 — High — stale node name stays on a live stream

**Where:** `pkg/ztunnel/xds/native_node_name.go`, `(*StreamProcessor).bindNodeNames` lines 147–165. The watch install is lines 163–164. `(*nativeNodeNames).verify` (lines 127–142) runs only from `revalidateNodeNames` (lines 171–179). `(*StreamProcessor).Start` handles `nodeNameWatch` and the endpoint channel in one `select` (`stream_processor.go`, the arm added at line 901). `sendAddressResponse` is unchanged and sends with no second verify.

**Sequence:**

1. An Address batch for `172.18.0.2` publishes `Workload.Node=cmtc-a-worker` and stores that pair in `boundNodeNames`.
2. The node row for that address is deleted and inserted as `cmtc-a-renamed`. That closes the watch.
3. The next event is a CiliumEndpoint on a different address, `172.18.0.3`.
4. `select` takes the endpoint. `bindNodeNames` checks only the new batch, copies those pairs, and replaces `nodeNameWatch` with the watch from that later read.
5. `revalidateNodeNames` never runs for the closed watch. The stream stays up. `cmtc-a-worker` remains the published name for `172.18.0.2` until some later node-table write. A reconnect would rebuild from an empty map, but this path does not close the stream, so no reconnect happens.

`TestNativeNodeNameWatchInvalidatesStreamOnNodeChange` passes on this commit. It calls `revalidateNodeNames` itself, and its bind-time check uses an event for the changed address. It never selects an unrelated batch after a closed watch.

This is name projection from the node table (`Node.Name` / CiliumNode name), not a Pod UID or Node UID check. A stale name makes ztunnel keep the old `workload.node`. The strict witness (`ztunnel` `src/state/outbound_source.rs` line 47, `cfg.local_node != workload.node`) then disagrees with the pod or keeps classifying it by the old name. The chart change is the correct witness input: `install/kubernetes/cilium/templates/ztunnel/daemonset.yaml` sets `NODE_NAME` from `spec.nodeName` (line 106). Transport port 15008 is not that witness.

**Patch** (against the committed `map[netip.Addr]string` binder, not the dirty tree):

```go
func (sp *StreamProcessor) bindNodeNames(collection EndpointEventCollection) (EndpointEventCollection, error) {
	if sp.nodeNames == nil {
		return nil, wrapValidationError(errInvalidWorkloadData, "Kubernetes node discovery is not configured")
	}
	bound, pairs, _, err := sp.nodeNames.bind(collection)
	if err != nil {
		return nil, err
	}
	retained := maps.Clone(sp.boundNodeNames)
	if retained == nil {
		retained = make(map[netip.Addr]string)
	}
	maps.Copy(retained, pairs)
	watch, err := sp.nodeNames.verify(retained)
	if err != nil {
		return nil, err
	}
	sp.boundNodeNames = retained
	sp.nodeNameWatch = watch
	return bound, nil
}
```

At the start of `sendAddressResponse`, after the nil checks and before `SendMsg`:

```go
if sp.nodeNames != nil {
	watch, err := sp.nodeNames.verify(sp.boundNodeNames)
	if err != nil {
		return fmt.Errorf("Kubernetes node binding changed before publication: %w", err)
	}
	sp.nodeNameWatch = watch
}
```

On verify failure, do not replace `boundNodeNames`. Discard the watch returned by `bind`.

**Test that fails on this commit:**

```go
func TestLaterBatchRejectsAnEarlierNodeChange(t *testing.T) {
	db, nodes := testNodeTable(t, false,
		testNodeRow{name: "cmtc-a-worker", cluster: "cmtc-a", clusterID: 1, addresses: []string{"172.18.0.2"}},
		testNodeRow{name: "cmtc-a-control-plane", cluster: "cmtc-a", clusterID: 1, addresses: []string{"172.18.0.3"}},
	)
	names, err := newNativeNodeNames(db, nodes, testLocalCluster)
	require.NoError(t, err)
	sp := &StreamProcessor{log: slog.New(slog.DiscardHandler), nodeNames: names}

	bound, err := sp.bindNodeNames(EndpointEventCollection{
		nodeTestEvent("11111111-1111-4111-8111-111111111111", "172.18.0.2"),
	})
	require.NoError(t, err)
	require.Equal(t, "cmtc-a-worker", bound[0].NodeName)
	stale := sp.nodeNameWatch
	published := maps.Clone(sp.boundNodeNames)

	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Delete(txn, &node.Node{Node: nodetypes.Node{Name: "cmtc-a-worker", Cluster: "cmtc-a"}})
	require.NoError(t, err)
	_, _, err = nodes.Insert(txn, &node.Node{Node: nodetypes.Node{
		Name: "cmtc-a-renamed", Cluster: "cmtc-a", ClusterID: 1,
		IPAddresses: []nodetypes.Address{nodetypes.NewAddress(addressing.NodeInternalIP, netip.MustParseAddr("172.18.0.2"))},
	}})
	require.NoError(t, err)
	txn.Commit()
	<-stale

	bound, err = sp.bindNodeNames(EndpointEventCollection{
		nodeTestEvent("33333333-3333-4333-8333-333333333333", "172.18.0.3"),
	})
	require.Nil(t, bound)
	require.ErrorContains(t, err, "172.18.0.2")
	require.Equal(t, published, sp.boundNodeNames)
	require.Equal(t, stale, sp.nodeNameWatch)
}

func TestNodeChangeBeforeSendWithholdsResponse(t *testing.T) {
	db, nodes := testNodeTable(t, false,
		testNodeRow{name: "cmtc-a-worker", cluster: "cmtc-a", clusterID: 1, addresses: []string{"172.18.0.2"}},
	)
	names, err := newNativeNodeNames(db, nodes, testLocalCluster)
	require.NoError(t, err)
	sent := 0
	sp := &StreamProcessor{
		log: slog.New(slog.DiscardHandler), nodeNames: names,
		stream: &MockStream{OnSendMsg: func(any) error { sent++; return nil }},
		expectedNonce: map[string]struct{}{},
	}
	response, err := sp.addressResponse(EndpointEventCollection{
		nodeTestEvent("11111111-1111-4111-8111-111111111111", "172.18.0.2"),
	})
	require.NoError(t, err)

	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Delete(txn, &node.Node{Node: nodetypes.Node{Name: "cmtc-a-worker", Cluster: "cmtc-a"}})
	require.NoError(t, err)
	_, _, err = nodes.Insert(txn, &node.Node{Node: nodetypes.Node{
		Name: "cmtc-a-renamed", Cluster: "cmtc-a", ClusterID: 1,
		IPAddresses: []nodetypes.Address{nodetypes.NewAddress(addressing.NodeInternalIP, netip.MustParseAddr("172.18.0.2"))},
	}})
	require.NoError(t, err)
	txn.Commit()

	require.ErrorContains(t, sp.sendAddressResponse(response, "test"), "before publication")
	require.Zero(t, sent)
}
```

On `d040a4bc` the first test gets a successful bind of `cmtc-a-control-plane`. The second test sends.

## Finding 2 — High — Required program with all-zero addresses forwards TCP/15008

**Where:** `bpf/lib/ztunnel_admission.h`, `ztunnel_own_mode` lines 102–131. `complete` starts `true` and is cleared only inside a family whose compiled address is non-zero. `ztunnel_mode_decide` (lines 50–62) returns `HBONE_ONLY` when `ztunnel_required` is true, quarantine is false, and `complete` stays true. This commit does not change that collector. It is what first copies the obligation into the program: `pkg/datapath/config/endpoint.go` `Endpoint`, the new lines 59–61, `cfg.ZtunnelRequired = required.IsZtunnelMeshOnly()`. `Endpoint` still leaves `EndpointIPv4` / `EndpointIPv6` zero when `IsValid()` is false (lines 16–21). The new comment on `ZtunnelMeshOnlyProvider` says a missing own map entry does not forward as ordinary.

**Sequence:** Compile with `ENABLE_IPV4`, `ENABLE_IPV6`, `endpoint_ipv4=0`, `endpoint_ipv6=::`, `ztunnel_required=true`, `ztunnel_quarantined=false`, and no `cilium_lxc` row. Both family checks skip the lookup. `complete` stays true. Egress and ingress TCP destination port 15008 take `ztunnel_hbone_*_verdict` and return `CTX_ACT_OK`. No owned row was read. A non-zero compiled address with a missing row does quarantine; `ztunnel_required_01` only covers that shape, because it assigns `v4_pod_one` and `v6_pod_one`.

While `ztunnel_quarantined` is still true, `ztunnel_mode_decide` drops first, so the hole is the released program. Assumption: a lab pod is actually regenerated in that state before it has an IP. The config path is in this commit; a live pod hitting it was not shown.

**Patch:**

```c
static __always_inline enum ztunnel_mode ztunnel_own_mode(void)
{
	const struct endpoint_info *ep __maybe_unused;
	bool complete = true;
	bool configured = false;
	__u32 flags = 0;

#ifdef ENABLE_IPV4
	if (CONFIG(endpoint_ipv4).be32) {
		configured = true;
		ep = __lookup_ip4_endpoint(CONFIG(endpoint_ipv4).be32);
		if (ep && ep->lxc_id == LXC_ID)
			flags |= ep->flags;
		else
			complete = false;
	}
#endif
#ifdef ENABLE_IPV6
	{
		union v6addr own = CONFIG(endpoint_ipv6);

		if (own.d1 || own.d2) {
			configured = true;
			ep = __lookup_ip6_endpoint(&own);
			if (ep && ep->lxc_id == LXC_ID)
				flags |= ep->flags;
			else
				complete = false;
		}
	}
#endif
	if (!configured)
		complete = false;
	return ztunnel_mode_decide(CONFIG(ztunnel_required), CONFIG(ztunnel_quarantined),
				   complete, flags);
}
```

One configured family with an owned row still completes. Zero families do not.

**Test:** a second loader, same `CASE`/`pod_send_packet` machinery as `bpf/tests/ztunnel_required_admission.c`, with this config and no map inserts:

```c
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = 0 })
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { })
ASSIGN_CONFIG(__u16, endpoint_id, 77)
ASSIGN_CONFIG(bool, ztunnel_required, true)
ASSIGN_CONFIG(bool, ztunnel_quarantined, false)
```

Send TCP from the pod, source port 42010, destination port 15008. Assert `CTX_ACT_DROP` and one egress `DROP_POLICY`. On this commit the status is the HBONE redirect / `CTX_ACT_OK` path. Add the same packet in the ingress direction and assert drop there too.

## Finding 3 — Low — last removal never retires an address

**Where:** `bind` lines 101–106 pass `REMOVED` through without editing the map. `bindNodeNames` lines 158–163 only insert. The key is the address, not the Pod UID.

**Sequence:** Publish two pods on `172.18.0.2`, remove both, then publish a new pod after that address belongs to `cmtc-a-renamed`. The committed binder returns `node address 172.18.0.2 was published as "cmtc-a-worker"`. The stream ends. A new stream has an empty map and can publish `cmtc-a-renamed`. This does not emit the wrong name. Two pods on one address stay safe only because the entry is never deleted. The gap is that the last removal also never deletes it.

**Patch:** track `map[podUID]struct{ addr netip.Addr; name string }`. On `REMOVED`, delete that UID. After the batch, keep an address only while some remaining UID still uses it. Then run Finding 1’s `verify` on the resulting address set. Do not delete an address that another UID still holds.

**Test that fails on this commit:** publish UIDs `…1111` and `…2222` on `172.18.0.2` and `…3333` on `172.18.0.3`. Remove `…1111` only, rename `172.18.0.2` to `cmtc-a-renamed`, and bind a batch that does not create a pod on `172.18.0.2`. That must still error, because `…2222` remains. Then remove `…2222` and bind a create of UID `…4444` on `172.18.0.2`. The committed code still errors with `was published as`. The fixed code returns `NodeName=cmtc-a-renamed` and drops `…2222` from the map.

## Inherited, still open, not introduced by the 21-file diff

**Withdrawal write failure — High.** `pkg/endpoint/ztunnel_datapath_admission.go` `rewriteZtunnelDatapathFlags` lines 210–223. Not in this commit. `WithdrawZtunnelAdmission` sets the Go atomic, then `WriteEndpoint`. On error it logs and returns. `ztunnel_mode_decide` reads the loaded program and the map, not that atomic. After a successful release, the loaded program has `ztunnel_quarantined=false` and the map has the released flags. A failed rewrite leaves both. TCP/15008 continues. A second `WithdrawZtunnelAdmission` returns at `Swap(true)` and does not retry the write. `TestZtunnelIncarnationChangeQuarantinesUnderLockAndMapFailureStaysClosed` only asserts `IsZtunnelQuarantined()` after `"map write failed"`, so it passes while the map is unchanged.

The recovery is a datapath regeneration that compiles `ztunnel_quarantined=true`, queued from the write-error path without taking a lock the caller of `WithdrawZtunnelAdmission` already holds. The test that fails before that: release, install a frontend, fail `WriteEndpoint`, and assert a datapath-level regen was queued. Also assert the recording map’s stored flags do not contain the quarantine bit. Today the regen count stays zero and the test at line 193 still passes.

**Reply comment versus `CT_RELATED`.** In `bpf/bpf_lxc.c`, `handle_ipv4_from_lxc` around line 1509 (and the three sibling sites this commit edited), the condition remains `ct_status == CT_REPLY`. The comment this commit wrote says the reply must belong to an HBONE flow whatever conntrack recorded. `CT_RELATED` shares the case and skips both policy and the port check. I cannot show a TCP payload taking `CT_RELATED`. Established and reply TCP are checked. Treat `CT_RELATED` as an unproven data bypass.

## Attacks that do not succeed on this commit

- Same name and same IP in `cmtc-a` / id 1 and `cmtc-b` / id 2 stay separated. Deleting the local row does not select the remote row (`snapshot` lines 61–63, `TestNativeNodeNameRepeatedNamesInDifferentClusters`).
- Missing, empty, ambiguous, unsynchronized, and unparsable addresses fail the batch. A nil resolver makes `addressResponse` return `Kubernetes node discovery is not configured`. `ToXDSAddress` rejects an empty `NodeName` and writes `NodeName`, not `Networking.NodeIP`.
- Initial replay, CEP/CES, and enrollment all use `addressResponse`. An unenrolled namespace produces no name. A namespace that becomes enrolled does not replay until the next endpoint event; the absence is a missing workload, not a substituted name.
- A new stream starts with an empty `boundNodeNames`. Reconnect repairs Finding 1 only after the stream dies. Finding 1 does not die.
- Cluster ID 0 makes `newNativeNodeNames` fail and `NewServer` (`cell.go` lines 84–88) keep serving with a nil resolver. Address requests fail closed. There is no IP fallback. Whether either lab uses ID 0 was not in the reviewed artifacts.
- Foreign endpoint id 78, a missing row for a non-zero compiled address, and a one-family gap are quarantined by `ztunnel_required_admission.c` cases 01–03 and 07.
- Egress and ingress TCP/15008 are a transport shape. The commit says so. Cases 04 and 08 forward that shape with no TLS parse. Cases 05, 06, and 10–12 drop application, world, host, and UDP plaintext. Cases 14–17 drop established and reply plaintext. Case 19 drops outer 15008 when native policy allows only 8080, so the original application tuple is not widened. Those are program tests with selected `CHECK` bodies, not empty cases.
- `fixtureBound` returns the original collection when bind fails. Current fixture IPs match `worker-a`, so the existing converter errors are not masked. Converter tests that preset `NodeName` and call `toValidatedDeltaDiscoveryResponse` do not prove discovery. `addressResponse` does.
- Old bytecode ignores the new checks. The header says that. This commit adds no program-version gate. Regeneration of every endpoint program is still required. An imported agent image does not prove every loaded `bpf_lxc` is the new one.

## Acceptance gates still unmet

- `TestLaterBatchRejectsAnEarlierNodeChange` fails on `d040a4bc` and passes only after retained-set verify plus verify inside `sendAddressResponse`.
- A zero-address Required program drops TCP/15008 in both directions. `ztunnel_required_01` does not count.
- A failed quarantine `WriteEndpoint` queues datapath regeneration. The current map-failure test does not count.
- Last Pod removal retires that Pod’s address and keeps a sibling on the same address.
- ztunnel stays off. There is no strict TLS or source-witness run, and no ADS capture of `Workload.Node` from this binary.
- The cmtc-a agent image claim (`d040a4bc9a` by version and imported imageID, after the corrected canary) is user-reported. It is a dev overlay, not a release, and it is not mTLS proof. This review did not inspect the node.
- Original application-tuple authorization, approved DNS/host exceptions, and old-program replacement remain open. Kubelet probes to application ports now drop; that is fail-closed and will break probes until a separate exception exists.
- SPIRE agent delegated API access on the two clusters is a separate change. It does not prove this port and does not authorize SPIRE server Admin or root key changes.

**Verdict for `d040a4bc` only:** do not accept it. Single-batch projection and the non-zero-address HBONE drop rules are real. The cross-batch watch replacement still leaves a stale node name on a live stream, and a released Required program with all-zero compiled addresses forwards unauthenticated TCP/15008.
