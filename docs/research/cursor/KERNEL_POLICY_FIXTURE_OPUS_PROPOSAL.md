# Cursor kernel policy fixture proposal

Model confirmed: Claude Opus 5.5 300K High. Session `014a474d-566d-4f58-8588-baa744ffc456`. Proposal only. The primary must review and run all checks. Cursor ran formatting and read-only apply checks; it did not run kernel tests or change the source.

# Kernel policy-map reachability fixture fix

Target: `/private/tmp/cilium-ztunnel-authorization-runtime`. The dirty reachability files match `source-manifest.json`. `HEAD` moved to `3985cc13` (lost-ADD-ACK commit). That commit does not touch these files. Both patches pass `git apply --check` against the live tree.

## Patch A (apply now)
- [pkg/datapath/loader/compile.go](pkg/datapath/loader/compile.go): revert the include-order change to upstream.
- [pkg/datapath/loader/util_test.go](pkg/datapath/loader/util_test.go): add `newTestLoaderWithConfigWriter`. `newTestLoader` delegates to it, so existing behaviour does not change.
- [pkg/datapath/loader/ztunnel_policy_reachability.go](pkg/datapath/loader/ztunnel_policy_reachability.go): require slot 29 (and IPv6 slot 32) to hold a program only on dual-stack nodes; on single-stack nodes require the slot to be empty.
- [pkg/datapath/loader/ztunnel_policy_reachability_test.go](pkg/datapath/loader/ztunnel_policy_reachability_test.go):
  - Inject the six map sizes through the production `NodeExtraDefines` writer path.
  - Normalize the LB config with `loadbalancer.NewConfig`.
  - Set the NAT, neighbour and fragment map sizes, and restore them afterwards.
  - Prepend the generated globals directory to `testIncludes` for this test only.
  - Fix the policy-map pin restore with `Unpin`.
  - Log the kernel map inventory.
  - Add negative cases: missing pin, deleted slot, populated slot 29, and an emptied global policy slot.
  - Check from the parent test that the configuration is restored.

## Patch B (apply only after the inventory confirms it)
- `cil_to_container`: require `callsID` only.
- Slot 7: require `callsID` only.
- Slot 13: require `policyMapID` instead of `policyCallID`.
- Apply the same changes to the IPv6 slots.

## Gates
- The focused privileged race run passes with 0 skips.
- The two-phase compile produces two template hashes.
- No zero-size map error appears.
- The full loader package passes, both privileged and unprivileged.
- `go vet` reports nothing and lint reports 0 issues.
- No Protected claim. The combined compatibility guard stays CLOSED.

## Complete Patch A

```diff
--- a/pkg/datapath/loader/compile.go
+++ b/pkg/datapath/loader/compile.go
@@ -177,13 +177,8 @@
 	ctx, cancel := context.WithTimeout(ctx, defaults.ExecTimeout)
 	defer cancel()
 
-	// Generated runtime headers must take precedence over test-only include roots.
-	// In particular, bpf/node_config.h is a deprecated static fallback; placing
-	// testIncludes first would shadow the generated globals/node_config.h and
-	// silently compile endpoint programs with the wrong node feature set.
-	compileArgs := []string{fmt.Sprintf("-I%s", path.Join(dir.Runtime, "globals"))}
-	compileArgs = append(compileArgs, testIncludes...)
-	compileArgs = append(compileArgs,
+	compileArgs := append(testIncludes,
+		fmt.Sprintf("-I%s", path.Join(dir.Runtime, "globals")),
 		fmt.Sprintf("-I%s", dir.State),
 		fmt.Sprintf("-I%s", dir.Library),
 		fmt.Sprintf("-I%s", path.Join(dir.Library, "include")),
--- a/pkg/datapath/loader/util_test.go
+++ b/pkg/datapath/loader/util_test.go
@@ -67,6 +67,10 @@
 }
 
 func newTestLoader(tb testing.TB) *loader {
+	return newTestLoaderWithConfigWriter(tb, configWriterForTest(tb))
+}
+
+func newTestLoaderWithConfigWriter(tb testing.TB, writer linuxConfig.Writer) *loader {
 	setupCompilationDirectories(tb)
 
 	var l *loader
@@ -92,7 +96,7 @@
 			resolver, promise := promise.New[endpointstate.Restorer]()
 			resolver.Resolve(&FakeRestorer{})
 			return sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
-				configWriterForTest(tb),
+				writer,
 				&manager.NodeConfigNotifier{},
 				promise,
 				&FakePreFilter{}
--- a/pkg/datapath/loader/ztunnel_policy_reachability.go
+++ b/pkg/datapath/loader/ztunnel_policy_reachability.go
@@ -5,6 +5,7 @@
 
 import (
 	"context"
+	"errors"
 	"fmt"
 	"path/filepath"
 	"reflect"
@@ -47,6 +48,12 @@
 	Revision  uint64
 }
 
+type policyTailCallHop struct {
+	index uint32
+	name  string
+	maps  []uint32
+}
+
 // VerifyZtunnelPolicyMapReachability is a point-in-time read of the actual
 // pinned Cilium endpoint maps, ProgramArray targets, and TCX links. A missing
 // map ID, unsupported kernel query, unsupported datapath mode, or any mismatch
@@ -182,6 +189,10 @@
 		out.ToContainerProgramID, out.ToContainerLinkID = toLink.ProgramID, toLink.LinkID
 		out.ToContainerAttachSetRevision = toLink.Revision
 	}
+
+	// bpf_lxc.c cil_lxc_policy tail-calls the policy-only CT slots only when
+	// both families are compiled; single-stack objects inline that lookup.
+	dualStack := option.Config.EnableIPv4 && option.Config.EnableIPv6
 
 	if identity.IPv4 {
 		from4, err := lookupProgram(calls, callIPv4FromLXC, "tail_handle_ipv4", callsID, policyMapID)
@@ -214,16 +225,17 @@
 			out.EgressPrograms = append(out.EgressPrograms, ref)
 		}
 
-		for _, hop := range []struct {
-			index uint32
-			name  string
-			maps  []uint32
-		}{
+		ingress := []policyTailCallHop{
 			{callIPv4CTIngress, "tail_ipv4_ct_ingress", []uint32{callsID}},
 			{callIPv4ToEndpoint, "tail_ipv4_to_endpoint", []uint32{policyCallID}},
-			{callIPv4CTIngressPolicyOnly, "tail_ipv4_ct_ingress_policy_only", []uint32{callsID}},
-			{callIPv4ToLXCPolicyOnly, "tail_ipv4_policy", []uint32{callsID, policyMapID}},
-		} {
+		}
+		if dualStack {
+			ingress = append(ingress, policyTailCallHop{callIPv4CTIngressPolicyOnly, "tail_ipv4_ct_ingress_policy_only", []uint32{callsID}})
+		} else if err := requireEmptyProgramArraySlot(calls, callIPv4CTIngressPolicyOnly); err != nil {
+			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv4 policy tail-call slot %d: %w", callIPv4CTIngressPolicyOnly, err)
+		}
+		ingress = append(ingress, policyTailCallHop{callIPv4ToLXCPolicyOnly, "tail_ipv4_policy", []uint32{callsID, policyMapID}})
+		for _, hop := range ingress {
 			program, err := lookupProgram(calls, hop.index, hop.name, hop.maps...)
 			if err != nil {
 				return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv4 policy tail-call slot %d: %w", hop.index, err)
@@ -267,16 +279,17 @@
 			out.EgressPrograms = append(out.EgressPrograms, ref)
 		}
 
-		for _, hop := range []struct {
-			index uint32
-			name  string
-			maps  []uint32
-		}{
+		ingress := []policyTailCallHop{
 			{callIPv6CTIngress, "tail_ipv6_ct_ingress", []uint32{callsID}},
 			{callIPv6ToEndpoint, "tail_ipv6_to_endpoint", []uint32{policyCallID}},
-			{callIPv6CTIngressPolicyOnly, "tail_ipv6_ct_ingress_policy_only", []uint32{callsID}},
-			{callIPv6ToLXCPolicyOnly, "tail_ipv6_policy", []uint32{callsID, policyMapID}},
-		} {
+		}
+		if dualStack {
+			ingress = append(ingress, policyTailCallHop{callIPv6CTIngressPolicyOnly, "tail_ipv6_ct_ingress_policy_only", []uint32{callsID}})
+		} else if err := requireEmptyProgramArraySlot(calls, callIPv6CTIngressPolicyOnly); err != nil {
+			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv6 policy tail-call slot %d: %w", callIPv6CTIngressPolicyOnly, err)
+		}
+		ingress = append(ingress, policyTailCallHop{callIPv6ToLXCPolicyOnly, "tail_ipv6_policy", []uint32{callsID, policyMapID}})
+		for _, hop := range ingress {
 			program, err := lookupProgram(calls, hop.index, hop.name, hop.maps...)
 			if err != nil {
 				return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv6 policy tail-call slot %d: %w", hop.index, err)
@@ -390,6 +403,22 @@
 		return nil, fmt.Errorf("ProgramArray index %d target map bindings: %w", index, err)
 	}
 	return program, nil
+}
+
+func requireEmptyProgramArraySlot(programArray *ebpf.Map, index uint32) error {
+	var program *ebpf.Program
+	err := programArray.Lookup(&index, &program)
+	if errors.Is(err, ebpf.ErrKeyNotExist) {
+		return nil
+	}
+	if err != nil {
+		return fmt.Errorf("read ProgramArray index %d: %w", index, err)
+	}
+	if program == nil {
+		return nil
+	}
+	_ = program.Close()
+	return fmt.Errorf("ProgramArray index %d is populated, but the single-stack endpoint object inlines this lookup", index)
 }
 
 func requireProgramMaps(info *ebpf.ProgramInfo, required ...uint32) error {
--- a/pkg/datapath/loader/ztunnel_policy_reachability_test.go
+++ b/pkg/datapath/loader/ztunnel_policy_reachability_test.go
@@ -7,13 +7,15 @@
 
 import (
 	"context"
+	"errors"
+	"fmt"
 	"log/slog"
 	"os"
 	"path/filepath"
 	"regexp"
 	"runtime"
+	"slices"
 	"strconv"
-	"strings"
 	"testing"
 	"time"
 	"unsafe"
@@ -26,11 +28,19 @@
 	"golang.org/x/sys/unix"
 
 	"github.com/cilium/cilium/pkg/bpf"
+	linuxConfig "github.com/cilium/cilium/pkg/datapath/linux/config"
+	dpdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
 	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
+	"github.com/cilium/cilium/pkg/defaults"
 	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
+	"github.com/cilium/cilium/pkg/kpr"
+	"github.com/cilium/cilium/pkg/loadbalancer"
 	"github.com/cilium/cilium/pkg/lock"
 	"github.com/cilium/cilium/pkg/maglev"
+	"github.com/cilium/cilium/pkg/maps/egressmap"
+	fakeNodeMap "github.com/cilium/cilium/pkg/maps/nodemap/fake"
 	"github.com/cilium/cilium/pkg/maps/policymap"
+	fakenode "github.com/cilium/cilium/pkg/node/fake"
 	"github.com/cilium/cilium/pkg/option"
 	"github.com/cilium/cilium/pkg/testutils"
 )
@@ -66,6 +76,25 @@
 			got, err := strconv.ParseUint(string(match[1]), 10, 32)
 			require.NoError(t, err)
 			require.Equal(t, want, uint32(got))
+		})
+	}
+}
+
+// The verifier requires an empty policy-only CT slot in single-stack objects.
+// This source check fails if bpf_lxc.c stops gating that tail call on both families.
+func TestZtunnelPolicyReachabilityPolicyOnlyCTSlotIsDualStackOnly(t *testing.T) {
+	_, sourceFile, _, ok := runtime.Caller(0)
+	require.True(t, ok)
+	source, err := os.ReadFile(filepath.Join(filepath.Dir(sourceFile), "../../../bpf/bpf_lxc.c"))
+	require.NoError(t, err)
+
+	for family, macro := range map[string]string{
+		"IPv4": "CILIUM_CALL_IPV4_CT_INGRESS_POLICY_ONLY",
+		"IPv6": "CILIUM_CALL_IPV6_CT_INGRESS_POLICY_ONLY",
+	} {
+		t.Run(family, func(t *testing.T) {
+			pattern := regexp.MustCompile(`if \(is_defined\(ENABLE_IPV4\) && is_defined\(ENABLE_IPV6\)\)\s+ret = tail_call_internal\(ctx, ` + macro + `,`)
+			require.Regexp(t, pattern, string(source))
 		})
 	}
 }
@@ -104,73 +133,225 @@
 
 func (*policyReachabilityTestEndpoint) RequireEgressProg() bool { return true }
 
-// appendReachabilityMapDefaultsForTest supplies only map-size defines that the
-// narrow loader test Hive does not register. Values come from Cilium's checked-in
-// default node_config.h; the generated runtime header remains authoritative for
-// node feature macros such as ENABLE_IPV4.
-func appendReachabilityMapDefaultsForTest(t *testing.T) {
+// reachabilityNodeDefinesForTest returns the node defines that production map
+// cells contribute through the header-node-defines group. The loader test Hive
+// omits those cells because their start hooks create and pin maps.
+func reachabilityNodeDefinesForTest(t *testing.T) dpdef.Map {
 	t.Helper()
 
-	generatedPath := option.Config.GetNodeConfigPath()
-	generated, err := os.ReadFile(generatedPath)
-	require.NoError(t, err)
-	fallback, err := os.ReadFile(filepath.Join(option.Config.BpfDir, "node_config.h"))
-	require.NoError(t, err)
-
-	mapSizeDefines := []string{
-		"POLICY_STATS_MAP_SIZE",
-		"POLICY_MAP_SIZE",
-		"EGRESS_POLICY_MAP_SIZE",
-		"SRV6_VRF_MAP_SIZE",
-		"SRV6_POLICY_MAP_SIZE",
-		"SRV6_SID_MAP_SIZE",
-	}
-	wanted := make(map[string]struct{}, len(mapSizeDefines))
-	for _, name := range mapSizeDefines {
-		wanted[name] = struct{}{}
-	}
-
-	fallbackValues := make(map[string]string, len(mapSizeDefines))
-	for _, line := range strings.Split(string(fallback), "\n") {
-		fields := strings.Fields(line)
-		if len(fields) < 3 || fields[0] != "#define" {
+	possibleCPUs, err := ebpf.PossibleCPU()
+	require.NoError(t, err)
+	statsEntries := policymap.DefaultPolicyConfig.BpfPolicyStatsMapMax
+	statsEntries -= statsEntries % possibleCPUs
+
+	nodeDefines := dpdef.Map{
+		"POLICY_MAP_SIZE":        strconv.Itoa(policymap.DefaultPolicyConfig.BpfPolicyMapMax),
+		"POLICY_STATS_MAP_SIZE":  strconv.Itoa(statsEntries),
+		"EGRESS_POLICY_MAP_SIZE": strconv.Itoa(egressmap.DefaultPolicyConfig.EgressGatewayPolicyMapMax),
+	}
+	// srv6map does not export its map sizes; bpf/node_config.h carries the same values.
+	checkedIn, err := os.ReadFile(filepath.Join(bpfDir, "node_config.h"))
+	require.NoError(t, err)
+	for _, name := range []string{"SRV6_VRF_MAP_SIZE", "SRV6_POLICY_MAP_SIZE", "SRV6_SID_MAP_SIZE"} {
+		value, ok := numericDefine(checkedIn, name)
+		require.Truef(t, ok, "bpf/node_config.h must define %s as a decimal literal", name)
+		nodeDefines[name] = strconv.FormatUint(value, 10)
+	}
+	return nodeDefines
+}
+
+func numericDefine(header []byte, name string) (uint64, bool) {
+	match := regexp.MustCompile(`(?m)^#define\s+` + regexp.QuoteMeta(name) + `\s+([0-9]+)\s*$`).FindSubmatch(header)
+	if len(match) != 2 {
+		return 0, false
+	}
+	value, err := strconv.ParseUint(string(match[1]), 10, 32)
+	return value, err == nil
+}
+
+func reachabilityConfigWriterForTest(t *testing.T) linuxConfig.Writer {
+	t.Helper()
+
+	writer, err := linuxConfig.NewHeaderfileWriter(linuxConfig.WriterParams{
+		NodeMap:          fakeNodeMap.NewFakeNodeMapV2(),
+		NodeAddressing:   fakenode.NewAddressing(),
+		NodeExtraDefines: []dpdef.Map{reachabilityNodeDefinesForTest(t)},
+	})
+	require.NoError(t, err)
+	return writer
+}
+
+// reachabilityNodeSizeDefines are node_config.h map sizes that bpf_lxc.c can
+// read. A zero value compiles, but map creation then fails at load time.
+var reachabilityNodeSizeDefines = []string{
+	"CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES",
+	"CILIUM_IPV6_FRAG_MAP_MAX_ENTRIES",
+	"CILIUM_LB_AFFINITY_MAP_MAX_ENTRIES",
+	"CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES",
+	"CILIUM_LB_MAGLEV_MAP_MAX_ENTRIES",
+	"CILIUM_LB_REV_NAT_MAP_MAX_ENTRIES",
+	"CILIUM_LB_SERVICE_MAP_MAX_ENTRIES",
+	"CT_MAP_SIZE_ANY",
+	"CT_MAP_SIZE_TCP",
+	"EGRESS_POLICY_MAP_SIZE",
+	"LB4_REVERSE_NAT_SK_MAP_SIZE",
+	"LB4_SRC_RANGE_MAP_SIZE",
+	"LB6_REVERSE_NAT_SK_MAP_SIZE",
+	"LB6_SRC_RANGE_MAP_SIZE",
+	"LB_MAGLEV_LUT_SIZE",
+	"NODEPORT_NEIGH4_SIZE",
+	"NODEPORT_NEIGH6_SIZE",
+	"POLICY_MAP_SIZE",
+	"POLICY_STATS_MAP_SIZE",
+	"SNAT_MAPPING_IPV4_SIZE",
+	"SNAT_MAPPING_IPV6_SIZE",
+	"SRV6_POLICY_MAP_SIZE",
+	"SRV6_SID_MAP_SIZE",
+	"SRV6_VRF_MAP_SIZE",
+}
+
+type reachabilityGlobalConfig struct {
+	enableTCX             bool
+	enableIPv4            bool
+	enableIPv6            bool
+	enableL7Proxy         bool
+	enableEnvoyConfig     bool
+	enableDatapathPlugins bool
+	enableIPv4Masquerade  bool
+	enableIPv6Masquerade  bool
+	enableBPFMasquerade   bool
+	fragmentsMapEntries   int
+	natMapEntriesGlobal   int
+	neighMapEntriesGlobal int
+}
+
+func snapshotReachabilityGlobalConfig() reachabilityGlobalConfig {
+	return reachabilityGlobalConfig{
+		enableTCX:             option.Config.EnableTCX,
+		enableIPv4:            option.Config.EnableIPv4,
+		enableIPv6:            option.Config.EnableIPv6,
+		enableL7Proxy:         option.Config.EnableL7Proxy,
+		enableEnvoyConfig:     option.Config.EnableEnvoyConfig,
+		enableDatapathPlugins: option.Config.EnableDatapathPlugins,
+		enableIPv4Masquerade:  option.Config.EnableIPv4Masquerade,
+		enableIPv6Masquerade:  option.Config.EnableIPv6Masquerade,
+		enableBPFMasquerade:   option.Config.EnableBPFMasquerade,
+		fragmentsMapEntries:   option.Config.FragmentsMapEntries,
+		natMapEntriesGlobal:   option.Config.NATMapEntriesGlobal,
+		neighMapEntriesGlobal: option.Config.NeighMapEntriesGlobal,
+	}
+}
+
+func (c reachabilityGlobalConfig) restore() {
+	option.Config.EnableTCX = c.enableTCX
+	option.Config.EnableIPv4 = c.enableIPv4
+	option.Config.EnableIPv6 = c.enableIPv6
+	option.Config.EnableL7Proxy = c.enableL7Proxy
+	option.Config.EnableEnvoyConfig = c.enableEnvoyConfig
+	option.Config.EnableDatapathPlugins = c.enableDatapathPlugins
+	option.Config.EnableIPv4Masquerade = c.enableIPv4Masquerade
+	option.Config.EnableIPv6Masquerade = c.enableIPv6Masquerade
+	option.Config.EnableBPFMasquerade = c.enableBPFMasquerade
+	option.Config.FragmentsMapEntries = c.fragmentsMapEntries
+	option.Config.NATMapEntriesGlobal = c.natMapEntriesGlobal
+	option.Config.NeighMapEntriesGlobal = c.neighMapEntriesGlobal
+}
+
+func programIndexes(references []endpointtypes.ZtunnelPolicyProgramReference) []uint32 {
+	indexes := make([]uint32, 0, len(references))
+	for _, reference := range references {
+		indexes = append(indexes, reference.Index)
+	}
+	return indexes
+}
+
+// logPolicyPathInventory records which endpoint maps each attached and
+// tail-called program references in the kernel. It asserts no reachability; it
+// makes a wrong verifier map table diagnosable from one privileged run.
+func logPolicyPathInventory(t *testing.T, l *loader, endpointID uint16, ifIndex int) {
+	t.Helper()
+
+	calls, callsID, err := loadKernelMap(l.CallsMapPath(endpointID), ebpf.ProgramArray, 4, 4)
+	require.NoError(t, err)
+	defer calls.Close()
+	policy, policyMapID, err := loadKernelMap(
+		bpf.LocalMapPath(l.logger, policymap.MapName, endpointID),
+		ebpf.LPMTrie,
+		uint32(unsafe.Sizeof(policymap.PolicyKey{})),
+		uint32(unsafe.Sizeof(policymap.PolicyEntry{})),
+	)
+	require.NoError(t, err)
+	defer policy.Close()
+	policyCalls, policyCallID, err := loadKernelMap(bpf.MapPath(l.logger, policymap.PolicyCallMapName), ebpf.ProgramArray, 4, 4)
+	require.NoError(t, err)
+	defer policyCalls.Close()
+
+	describe := func(label string, program *ebpf.Program) {
+		defer program.Close()
+		info, err := program.Info()
+		require.NoError(t, err)
+		ids, ok := info.MapIDs()
+		require.True(t, ok, "kernel must expose program map IDs")
+		t.Logf("policy-path inventory %s: name=%s calls=%t policy=%t policy_call=%t",
+			label, info.Name,
+			slices.Contains(ids, ebpf.MapID(callsID)),
+			slices.Contains(ids, ebpf.MapID(policyMapID)),
+			slices.Contains(ids, ebpf.MapID(policyCallID)))
+	}
+
+	for index := range calls.MaxEntries() {
+		var program *ebpf.Program
+		err := calls.Lookup(&index, &program)
+		if errors.Is(err, ebpf.ErrKeyNotExist) {
 			continue
 		}
-		if _, ok := wanted[fields[1]]; ok {
-			fallbackValues[fields[1]] = strings.Join(fields[2:], " ")
+		require.NoError(t, err)
+		if program != nil {
+			describe(fmt.Sprintf("cilium_calls[%d]", index), program)
 		}
 	}
-
-	for _, name := range mapSizeDefines {
-		pattern := regexp.MustCompile(`(?m)^#define\s+` + regexp.QuoteMeta(name) + `(?:\s|$)`)
-		if pattern.Match(generated) {
-			continue
+	endpointKey := uint32(endpointID)
+	var policyProgram *ebpf.Program
+	require.NoError(t, policyCalls.Lookup(&endpointKey, &policyProgram))
+	require.NotNil(t, policyProgram)
+	describe("cilium_call_policy[endpoint]", policyProgram)
+	for _, attach := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
+		result, err := link.QueryPrograms(link.QueryOptions{Target: ifIndex, Attach: attach})
+		require.NoError(t, err)
+		for _, attached := range result.Programs {
+			program, err := ebpf.NewProgramFromID(attached.ID)
+			require.NoError(t, err)
+			describe("tcx "+attach.String(), program)
 		}
-		value, ok := fallbackValues[name]
-		require.Truef(t, ok, "checked-in default node_config.h must define %s", name)
-		generated = append(generated, []byte("\n#define "+name+" "+value+"\n")...)
-	}
-	require.NoError(t, os.WriteFile(generatedPath, generated, 0o600))
+	}
 }
 
 func TestPrivilegedZtunnelPolicyMapReachabilityReadsAndRejectsKernelPathChanges(t *testing.T) {
 	testutils.PrivilegedTest(t)
 	lock.SetLogger(slog.Default())
-	if err := rlimit.RemoveMemlock(); err != nil {
-		t.Fatal(err)
-	}
+	require.NoError(t, rlimit.RemoveMemlock())
 	skipTCXUnsupported(t)
+
+	globalsBefore := snapshotReachabilityGlobalConfig()
+	includesBefore := slices.Clone(testIncludes)
+	_, err := os.Stat(bpf.TCGlobalsPath())
+	globalsPathExisted := err == nil
+
+	t.Run("kernel path", verifyPolicyMapReachabilityKernelPath)
+
+	require.Equal(t, globalsBefore, snapshotReachabilityGlobalConfig(), "the test must restore every option.Config field it changes")
+	require.Equal(t, includesBefore, testIncludes, "the test must restore the shared compile include list")
+	if !globalsPathExisted {
+		_, err = os.Stat(bpf.TCGlobalsPath())
+		require.ErrorIs(t, err, os.ErrNotExist, "the private bpffs fixture must remove its pinned maps")
+	}
+}
+
+func verifyPolicyMapReachabilityKernelPath(t *testing.T) {
 	initBpffs(t)
 
-	oldTCX := option.Config.EnableTCX
-	oldIPv4 := option.Config.EnableIPv4
-	oldIPv6 := option.Config.EnableIPv6
-	oldL7Proxy := option.Config.EnableL7Proxy
-	oldEnvoyConfig := option.Config.EnableEnvoyConfig
-	oldPlugins := option.Config.EnableDatapathPlugins
-	oldMasq4 := option.Config.EnableIPv4Masquerade
-	oldMasq6 := option.Config.EnableIPv6Masquerade
-	oldBPFMasq := option.Config.EnableBPFMasquerade
+	globals := snapshotReachabilityGlobalConfig()
+	t.Cleanup(globals.restore)
 	option.Config.EnableTCX = true
 	// First compile with no IP-family datapath enabled. bpf_lxc.c then has no
 	// reachable policy lookup, so the ELF correctly omits cilium_policy. The
@@ -184,42 +365,59 @@
 	option.Config.EnableIPv4Masquerade = false
 	option.Config.EnableIPv6Masquerade = false
 	option.Config.EnableBPFMasquerade = false
-	t.Cleanup(func() {
-		option.Config.EnableTCX = oldTCX
-		option.Config.EnableIPv4 = oldIPv4
-		option.Config.EnableIPv6 = oldIPv6
-		option.Config.EnableL7Proxy = oldL7Proxy
-		option.Config.EnableEnvoyConfig = oldEnvoyConfig
-		option.Config.EnableDatapathPlugins = oldPlugins
-		option.Config.EnableIPv4Masquerade = oldMasq4
-		option.Config.EnableIPv6Masquerade = oldMasq6
-		option.Config.EnableBPFMasquerade = oldBPFMasq
-	})
-
-	l := newTestLoader(t)
+	// The agent never writes these sizes as zero: DaemonConfig.Validate rejects
+	// small NAT and fragment maps, and dynamic sizing copies NAT to neighbour.
+	option.Config.FragmentsMapEntries = defaults.FragmentsMapEntries
+	option.Config.NATMapEntriesGlobal = option.NATMapEntriesGlobalDefault
+	option.Config.NeighMapEntriesGlobal = option.NATMapEntriesGlobalDefault
+
+	l := newTestLoaderWithConfigWriter(t, reachabilityConfigWriterForTest(t))
 	l.logger = hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
+	// The shared fixture lists static bpf/ before the generated globals
+	// directory, so bpf/node_config.h would shadow the profiles below. compile()
+	// appends to testIncludes, so the override must not leave spare capacity.
+	sharedIncludes := testIncludes
+	testIncludes = slices.Clip(append([]string{"-I" + option.Config.GetGlobalsDir()}, sharedIncludes...))
+	t.Cleanup(func() { testIncludes = sharedIncludes })
+
 	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
 	defer cancel()
+
+	lbConfig, err := loadbalancer.NewConfig(l.logger, loadbalancer.DefaultUserConfig, option.Config, kpr.KPRConfig{})
+	require.NoError(t, err)
 	lnc := localNodeConfig
+	lnc.LBConfig = lbConfig
 	lnc.EnableIPv4 = false
 	lnc.EnableIPv6 = false
 	lnc.DeviceMTU = 1500
 	lnc.MaglevConfig = maglev.DefaultConfig
 	ep := &policyReachabilityTestEndpoint{sourceIPReceiptTestEndpoint: newSourceIPReceiptTestEndpoint(t, 42, "p", "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", true)}
 	t.Cleanup(func() { l.Unload(ep) })
-	// ReloadDatapath assumes the node-generated header has been provisioned by
-	// Reinitialize in production. This unit fixture calls that narrow setup
-	// directly so ENABLE_IPV4/ENABLE_IPV6 reflect the test's chosen profile.
+	policyPath := bpf.LocalMapPath(l.logger, policymap.MapName, 42)
+
+	// Production Reinitialize writes the node header before endpoint loads.
 	require.NoError(t, os.MkdirAll(option.Config.GetGlobalsDir(), 0o755))
-	require.NoError(t, l.writeNodeConfigHeader(&lnc))
-	appendReachabilityMapDefaultsForTest(t)
-	nodeConfig, err := os.ReadFile(option.Config.GetNodeConfigPath())
-	require.NoError(t, err)
-	require.NotContains(t, string(nodeConfig), "ENABLE_IPV4")
-	require.NotContains(t, string(nodeConfig), "ENABLE_IPV6")
-	require.NoError(t, l.templateCache.UpdateDatapathHash(&lnc))
+	writeNodeConfig := func() string {
+		t.Helper()
+		require.NoError(t, l.writeNodeConfigHeader(&lnc))
+		header, err := os.ReadFile(option.Config.GetNodeConfigPath())
+		require.NoError(t, err)
+		for _, name := range reachabilityNodeSizeDefines {
+			value, ok := numericDefine(header, name)
+			require.Truef(t, ok, "generated node_config.h must define %s", name)
+			require.NotZerof(t, value, "generated node_config.h must not size %s to zero", name)
+		}
+		require.NoError(t, l.templateCache.UpdateDatapathHash(&lnc))
+		return string(header)
+	}
+
+	nodeConfig := writeNodeConfig()
+	require.NotContains(t, nodeConfig, "ENABLE_IPV4")
+	require.NotContains(t, nodeConfig, "ENABLE_IPV6")
 	_, err = l.ReloadDatapath(ctx, ep, &lnc, &metrics.SpanStat{})
 	require.NoError(t, err, "test must load the actual Cilium endpoint object")
+	_, err = os.Stat(policyPath)
+	require.ErrorIs(t, err, os.ErrNotExist, "an object without IP-family policy hooks must not pin an endpoint policy map")
 
 	compiledOutIdentity := endpointtypes.ZtunnelPolicyMapReachabilityIdentity{
 		EndpointID: 42, NamespaceUID: "00000000-0000-4000-8000-000000000001", PodUID: "00000000-0000-4000-8000-000000000002",
@@ -237,17 +435,12 @@
 	l.Unload(ep)
 	option.Config.EnableIPv4 = true
 	lnc.EnableIPv4 = true
-	require.NoError(t, l.writeNodeConfigHeader(&lnc))
-	appendReachabilityMapDefaultsForTest(t)
-	nodeConfig, err = os.ReadFile(option.Config.GetNodeConfigPath())
-	require.NoError(t, err)
-	require.Contains(t, string(nodeConfig), "ENABLE_IPV4")
-	require.NotContains(t, string(nodeConfig), "ENABLE_IPV6")
-	require.NoError(t, l.templateCache.UpdateDatapathHash(&lnc))
+	nodeConfig = writeNodeConfig()
+	require.Contains(t, nodeConfig, "#define ENABLE_IPV4 1")
+	require.NotContains(t, nodeConfig, "ENABLE_IPV6")
 	_, err = l.ReloadDatapath(ctx, ep, &lnc, &metrics.SpanStat{})
-	require.NoError(t, err, "the real IPv4 Cilium endpoint should recover after the node feature is enabled")
-
-	policyPath := bpf.LocalMapPath(l.logger, policymap.MapName, 42)
+	require.NoError(t, err, "the real IPv4 Cilium endpoint should load after the node feature is enabled")
+
 	policyMap, policyMapID, err := loadKernelMap(
 		policyPath,
 		ebpf.LPMTrie,
@@ -256,6 +449,8 @@
 	)
 	require.NoError(t, err)
 	require.NoError(t, policyMap.Close())
+	logPolicyPathInventory(t, l, 42, ep.GetIfIndex())
+
 	identity := endpointtypes.ZtunnelPolicyMapReachabilityIdentity{
 		EndpointID: 42, NamespaceUID: "00000000-0000-4000-8000-000000000001", PodUID: "00000000-0000-4000-8000-000000000002",
 		NetNSPath: ep.netNSPath, NetNSCookie: ep.NetNsCookie,
@@ -263,23 +458,30 @@
 		PolicyDigest: "kernel-fixture-policy", DatapathConfigHash: "kernel-fixture-config",
 		IPv4: ep.IPv4Address().IsValid(), IPv6: ep.IPv6Address().IsValid(), RequireToContainer: ep.RequireEgressProg(),
 	}
+	verify := func() error {
+		_, err := l.VerifyZtunnelPolicyMapReachability(ctx, identity)
+		return err
+	}
 
 	observation, err := l.VerifyZtunnelPolicyMapReachability(ctx, identity)
 	require.NoError(t, err)
 	require.Equal(t, identity, observation.Identity)
+	require.Equal(t, policyMapID, observation.PolicyMapID)
 	require.NotZero(t, observation.CallsMapID)
 	require.NotZero(t, observation.PolicyCallMapID)
+	require.NotZero(t, observation.EndpointPolicyProgramID)
 	require.NotZero(t, observation.FromContainerProgramID)
 	require.NotZero(t, observation.FromContainerLinkID)
 	require.NotZero(t, observation.ToContainerProgramID)
 	require.NotZero(t, observation.ToContainerLinkID)
-	require.NotEmpty(t, observation.EgressPrograms)
-	require.NotEmpty(t, observation.IngressPrograms)
+	require.Equal(t, []uint32{callIPv4FromLXC, callIPv4CTEgress, callIPv4FromLXCCont}, programIndexes(observation.EgressPrograms))
+	require.Equal(t, []uint32{callIPv4CTIngress, callIPv4ToEndpoint, callIPv4ToLXCPolicyOnly}, programIndexes(observation.IngressPrograms),
+		"a single-stack object inlines the policy-only CT lookup")
 
 	wrongMap := identity
 	wrongMap.PolicyMapID++
 	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, wrongMap)
-	require.Error(t, err, "the current endpoint policy-map pin must match the ID from the native policy snapshot")
+	require.ErrorContains(t, err, "endpoint policy map ID changed", "the current endpoint policy-map pin must match the ID from the native policy snapshot")
 
 	originalPolicyMap, err := ebpf.LoadPinnedMap(policyPath, nil)
 	require.NoError(t, err)
@@ -292,61 +494,53 @@
 		Flags:      unix.BPF_F_NO_PREALLOC | unix.BPF_F_RDONLY_PROG,
 	})
 	require.NoError(t, err)
-	originalPolicyPinned := true
-	replacementPolicyPinned := false
 	t.Cleanup(func() {
-		if replacementPolicyPinned {
-			require.NoError(t, os.Remove(policyPath))
-			replacementPolicyPinned = false
-		}
-		if !originalPolicyPinned {
+		// Map.Pin is a no-op when the handle already records the same path, so
+		// every pin change goes through Unpin on the handle that owns the path.
+		require.NoError(t, replacementPolicyMap.Unpin())
+		if !originalPolicyMap.IsPinned() {
 			require.NoError(t, originalPolicyMap.Pin(policyPath))
-			originalPolicyPinned = true
 		}
 		require.NoError(t, replacementPolicyMap.Close())
 		require.NoError(t, originalPolicyMap.Close())
 	})
-	require.NoError(t, os.Remove(policyPath))
-	originalPolicyPinned = false
+	require.NoError(t, originalPolicyMap.Unpin())
+	require.ErrorContains(t, verify(), "open endpoint policy map", "a missing endpoint policy-map pin must withhold reachability evidence")
 	require.NoError(t, replacementPolicyMap.Pin(policyPath))
-	replacementPolicyPinned = true
-	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, identity)
-	require.Error(t, err, "a replacement LPM pin at the same endpoint path must not inherit the old map identity")
-	require.NoError(t, os.Remove(policyPath))
-	replacementPolicyPinned = false
+	require.ErrorContains(t, verify(), "endpoint policy map ID changed", "a replacement LPM pin at the same endpoint path must not inherit the old map identity")
+	require.NoError(t, replacementPolicyMap.Unpin())
 	require.NoError(t, originalPolicyMap.Pin(policyPath))
-	originalPolicyPinned = true
-	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, identity)
-	require.NoError(t, err, "restoring the original endpoint policy map must recover")
+	require.NoError(t, verify(), "restoring the original endpoint policy map must recover")
 
 	calls, _, err := loadKernelMap(l.CallsMapPath(42), ebpf.ProgramArray, 4, 4)
 	require.NoError(t, err)
 	t.Cleanup(func() { require.NoError(t, calls.Close()) })
-	index := callIPv4FromLXC
-	var originalEgress *ebpf.Program
-	require.NoError(t, calls.Lookup(&index, &originalEgress))
-	require.NotNil(t, originalEgress)
-	defer originalEgress.Close()
 	rogue := mustTCProgramWithName(t, "rogue_tail")
-	t.Cleanup(func() { require.NoError(t, rogue.Close()) })
-	require.NoError(t, calls.Update(&index, rogue, ebpf.UpdateAny))
-	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, identity)
-	require.Error(t, err, "replacing the live endpoint egress tail-call target must withhold reachability evidence")
-	require.NoError(t, calls.Update(&index, originalEgress, ebpf.UpdateAny))
-	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, identity)
-	require.NoError(t, err, "restoring the real Cilium tail-call target must recover")
-	for _, index := range []uint32{callIPv4FromLXCCont, callIPv4ToLXCPolicyOnly} {
+	for _, index := range []uint32{
+		callIPv4FromLXC, callIPv4CTEgress, callIPv4FromLXCCont,
+		callIPv4CTIngress, callIPv4ToEndpoint, callIPv4ToLXCPolicyOnly,
+	} {
 		var original *ebpf.Program
 		require.NoError(t, calls.Lookup(&index, &original))
 		require.NotNil(t, original)
-		defer original.Close()
+		t.Cleanup(func() { require.NoError(t, original.Close()) })
+
 		require.NoError(t, calls.Update(&index, rogue, ebpf.UpdateAny))
-		_, err = l.VerifyZtunnelPolicyMapReachability(ctx, identity)
-		require.Error(t, err, "replacing a checked egress-continuation or ingress-policy target must withhold reachability evidence")
+		require.Errorf(t, verify(), "replacing checked tail-call slot %d must withhold reachability evidence", index)
 		require.NoError(t, calls.Update(&index, original, ebpf.UpdateAny))
-		_, err = l.VerifyZtunnelPolicyMapReachability(ctx, identity)
-		require.NoError(t, err, "restoring the checked Cilium target must recover")
-	}
+		require.NoErrorf(t, verify(), "restoring tail-call slot %d must recover", index)
+
+		require.NoError(t, calls.Delete(&index))
+		require.Errorf(t, verify(), "an empty checked tail-call slot %d must withhold reachability evidence", index)
+		require.NoError(t, calls.Update(&index, original, ebpf.UpdateAny))
+		require.NoErrorf(t, verify(), "refilling tail-call slot %d must recover", index)
+	}
+
+	policyOnlyCT := callIPv4CTIngressPolicyOnly
+	require.NoError(t, calls.Update(&policyOnlyCT, rogue, ebpf.UpdateAny))
+	require.ErrorContains(t, verify(), "is populated", "a single-stack object must keep the dual-stack-only policy CT slot empty")
+	require.NoError(t, calls.Delete(&policyOnlyCT))
+	require.NoError(t, verify(), "clearing the unreachable slot must recover")
 
 	policyCalls, _, err := loadKernelMap(bpf.MapPath(l.logger, policymap.PolicyCallMapName), ebpf.ProgramArray, 4, 4)
 	require.NoError(t, err)
@@ -355,30 +549,27 @@
 	var originalPolicy *ebpf.Program
 	require.NoError(t, policyCalls.Lookup(&endpointKey, &originalPolicy))
 	require.NotNil(t, originalPolicy)
-	defer originalPolicy.Close()
+	t.Cleanup(func() { require.NoError(t, originalPolicy.Close()) })
 	require.NoError(t, policyCalls.Update(&endpointKey, rogue, ebpf.UpdateAny))
-	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, identity)
-	require.Error(t, err, "replacing the global destination-policy target must withhold reachability evidence")
+	require.Error(t, verify(), "replacing the global destination-policy target must withhold reachability evidence")
 	require.NoError(t, policyCalls.Update(&endpointKey, originalPolicy, ebpf.UpdateAny))
-	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, identity)
-	require.NoError(t, err, "restoring the real destination-policy target must recover")
+	require.NoError(t, verify(), "restoring the real destination-policy target must recover")
+	require.NoError(t, policyCalls.Delete(&endpointKey))
+	require.Error(t, verify(), "an empty global destination-policy slot must withhold reachability evidence")
+	require.NoError(t, policyCalls.Update(&endpointKey, originalPolicy, ebpf.UpdateAny))
+	require.NoError(t, verify(), "refilling the destination-policy slot must recover")
 
 	extra, err := link.AttachTCX(link.TCXOptions{Program: rogue, Attach: ebpf.AttachTCXIngress, Interface: ep.GetIfIndex(), Anchor: link.Tail()})
 	require.NoError(t, err)
-	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, identity)
-	require.Error(t, err, "an extra ingress program makes the observed attachment set unsupported")
+	require.Error(t, verify(), "an extra ingress program makes the observed attachment set unsupported")
 	require.NoError(t, extra.Close())
-	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, identity)
-	require.NoError(t, err, "the unchanged Cilium path is observable after the extra link is removed")
+	require.NoError(t, verify(), "the unchanged Cilium path is observable after the extra link is removed")
 	extraEgress, err := link.AttachTCX(link.TCXOptions{Program: rogue, Attach: ebpf.AttachTCXEgress, Interface: ep.GetIfIndex(), Anchor: link.Tail()})
 	require.NoError(t, err)
-	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, identity)
-	require.Error(t, err, "an extra destination-side TCX program makes the observed attachment set unsupported")
+	require.Error(t, verify(), "an extra destination-side TCX program makes the observed attachment set unsupported")
 	require.NoError(t, extraEgress.Close())
-	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, identity)
-	require.NoError(t, err, "the unchanged destination-side path recovers after extra link removal")
+	require.NoError(t, verify(), "the unchanged destination-side path recovers after extra link removal")
 
 	l.Unload(ep)
-	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, identity)
-	require.Error(t, err, "endpoint unload must remove the current path")
-}
+	require.Error(t, verify(), "endpoint unload must remove the current path")
+}
```

## Complete Patch B

```diff
--- a/pkg/datapath/loader/ztunnel_policy_reachability.go
+++ b/pkg/datapath/loader/ztunnel_policy_reachability.go
@@ -165,7 +165,7 @@
 		if err != nil {
 			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
 		}
-		if err := requireProgramMaps(toInfo, callsID, policyCallID); err != nil {
+		if err := requireProgramMaps(toInfo, callsID); err != nil {
 			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("to-container entrypoint cannot reach the native endpoint policy path: %w", err)
 		}
 	}
@@ -195,7 +195,7 @@
 	dualStack := option.Config.EnableIPv4 && option.Config.EnableIPv6
 
 	if identity.IPv4 {
-		from4, err := lookupProgram(calls, callIPv4FromLXC, "tail_handle_ipv4", callsID, policyMapID)
+		from4, err := lookupProgram(calls, callIPv4FromLXC, "tail_handle_ipv4", callsID)
 		if err != nil {
 			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv4 egress policy path: %w", err)
 		}
@@ -227,7 +227,7 @@
 
 		ingress := []policyTailCallHop{
 			{callIPv4CTIngress, "tail_ipv4_ct_ingress", []uint32{callsID}},
-			{callIPv4ToEndpoint, "tail_ipv4_to_endpoint", []uint32{policyCallID}},
+			{callIPv4ToEndpoint, "tail_ipv4_to_endpoint", []uint32{policyMapID}},
 		}
 		if dualStack {
 			ingress = append(ingress, policyTailCallHop{callIPv4CTIngressPolicyOnly, "tail_ipv4_ct_ingress_policy_only", []uint32{callsID}})
@@ -249,7 +249,7 @@
 		}
 	}
 	if identity.IPv6 {
-		from6, err := lookupProgram(calls, callIPv6FromLXC, "tail_handle_ipv6", callsID, policyMapID)
+		from6, err := lookupProgram(calls, callIPv6FromLXC, "tail_handle_ipv6", callsID)
 		if err != nil {
 			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv6 egress policy path: %w", err)
 		}
@@ -281,7 +281,7 @@
 
 		ingress := []policyTailCallHop{
 			{callIPv6CTIngress, "tail_ipv6_ct_ingress", []uint32{callsID}},
-			{callIPv6ToEndpoint, "tail_ipv6_to_endpoint", []uint32{policyCallID}},
+			{callIPv6ToEndpoint, "tail_ipv6_to_endpoint", []uint32{policyMapID}},
 		}
 		if dualStack {
 			ingress = append(ingress, policyTailCallHop{callIPv6CTIngressPolicyOnly, "tail_ipv6_ct_ingress_policy_only", []uint32{callsID}})
```
