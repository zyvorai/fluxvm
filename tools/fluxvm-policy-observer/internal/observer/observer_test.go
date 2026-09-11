// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package observer

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct{ responses map[string][]byte }

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	if out, ok := f.responses[key]; ok {
		return out, nil
	}
	if strings.Contains(key, " map dump pinned ") {
		return []byte("[]"), nil
	}
	return nil, fmt.Errorf("unexpected command: %s", key)
}
func putFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
func bytesJSON(b []byte) any {
	a := make([]int, len(b))
	for i, v := range b {
		a[i] = int(v)
	}
	return a
}
func u32(v uint32) []byte { b := make([]byte, 4); binary.NativeEndian.PutUint32(b, v); return b }
func statBytes(a, d, u uint64) []byte {
	b := make([]byte, 24)
	binary.NativeEndian.PutUint64(b[0:8], a)
	binary.NativeEndian.PutUint64(b[8:16], d)
	binary.NativeEndian.PutUint64(b[16:24], u)
	return b
}

// ruleVal builds a minimal struct fluxvm_pod_rule value: only pod_id (bytes
// 0-3) and direction (byte 4) matter to ruleCounts; the rest of the real
// 28-byte struct is irrelevant to this test.
func ruleVal(pod uint32, direction byte) []byte { return append(u32(pod), direction, 0, 0, 0) }

func TestCollectLegacyTCHooksAndDirectionalStats(t *testing.T) {
	root := t.TempDir()
	pinRoot := filepath.Join(root, "bpf")
	metaRoot := filepath.Join(root, "meta")
	vm := "00112233445566778899aabbccddeeff"
	pin := filepath.Join(pinRoot, "vms", vm)
	meta := filepath.Join(metaRoot, vm)
	putFile(t, filepath.Join(meta, "pod_id"), "42\n")
	putFile(t, filepath.Join(meta, "schema_version"), "8\n")
	putFile(t, filepath.Join(meta, "iface"), "tap42\n")
	putFile(t, filepath.Join(meta, "attach_mode"), "tc\n")
	// Set 14: fluxvm_pod_ingress is a separate object sharing the main
	// program's pinned fluxvm_ppstat/fluxvm_pspol -- there is no "_in"
	// suffix, and the former CIDR/port-range maps no longer exist at all
	// (superseded by the unified fluxvm_prules map).
	for _, p := range []string{"progs/fluxvm_egress", "progs/fluxvm_pod_ingress", "maps/fluxvm_ppstat", "maps/fluxvm_pspol", "maps/fluxvm_pid4", "maps/fluxvm_prules"} {
		putFile(t, filepath.Join(pin, p), "")
	}
	stat, _ := json.Marshal([]any{map[string]any{"key": bytesJSON(u32(42)), "values": []any{map[string]any{"cpu": 0, "value": bytesJSON(statBytes(10, 2, 1))}, map[string]any{"cpu": 1, "value": bytesJSON(statBytes(3, 1, 0))}}}})
	// ENABLED|DEFAULT_DENY|AUDIT, not RICH_RULES: the legacy (pre-schema-v2)
	// decode path, where DEFAULT_DENY is an egress-only concept and ingress
	// has no independent isolation bit.
	pol := append(u32(1|2|4), make([]byte, 12)...)
	polJ, _ := json.Marshal([]any{map[string]any{"key": bytesJSON(u32(42)), "value": bytesJSON(pol)}})
	one, _ := json.Marshal([]any{map[string]any{"key": bytesJSON(u32(42)), "value": []int{1}}})
	prules, _ := json.Marshal([]any{
		map[string]any{"key": bytesJSON(u32(0)), "value": bytesJSON(ruleVal(42, 1))},
		map[string]any{"key": bytesJSON(u32(1)), "value": bytesJSON(ruleVal(42, 2))},
		map[string]any{"key": bytesJSON(u32(2)), "value": bytesJSON(ruleVal(99, 1))}, // different pod_id, must not be counted
	})
	r := fakeRunner{responses: map[string][]byte{
		"bpftool -j prog show pinned " + filepath.Join(pin, "progs/fluxvm_egress"):      []byte(`[ {"id":101} ]`),
		"bpftool -j prog show pinned " + filepath.Join(pin, "progs/fluxvm_pod_ingress"): []byte(`[ {"id":202} ]`),
		"tc -j filter show dev tap42 ingress pref 49152":                                []byte(`[{"options":{"id":101}}]`),
		"tc -j filter show dev tap42 egress pref 49153":                                 []byte(`[{"options":{"id":202}}]`),
		"bpftool -j map dump pinned " + filepath.Join(pin, "maps/fluxvm_ppstat"):        stat,
		"bpftool -j map dump pinned " + filepath.Join(pin, "maps/fluxvm_pspol"):         polJ,
		"bpftool -j map dump pinned " + filepath.Join(pin, "maps/fluxvm_pid4"):          one,
		"bpftool -j map dump pinned " + filepath.Join(pin, "maps/fluxvm_prules"):        prules,
	}}
	snap := Collector{PinRoot: pinRoot, MetaRoot: metaRoot, Runner: r}.Collect(context.Background())
	if len(snap.VMs) != 1 {
		t.Fatalf("got %d VMs", len(snap.VMs))
	}
	v := snap.VMs[0]
	if !v.Egress.Attached || !v.Ingress.Attached {
		t.Fatalf("hooks not healthy: %+v %+v", v.Egress, v.Ingress)
	}
	// Set 14 shares one stat counter across both directions.
	want := DirectionStats{Allowed: 13, Dropped: 3, Audited: 1}
	if v.EgressStats != want || v.IngressStats != want {
		t.Fatalf("stats: egress=%+v ingress=%+v want=%+v", v.EgressStats, v.IngressStats, want)
	}
	if !v.EgressPolicy.Enabled || !v.EgressPolicy.DefaultDeny || !v.EgressPolicy.Audit {
		t.Fatalf("egress policy: %+v", v.EgressPolicy)
	}
	if !v.IngressPolicy.Enabled || v.IngressPolicy.DefaultDeny || !v.IngressPolicy.Audit {
		t.Fatalf("ingress policy (legacy mode must not isolate ingress): %+v", v.IngressPolicy)
	}
	if v.RuleEntries["shared_address_v4"] != 1 {
		t.Fatalf("shared_address_v4: %+v", v.RuleEntries)
	}
	if v.RuleEntries["egress_rules"] != 1 || v.RuleEntries["ingress_rules"] != 1 {
		t.Fatalf("rich rule counts: %+v", v.RuleEntries)
	}
	if len(v.Errors) != 0 {
		t.Fatalf("errors: %v", v.Errors)
	}
}

func TestPolicyStateRichModeUsesIndependentIsolationBits(t *testing.T) {
	root := t.TempDir()
	pinRoot := filepath.Join(root, "bpf")
	pin := filepath.Join(pinRoot, "vms", "x")
	putFile(t, filepath.Join(pin, "maps/fluxvm_pspol"), "")
	// ENABLED|RICH_RULES|EGRESS_ISOLATED (no INGRESS_ISOLATED).
	pol := append(u32(1|8|16), make([]byte, 12)...)
	polJ, _ := json.Marshal([]any{map[string]any{"key": bytesJSON(u32(7)), "value": bytesJSON(pol)}})
	r := fakeRunner{responses: map[string][]byte{
		"bpftool -j map dump pinned " + filepath.Join(pin, "maps/fluxvm_pspol"): polJ,
	}}
	egress, ingress := Collector{BPFTool: "bpftool", Runner: r}.policyState(context.Background(), filepath.Join(pin, "maps/fluxvm_pspol"), 7, &VMState{})
	if !egress.Enabled || !egress.DefaultDeny {
		t.Fatalf("egress should be isolated: %+v", egress)
	}
	if !ingress.Enabled || ingress.DefaultDeny {
		t.Fatalf("ingress should not be isolated: %+v", ingress)
	}
}

// The main guest-egress program prefers TCX and reports attached via a
// matching pinned link; the separate Pod-ingress program is never TCX
// (Set 14 attaches it only via plain tc at pref 49153), so `attach_mode:
// tcx` on the VM must not make the ingress check look for a
// links/tcx_pod_ingress link -- it must still consult tc, and here that tc
// query finds no filter at all, so ingress is correctly unattached.
func TestCollectTCXEgressDoesNotGateIngressOnATCXLink(t *testing.T) {
	root := t.TempDir()
	pinRoot := filepath.Join(root, "bpf")
	metaRoot := filepath.Join(root, "meta")
	vm := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pin := filepath.Join(pinRoot, "vms", vm)
	meta := filepath.Join(metaRoot, vm)
	putFile(t, filepath.Join(meta, "iface"), "tap0")
	putFile(t, filepath.Join(meta, "schema_version"), "8")
	putFile(t, filepath.Join(meta, "attach_mode"), "tcx")
	for _, p := range []string{"progs/fluxvm_egress", "progs/fluxvm_pod_ingress", "links/tcx_ingress"} {
		putFile(t, filepath.Join(pin, p), "")
	}
	r := fakeRunner{responses: map[string][]byte{
		"bpftool -j prog show pinned " + filepath.Join(pin, "progs/fluxvm_egress"):      []byte(`{"id":11}`),
		"bpftool -j prog show pinned " + filepath.Join(pin, "progs/fluxvm_pod_ingress"): []byte(`{"id":12}`),
		"bpftool -j link show pinned " + filepath.Join(pin, "links/tcx_ingress"):        []byte(`{"prog_id":11}`),
		"tc -j filter show dev tap0 egress pref 49153":                                  []byte(`[]`),
	}}
	v := Collector{PinRoot: pinRoot, MetaRoot: metaRoot, Runner: r}.Collect(context.Background()).VMs[0]
	if !v.Egress.Attached || v.Ingress.Attached {
		t.Fatalf("unexpected hook state: egress=%v ingress=%v", v.Egress.Attached, v.Ingress.Attached)
	}
}

// The inverse: a real ingress filter present at pref 49153 with the exact
// owned program id must report attached even while the main program is
// TCX-attached.
func TestCollectIngressAttachedViaPlainTCEvenWhenEgressIsTCX(t *testing.T) {
	root := t.TempDir()
	pinRoot := filepath.Join(root, "bpf")
	metaRoot := filepath.Join(root, "meta")
	vm := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	pin := filepath.Join(pinRoot, "vms", vm)
	meta := filepath.Join(metaRoot, vm)
	putFile(t, filepath.Join(meta, "iface"), "tap0")
	putFile(t, filepath.Join(meta, "schema_version"), "8")
	putFile(t, filepath.Join(meta, "attach_mode"), "tcx")
	for _, p := range []string{"progs/fluxvm_egress", "progs/fluxvm_pod_ingress", "links/tcx_ingress"} {
		putFile(t, filepath.Join(pin, p), "")
	}
	r := fakeRunner{responses: map[string][]byte{
		"bpftool -j prog show pinned " + filepath.Join(pin, "progs/fluxvm_egress"):      []byte(`{"id":11}`),
		"bpftool -j prog show pinned " + filepath.Join(pin, "progs/fluxvm_pod_ingress"): []byte(`{"id":12}`),
		"bpftool -j link show pinned " + filepath.Join(pin, "links/tcx_ingress"):        []byte(`{"prog_id":11}`),
		"tc -j filter show dev tap0 egress pref 49153":                                  []byte(`[{"options":{"id":12}}]`),
	}}
	v := Collector{PinRoot: pinRoot, MetaRoot: metaRoot, Runner: r}.Collect(context.Background()).VMs[0]
	if !v.Egress.Attached || !v.Ingress.Attached {
		t.Fatalf("unexpected hook state: egress=%v ingress=%v", v.Egress.Attached, v.Ingress.Attached)
	}
}

func TestValidVMDir(t *testing.T) {
	if !validVMDir("00112233445566778899aabbccddeeff") {
		t.Fatal("valid simple UUID rejected")
	}
	for _, s := range []string{"abc", "00112233445566778899aabbccddeefg", "00112233-4455-6677-8899-aabbccddeeff"} {
		if validVMDir(s) {
			t.Fatalf("accepted %q", s)
		}
	}
}

func BenchmarkBytesFromJSON(b *testing.B) {
	v := make([]any, 64)
	for i := range v {
		v[i] = fmt.Sprintf("0x%02x", i)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = bytesFromJSON(v)
	}
}
