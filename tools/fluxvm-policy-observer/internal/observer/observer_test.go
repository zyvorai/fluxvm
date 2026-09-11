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
	for _, p := range []string{"progs/fluxvm_egress", "progs/fluxvm_pod_ingress", "maps/fluxvm_ppstat", "maps/fluxvm_ppstat_in", "maps/fluxvm_pspol", "maps/fluxvm_pspol_in", "maps/fluxvm_pid4", "maps/fluxvm_pid4_cidr_in"} {
		putFile(t, filepath.Join(pin, p), "")
	}
	statE, _ := json.Marshal([]any{map[string]any{"key": bytesJSON(u32(42)), "values": []any{map[string]any{"cpu": 0, "value": bytesJSON(statBytes(10, 2, 1))}, map[string]any{"cpu": 1, "value": bytesJSON(statBytes(3, 1, 0))}}}})
	statI, _ := json.Marshal([]any{map[string]any{"key": bytesJSON(u32(42)), "value": bytesJSON(statBytes(7, 4, 2))}})
	pol := append(u32(1|2), make([]byte, 12)...)
	polI := append(u32(1|4), make([]byte, 12)...)
	polJ, _ := json.Marshal([]any{map[string]any{"key": bytesJSON(u32(42)), "value": bytesJSON(pol)}})
	polIJ, _ := json.Marshal([]any{map[string]any{"key": bytesJSON(u32(42)), "value": bytesJSON(polI)}})
	one, _ := json.Marshal([]any{map[string]any{"key": bytesJSON(u32(42)), "value": []int{1}}})
	cidrKey := append(u32(64), u32(42)...)
	cidrKey = append(cidrKey, 10, 0, 0, 0)
	cidrOne, _ := json.Marshal([]any{map[string]any{"key": bytesJSON(cidrKey), "value": []int{1}}})
	r := fakeRunner{responses: map[string][]byte{
		"bpftool -j prog show pinned " + filepath.Join(pin, "progs/fluxvm_egress"):      []byte(`[ {"id":101} ]`),
		"bpftool -j prog show pinned " + filepath.Join(pin, "progs/fluxvm_pod_ingress"): []byte(`[ {"id":202} ]`),
		"tc -j filter show dev tap42 ingress pref 49152":                                []byte(`[{"options":{"id":101}}]`),
		"tc -j filter show dev tap42 egress pref 49152":                                 []byte(`[{"options":{"id":202}}]`),
		"bpftool -j map dump pinned " + filepath.Join(pin, "maps/fluxvm_ppstat"):        statE,
		"bpftool -j map dump pinned " + filepath.Join(pin, "maps/fluxvm_ppstat_in"):     statI,
		"bpftool -j map dump pinned " + filepath.Join(pin, "maps/fluxvm_pspol"):         polJ,
		"bpftool -j map dump pinned " + filepath.Join(pin, "maps/fluxvm_pspol_in"):      polIJ,
		"bpftool -j map dump pinned " + filepath.Join(pin, "maps/fluxvm_pid4"):          one,
		"bpftool -j map dump pinned " + filepath.Join(pin, "maps/fluxvm_pid4_cidr_in"):  cidrOne,
	}}
	snap := Collector{PinRoot: pinRoot, MetaRoot: metaRoot, Runner: r}.Collect(context.Background())
	if len(snap.VMs) != 1 {
		t.Fatalf("got %d VMs", len(snap.VMs))
	}
	v := snap.VMs[0]
	if !v.Egress.Attached || !v.Ingress.Attached {
		t.Fatalf("hooks not healthy: %+v %+v", v.Egress, v.Ingress)
	}
	if v.EgressStats != (DirectionStats{Allowed: 13, Dropped: 3, Audited: 1}) {
		t.Fatalf("egress stats: %+v", v.EgressStats)
	}
	if v.IngressStats != (DirectionStats{Allowed: 7, Dropped: 4, Audited: 2}) {
		t.Fatalf("ingress stats: %+v", v.IngressStats)
	}
	if !v.EgressPolicy.Enabled || !v.EgressPolicy.DefaultDeny || v.EgressPolicy.Audit {
		t.Fatalf("egress policy: %+v", v.EgressPolicy)
	}
	if !v.IngressPolicy.Enabled || v.IngressPolicy.DefaultDeny || !v.IngressPolicy.Audit {
		t.Fatalf("ingress policy: %+v", v.IngressPolicy)
	}
	if v.RuleEntries["egress_address_v4"] != 1 || v.RuleEntries["ingress_cidr_v4"] != 1 {
		t.Fatalf("rule counts: %+v", v.RuleEntries)
	}
	if len(v.Errors) != 0 {
		t.Fatalf("errors: %v", v.Errors)
	}
}

func TestCollectTCXRequiresMatchingDirectionalLinks(t *testing.T) {
	root := t.TempDir()
	pinRoot := filepath.Join(root, "bpf")
	metaRoot := filepath.Join(root, "meta")
	vm := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pin := filepath.Join(pinRoot, "vms", vm)
	meta := filepath.Join(metaRoot, vm)
	putFile(t, filepath.Join(meta, "iface"), "tap0")
	putFile(t, filepath.Join(meta, "schema_version"), "8")
	putFile(t, filepath.Join(meta, "attach_mode"), "tcx")
	for _, p := range []string{"progs/fluxvm_egress", "progs/fluxvm_pod_ingress", "links/tcx_ingress", "links/tcx_pod_ingress"} {
		putFile(t, filepath.Join(pin, p), "")
	}
	r := fakeRunner{responses: map[string][]byte{
		"bpftool -j prog show pinned " + filepath.Join(pin, "progs/fluxvm_egress"):      []byte(`{"id":11}`),
		"bpftool -j prog show pinned " + filepath.Join(pin, "progs/fluxvm_pod_ingress"): []byte(`{"id":12}`),
		"bpftool -j link show pinned " + filepath.Join(pin, "links/tcx_ingress"):        []byte(`{"prog_id":11}`),
		"bpftool -j link show pinned " + filepath.Join(pin, "links/tcx_pod_ingress"):    []byte(`{"prog_id":99}`),
	}}
	v := Collector{PinRoot: pinRoot, MetaRoot: metaRoot, Runner: r}.Collect(context.Background()).VMs[0]
	if !v.Egress.Attached || v.Ingress.Attached {
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
