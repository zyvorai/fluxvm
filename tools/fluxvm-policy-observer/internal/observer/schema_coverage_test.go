// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package observer

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCoverageSchemaV10Compatible(t *testing.T) {
	root := t.TempDir()
	pinRoot := filepath.Join(root, "bpf")
	metaRoot := filepath.Join(root, "meta")
	vm := "aabbccddeeff00112233445566778899"
	putFile(t, filepath.Join(metaRoot, vm, "pod_id"), "7\n")
	putFile(t, filepath.Join(metaRoot, vm, "schema_version"), "10\n")
	putFile(t, filepath.Join(metaRoot, vm, "iface"), "tap7\n")
	putFile(t, filepath.Join(metaRoot, vm, "attach_mode"), "tc\n")
	for _, p := range []string{"progs/fluxvm_egress", "progs/fluxvm_pod_ingress", "maps/fluxvm_ppstat", "maps/fluxvm_pspol", "maps/fluxvm_prules"} {
		putFile(t, filepath.Join(pinRoot, "vms", vm, p), "")
	}
	r := fakeRunner{responses: map[string][]byte{}}
	snap := Collector{PinRoot: pinRoot, MetaRoot: metaRoot, Runner: r}.Collect(context.Background())
	if len(snap.VMs) != 1 {
		t.Fatalf("got %d VMs", len(snap.VMs))
	}
	st := snap.VMs[0]
	if st.SchemaVersion != 10 || !st.SchemaCompatible {
		t.Fatalf("schema10: version=%d compatible=%v (CurrentSchema=%d)", st.SchemaVersion, st.SchemaCompatible, CurrentSchema)
	}
}

func TestCoverageSchemaV9IncompatibleWithCurrent(t *testing.T) {
	root := t.TempDir()
	pinRoot := filepath.Join(root, "bpf")
	metaRoot := filepath.Join(root, "meta")
	vm := "00112233445566778899aabbccddeeff"
	putFile(t, filepath.Join(metaRoot, vm, "pod_id"), "7\n")
	putFile(t, filepath.Join(metaRoot, vm, "schema_version"), "9\n")
	putFile(t, filepath.Join(metaRoot, vm, "iface"), "tap7\n")
	putFile(t, filepath.Join(metaRoot, vm, "attach_mode"), "tc\n")
	for _, p := range []string{"progs/fluxvm_egress", "maps/fluxvm_ppstat"} {
		putFile(t, filepath.Join(pinRoot, "vms", vm, p), "")
	}
	r := fakeRunner{responses: map[string][]byte{}}
	snap := Collector{PinRoot: pinRoot, MetaRoot: metaRoot, Runner: r}.Collect(context.Background())
	if len(snap.VMs) != 1 {
		t.Fatalf("got %d VMs", len(snap.VMs))
	}
	st := snap.VMs[0]
	if st.SchemaVersion != 9 || st.SchemaCompatible {
		t.Fatalf("schema9 should be incompatible with CurrentSchema=%d: version=%d compatible=%v",
			CurrentSchema, st.SchemaVersion, st.SchemaCompatible)
	}
}

func TestCoveragePreferPrhitWhenPresent(t *testing.T) {
	root := t.TempDir()
	hitPath := filepath.Join(root, "maps", "fluxvm_prhit")
	rulePath := filepath.Join(root, "maps", "fluxvm_prules")
	c := Collector{PinRoot: root, Runner: fakeRunner{responses: map[string][]byte{}}}
	st := &VMState{}
	_, _, _, ok := c.ruleTelemetry(context.Background(), hitPath, rulePath, 1, st)
	if ok {
		t.Fatal("missing prhit must report ok=false so caller falls back to ppstat")
	}
	putFile(t, hitPath, "")
	// Present path but bpftool dump fails → fall back (ok=false).
	c2 := Collector{BPFTool: "/nonexistent-bpftool-for-coverage", Runner: ExecRunner{}}
	st2 := &VMState{}
	_, _, _, ok = c2.ruleTelemetry(context.Background(), hitPath, rulePath, 1, st2)
	if ok {
		t.Fatal("unreadable prhit must fall back rather than fabricate zeros")
	}
}
