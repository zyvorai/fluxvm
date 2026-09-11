// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package metrics

import (
	"bytes"
	"fmt"
	"github.com/zyvorai/fluxvm/tools/fluxvm-policy-observer/internal/observer"
	"strings"
	"testing"
	"time"
)

func TestPrometheusDirectionalMetricsHaveSingleMetadataBlock(t *testing.T) {
	s := New()
	s.Update(observer.Snapshot{CollectedAt: time.Now(), VMs: []observer.VMState{{VMID: "abc", PodID: 7, SchemaVersion: 8, SchemaCompatible: true, Egress: observer.HookState{Required: true, Attached: true, Mode: "tcx"}, Ingress: observer.HookState{Required: true, Attached: false, Mode: "tcx"}, EgressStats: observer.DirectionStats{Allowed: 10, Dropped: 2}, IngressStats: observer.DirectionStats{Audited: 3}, RuleEntries: map[string]int{"egress_cidr_v4": 2, "ingress_exact_port_v4": 1}}}})
	var b bytes.Buffer
	s.WritePrometheus(&b)
	out := b.String()
	if strings.Count(out, "# HELP fluxvm_sentinel_policy_packets_total") != 1 {
		t.Fatalf("duplicate HELP block:\n%s", out)
	}
	for _, want := range []string{`direction="egress"`, `direction="ingress"`, `verdict="drop"`, `kind="cidr_v4"`, `fluxvm_sentinel_policy_hook_attached`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
func TestReady(t *testing.T) {
	s := New()
	if s.Ready(time.Minute) {
		t.Fatal("empty store ready")
	}
	s.Update(observer.Snapshot{CollectedAt: time.Now()})
	if !s.Ready(time.Minute) {
		t.Fatal("fresh store not ready")
	}
}

func BenchmarkPrometheusSnapshot(b *testing.B) {
	s := New()
	vms := make([]observer.VMState, 64)
	for i := range vms {
		vms[i] = observer.VMState{VMID: "00112233445566778899aabbccdd" + fmt.Sprintf("%04x", i), PodID: uint32(i + 1), SchemaVersion: 8, SchemaCompatible: true, Egress: observer.HookState{Required: true, Attached: true, Mode: "tcx"}, Ingress: observer.HookState{Required: true, Attached: true, Mode: "tcx"}, EgressStats: observer.DirectionStats{Allowed: 1000, Dropped: 3}, IngressStats: observer.DirectionStats{Allowed: 900, Dropped: 2}, RuleEntries: map[string]int{"egress_cidr_v4": 10, "ingress_exact_port_v4": 5}}
	}
	s.Update(observer.Snapshot{CollectedAt: time.Now(), VMs: vms})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		s.WritePrometheus(&out)
	}
}
