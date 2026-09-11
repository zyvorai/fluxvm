// FLUXVM_SECURE_CONTAINERS_SET17
// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/fluxvm/tools/fluxvm-policy-observer/internal/observer"
)

func TestSet17PrometheusEmitsRuleIdentityAndMiss(t *testing.T) {
	s := New()
	s.Update(observer.Snapshot{CollectedAt: time.Now(), VMs: []observer.VMState{{
		VMID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PodID: 42, DirectionalStats: true,
		RuleEntries: map[string]int{},
		RuleHits: []observer.RuleHit{
			{RuleIndex: 2, Matched: true, Direction: "egress", Verdict: "allow", Packets: 9, Family: "ipv4", Protocol: "tcp", CIDR: "10.0.0.9/32", PortStart: 443, PortEnd: 443},
			{RuleIndex: ^uint32(0), Matched: false, Direction: "ingress", Verdict: "drop", Packets: 4},
		},
	}}})
	var b bytes.Buffer
	s.WritePrometheus(&b)
	out := b.String()
	for _, want := range []string{
		"fluxvm_sentinel_policy_directional_counters",
		"fluxvm_sentinel_policy_rule_packets_total",
		`rule_index="2"`,
		`rule_index="miss"`,
		`cidr="10.0.0.9/32"`,
		"fluxvm_sentinel_policy_rule_info",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in metrics:\n%s", want, out)
		}
	}
}
