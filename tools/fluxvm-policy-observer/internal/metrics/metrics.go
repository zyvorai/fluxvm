// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package metrics

import (
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/fluxvm/tools/fluxvm-policy-observer/internal/observer"
)

type Store struct {
	mu           sync.RWMutex
	snapshot     observer.Snapshot
	scrapeErrors uint64
	scrapes      uint64
}

func New() *Store { return &Store{} }
func (s *Store) Update(snapshot observer.Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scrapes++
	s.scrapeErrors += uint64(len(snapshot.Errors))
	for _, vm := range snapshot.VMs {
		s.scrapeErrors += uint64(len(vm.Errors))
	}
	s.snapshot = snapshot
}
func (s *Store) Ready(maxAge time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.snapshot.CollectedAt.IsZero() && time.Since(s.snapshot.CollectedAt) <= maxAge
}

func (s *Store) WritePrometheus(w io.Writer) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := promWriter{w: w, seen: map[string]bool{}}
	p.counter("fluxvm_sentinel_observer_scrapes_total", "Completed policy-observer collection cycles.", "", s.scrapes)
	p.counter("fluxvm_sentinel_observer_scrape_errors_total", "Collection errors across bpftool/tc/filesystem sources.", "", s.scrapeErrors)
	p.gauge("fluxvm_sentinel_observer_vms", "FluxVM VM pin directories observed on this node.", "", float64(len(s.snapshot.VMs)))
	ts := float64(0)
	if !s.snapshot.CollectedAt.IsZero() {
		ts = float64(s.snapshot.CollectedAt.Unix())
	}
	p.gauge("fluxvm_sentinel_observer_last_scrape_unixtime", "Unix timestamp of the most recent collection cycle.", "", ts)

	vms := append([]observer.VMState(nil), s.snapshot.VMs...)
	sort.Slice(vms, func(i, j int) bool { return vms[i].VMID < vms[j].VMID })
	for _, vm := range vms {
		pod := strconv.FormatUint(uint64(vm.PodID), 10)
		vmLabel := escape(vm.VMID)
		base := `{pod_id="` + pod + `",vm="` + vmLabel + `"}`
		p.gauge("fluxvm_sentinel_dataplane_schema_version", "Recorded FluxVM eBPF dataplane schema version.", base, float64(vm.SchemaVersion))
		p.gauge("fluxvm_sentinel_dataplane_schema_compatible", "1 when the observer recognizes this dataplane schema.", base, boolf(vm.SchemaCompatible))
		p.gauge("fluxvm_sentinel_observer_vm_scrape_ok", "1 when all sources for this VM were collected without error.", base, boolf(len(vm.Errors) == 0))
		p.gauge("fluxvm_sentinel_policy_directional_counters", "1 when Set 17 rule telemetry provides true per-direction Pod-policy counters; 0 means Set 15 shared-counter fallback.", base, boolf(vm.DirectionalStats))
		dirs := []struct {
			name   string
			hook   observer.HookState
			policy observer.PolicyState
			stats  observer.DirectionStats
		}{{"egress", vm.Egress, vm.EgressPolicy, vm.EgressStats}, {"ingress", vm.Ingress, vm.IngressPolicy, vm.IngressStats}}
		for _, d := range dirs {
			mode := escape(emptyAs(d.hook.Mode, "unknown"))
			l := `{direction="` + d.name + `",mode="` + mode + `",pod_id="` + pod + `",vm="` + vmLabel + `"}`
			p.gauge("fluxvm_sentinel_policy_hook_required", "1 when the directional FluxVM policy hook exists in the loaded object.", l, boolf(d.hook.Required))
			p.gauge("fluxvm_sentinel_policy_hook_attached", "1 when the directional program is attached to the expected TC/TCX hook.", l, boolf(d.hook.Attached))
			p.gauge("fluxvm_sentinel_policy_enabled", "1 when a Pod policy entry is enabled for this direction.", l, boolf(d.policy.Enabled))
			p.gauge("fluxvm_sentinel_policy_default_deny", "1 when unmatched traffic is denied for this direction.", l, boolf(d.policy.DefaultDeny))
			p.gauge("fluxvm_sentinel_policy_audit_mode", "1 when denials are audit/log-and-allow for this direction.", l, boolf(d.policy.Audit))
			for _, v := range []struct {
				name  string
				value uint64
			}{{"allow", d.stats.Allowed}, {"drop", d.stats.Dropped}, {"audit", d.stats.Audited}} {
				vl := `{direction="` + d.name + `",pod_id="` + pod + `",verdict="` + v.name + `",vm="` + vmLabel + `"}`
				p.counter("fluxvm_sentinel_policy_packets_total", "Packets evaluated by the Pod policy dataplane, partitioned by direction and verdict.", vl, v.value)
			}
		}
		for _, hit := range vm.RuleHits {
			ruleIndex := strconv.FormatUint(uint64(hit.RuleIndex), 10)
			if !hit.Matched {
				ruleIndex = "miss"
			}
			l := `{direction="` + escape(hit.Direction) + `",pod_id="` + pod + `",rule_index="` + escape(ruleIndex) + `",verdict="` + escape(hit.Verdict) + `",vm="` + vmLabel + `"}`
			p.counter("fluxvm_sentinel_policy_rule_packets_total", "Packets attributed to an exact rich rule or the default-deny/audit miss sentinel.", l, hit.Packets)
			if hit.Matched {
				info := `{cidr="` + escape(hit.CIDR) + `",direction="` + escape(hit.Direction) + `",family="` + escape(hit.Family) + `",pod_id="` + pod + `",port_end="` + strconv.FormatUint(uint64(hit.PortEnd), 10) + `",port_start="` + strconv.FormatUint(uint64(hit.PortStart), 10) + `",protocol="` + escape(hit.Protocol) + `",rule_index="` + escape(ruleIndex) + `",vm="` + vmLabel + `"}`
				p.gauge("fluxvm_sentinel_policy_rule_info", "Current rich-rule identity for a Set 17 rule-hit slot.", info, 1)
			}
		}
		keys := make([]string, 0, len(vm.RuleEntries))
		for k := range vm.RuleEntries {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, kind := range keys {
			parts := strings.SplitN(kind, "_", 2)
			direction, ruleKind := "unknown", kind
			if len(parts) == 2 {
				direction, ruleKind = parts[0], parts[1]
			}
			l := `{direction="` + escape(direction) + `",kind="` + escape(ruleKind) + `",pod_id="` + pod + `",vm="` + vmLabel + `"}`
			p.gauge("fluxvm_sentinel_policy_rule_entries", "Number of compiled policy-map entries by direction and representation kind.", l, float64(vm.RuleEntries[kind]))
		}
	}
}

type promWriter struct {
	w    io.Writer
	seen map[string]bool
}

func (p *promWriter) header(n, h, typ string) {
	if p.seen[n] {
		return
	}
	p.seen[n] = true
	_, _ = io.WriteString(p.w, "# HELP "+n+" "+h+"\n# TYPE "+n+" "+typ+"\n")
}
func (p *promWriter) counter(n, h, l string, v uint64) {
	p.header(n, h, "counter")
	_, _ = io.WriteString(p.w, n+l+" "+strconv.FormatUint(v, 10)+"\n")
}
func (p *promWriter) gauge(n, h, l string, v float64) {
	p.header(n, h, "gauge")
	_, _ = io.WriteString(p.w, n+l+" "+strconv.FormatFloat(v, 'g', -1, 64)+"\n")
}
func emptyAs(v, f string) string {
	if v == "" {
		return f
	}
	return v
}
func boolf(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
func escape(s string) string {
	return strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"").Replace(s)
}
