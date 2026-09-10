// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"fmt"
	"io"
	"sync"
	"time"
)

type Metrics struct {
	mu sync.RWMutex

	reconciles       uint64
	reconcileErrors  uint64
	policiesApplied  uint64
	policiesCleared  uint64
	unsupportedRules uint64
	apiErrors        uint64

	localPods   int
	managedPods int
	matchedVMs  int
	unmatched   int

	lastSuccess time.Time
	lastRun     time.Time
	lastSeconds float64
}

func New() *Metrics { return &Metrics{} }

func (m *Metrics) ReconcileStart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconciles++
	m.lastRun = time.Now()
}

func (m *Metrics) ReconcileDone(localPods, managedPods, matchedVMs, unmatched int, unsupported uint64, duration time.Duration, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.localPods = localPods
	m.managedPods = managedPods
	m.matchedVMs = matchedVMs
	m.unmatched = unmatched
	m.unsupportedRules += unsupported
	m.lastSeconds = duration.Seconds()
	if success {
		m.lastSuccess = time.Now()
	} else {
		m.reconcileErrors++
	}
}

func (m *Metrics) PolicyApplied() {
	m.mu.Lock()
	m.policiesApplied++
	m.mu.Unlock()
}
func (m *Metrics) PolicyCleared() {
	m.mu.Lock()
	m.policiesCleared++
	m.mu.Unlock()
}
func (m *Metrics) APIError() {
	m.mu.Lock()
	m.apiErrors++
	m.mu.Unlock()
}

func (m *Metrics) Ready(maxAge time.Duration) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return !m.lastSuccess.IsZero() && time.Since(m.lastSuccess) <= maxAge
}

func (m *Metrics) WritePrometheus(w io.Writer) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	writeCounter(w, "fluxvm_networkpolicy_reconciles_total", "Completed reconciliation attempts.", m.reconciles)
	writeCounter(w, "fluxvm_networkpolicy_reconcile_errors_total", "Reconciliation attempts with one or more errors.", m.reconcileErrors)
	writeCounter(w, "fluxvm_networkpolicy_policies_applied_total", "FluxVM Pod policies created or changed.", m.policiesApplied)
	writeCounter(w, "fluxvm_networkpolicy_policies_cleared_total", "FluxVM Pod policies cleared because no egress policy applied.", m.policiesCleared)
	writeCounter(w, "fluxvm_networkpolicy_unsupported_rules_total", "NetworkPolicy rules represented more strictly because FluxVM address policy cannot express them exactly.", m.unsupportedRules)
	writeCounter(w, "fluxvm_networkpolicy_api_errors_total", "Kubernetes or FluxVM API operation errors.", m.apiErrors)
	writeGauge(w, "fluxvm_networkpolicy_local_pods", "Pods observed on this node.", float64(m.localPods))
	writeGauge(w, "fluxvm_networkpolicy_managed_pods", "Local Pods selected by an egress NetworkPolicy.", float64(m.managedPods))
	writeGauge(w, "fluxvm_networkpolicy_matched_vms", "FluxVM VMs matched to local Pods by Pod UID.", float64(m.matchedVMs))
	writeGauge(w, "fluxvm_networkpolicy_unmatched_pods", "Local Pods without a matching FluxVM VM.", float64(m.unmatched))
	writeGauge(w, "fluxvm_networkpolicy_last_reconcile_duration_seconds", "Duration of the latest reconciliation.", m.lastSeconds)
	lastSuccess := float64(0)
	if !m.lastSuccess.IsZero() {
		lastSuccess = float64(m.lastSuccess.Unix())
	}
	writeGauge(w, "fluxvm_networkpolicy_last_success_unixtime", "Unix timestamp of the latest successful reconciliation.", lastSuccess)
	lastRun := float64(0)
	if !m.lastRun.IsZero() {
		lastRun = float64(m.lastRun.Unix())
	}
	writeGauge(w, "fluxvm_networkpolicy_last_run_unixtime", "Unix timestamp of the latest reconciliation attempt.", lastRun)
}

func writeCounter(w io.Writer, name, help string, value uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, value)
}
func writeGauge(w io.Writer, name, help string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, value)
}
