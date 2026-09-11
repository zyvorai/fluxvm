// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/fluxvm"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/kube"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/metrics"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/policy"
)

type Kubernetes interface {
	Pods(context.Context) ([]kube.Pod, error)
	Namespaces(context.Context) ([]kube.Namespace, error)
	Services(context.Context) ([]kube.Service, error)
	NetworkPolicies(context.Context) ([]kube.NetworkPolicy, error)
}

type FluxVM interface {
	ListVMs(context.Context) ([]fluxvm.VMRecord, error)
	GetPodPolicy(context.Context, string) (*fluxvm.PodNetworkPolicy, error)
	SetPodPolicy(context.Context, string, fluxvm.PodNetworkPolicy) error
	ClearPodPolicy(context.Context, string) error
}

type Controller struct {
	Kube    Kubernetes
	FluxVM  FluxVM
	Metrics *metrics.Metrics
	Logger  *slog.Logger

	NodeName                 string
	Interval                 time.Duration
	MaxAddresses             int
	MaxRules                 int
	IncludeServiceClusterIPs bool
	GlobalAudit              bool
}

func (c *Controller) Run(ctx context.Context) error {
	if c.Interval <= 0 {
		c.Interval = 5 * time.Second
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Metrics == nil {
		c.Metrics = metrics.New()
	}
	if c.NodeName == "" {
		return errors.New("node name must be configured")
	}

	// Reconcile immediately on startup, then periodically. List-based
	// reconciliation deliberately favors deterministic state over a complex
	// watch cache for this first controller release; pagination still handles
	// large clusters, and every write is idempotent.
	for {
		if err := c.Reconcile(ctx); err != nil && !errors.Is(err, context.Canceled) {
			c.Logger.Error("NetworkPolicy reconciliation failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.Interval):
		}
	}
}

func (c *Controller) Reconcile(ctx context.Context) error {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Metrics == nil {
		c.Metrics = metrics.New()
	}
	started := time.Now()
	c.Metrics.ReconcileStart()
	var operationErrors []error

	pods, err := c.Kube.Pods(ctx)
	if err != nil {
		c.Metrics.APIError()
		c.Metrics.ReconcileDone(0, 0, 0, 0, 0, time.Since(started), false)
		return fmt.Errorf("list Pods: %w", err)
	}
	namespaces, err := c.Kube.Namespaces(ctx)
	if err != nil {
		c.Metrics.APIError()
		c.Metrics.ReconcileDone(0, 0, 0, 0, 0, time.Since(started), false)
		return fmt.Errorf("list Namespaces: %w", err)
	}
	services, err := c.Kube.Services(ctx)
	if err != nil {
		c.Metrics.APIError()
		c.Metrics.ReconcileDone(0, 0, 0, 0, 0, time.Since(started), false)
		return fmt.Errorf("list Services: %w", err)
	}
	networkPolicies, err := c.Kube.NetworkPolicies(ctx)
	if err != nil {
		c.Metrics.APIError()
		c.Metrics.ReconcileDone(0, 0, 0, 0, 0, time.Since(started), false)
		return fmt.Errorf("list NetworkPolicies: %w", err)
	}
	vms, err := c.FluxVM.ListVMs(ctx)
	if err != nil {
		c.Metrics.APIError()
		c.Metrics.ReconcileDone(0, 0, 0, 0, 0, time.Since(started), false)
		return fmt.Errorf("list FluxVM VMs: %w", err)
	}

	snapshot := policy.Snapshot{Pods: pods, Namespaces: namespaces, Services: services, NetworkPolicies: networkPolicies}
	vmsByPodUID := make(map[string][]fluxvm.VMRecord)
	for _, vm := range vms {
		if vm.Request.PodUID == nil || *vm.Request.PodUID == "" {
			continue
		}
		vmsByPodUID[*vm.Request.PodUID] = append(vmsByPodUID[*vm.Request.PodUID], vm)
	}
	for uid := range vmsByPodUID {
		sort.Slice(vmsByPodUID[uid], func(i, j int) bool { return vmsByPodUID[uid][i].ID < vmsByPodUID[uid][j].ID })
	}

	localPods := 0
	managedPods := 0
	matchedVMs := 0
	unmatched := 0
	unsupportedCount := uint64(0)

	for _, pod := range pods {
		if pod.Spec.NodeName != c.NodeName || terminalPod(pod) || pod.Metadata.UID == "" {
			continue
		}
		localPods++
		podVMs := vmsByPodUID[pod.Metadata.UID]
		if len(podVMs) == 0 {
			unmatched++
			continue
		}
		matchedVMs += len(podVMs)

		compiled, compileErr := policy.Compile(pod, snapshot, policy.Options{
			MaxAddresses:             c.MaxAddresses,
			MaxRules:                 c.MaxRules,
			IncludeServiceClusterIPs: c.IncludeServiceClusterIPs,
			GlobalAudit:              c.GlobalAudit,
		})
		unsupportedCount += uint64(len(compiled.Unsupported))
		for _, reason := range compiled.Unsupported {
			c.Logger.Warn("NetworkPolicy rule represented more strictly", "pod", pod.Metadata.Namespace+"/"+pod.Metadata.Name, "reason", reason)
		}
		if compileErr != nil {
			// Compile returns a safe deny-all policy whenever it can identify
			// the target as NetworkPolicy-isolated but cannot represent the rules.
			// Apply that policy rather than leaving a potentially stale wider
			// policy in place.
			c.Logger.Error("NetworkPolicy compile error; applying safe deny", "pod", pod.Metadata.Namespace+"/"+pod.Metadata.Name, "error", compileErr)
			operationErrors = append(operationErrors, fmt.Errorf("compile %s/%s: %w", pod.Metadata.Namespace, pod.Metadata.Name, compileErr))
		}

		if !compiled.Managed {
			for _, vm := range podVMs {
				if clearErr := c.clearIfPresent(ctx, pod, vm); clearErr != nil {
					operationErrors = append(operationErrors, clearErr)
				}
			}
			continue
		}
		managedPods++
		for _, vm := range podVMs {
			if applyErr := c.applyIfChanged(ctx, pod, vm, compiled); applyErr != nil {
				operationErrors = append(operationErrors, applyErr)
			}
		}
	}

	success := len(operationErrors) == 0
	c.Metrics.ReconcileDone(localPods, managedPods, matchedVMs, unmatched, unsupportedCount, time.Since(started), success)
	if success {
		c.Logger.Info("NetworkPolicy reconciliation complete",
			"node", c.NodeName,
			"local_pods", localPods,
			"managed_pods", managedPods,
			"matched_vms", matchedVMs,
			"unmatched_pods", unmatched,
			"unsupported_rules", unsupportedCount,
			"duration_ms", time.Since(started).Milliseconds())
		return nil
	}
	return errors.Join(operationErrors...)
}

func (c *Controller) applyIfChanged(ctx context.Context, pod kube.Pod, vm fluxvm.VMRecord, compiled policy.Result) error {
	current, err := c.FluxVM.GetPodPolicy(ctx, vm.ID)
	if err != nil {
		c.Metrics.APIError()
		return fmt.Errorf("get Pod policy vm=%s pod=%s/%s: %w", vm.ID, pod.Metadata.Namespace, pod.Metadata.Name, err)
	}
	desired := compiled.Policy
	desired.Canonicalize()
	if fluxvm.EqualPolicy(current, &desired) {
		return nil
	}
	if err := c.FluxVM.SetPodPolicy(ctx, vm.ID, desired); err != nil {
		c.Metrics.APIError()
		return fmt.Errorf("set Pod policy vm=%s pod=%s/%s: %w", vm.ID, pod.Metadata.Namespace, pod.Metadata.Name, err)
	}
	c.Metrics.PolicyApplied()
	c.Logger.Info("applied FluxVM Pod network policy",
		"pod", pod.Metadata.Namespace+"/"+pod.Metadata.Name,
		"pod_uid", pod.Metadata.UID,
		"vm_id", vm.ID,
		"default_deny", desired.DefaultDeny,
		"audit", desired.AuditMode,
		"schema_version", desired.SchemaVersion,
		"ingress_isolated", desired.IngressIsolated,
		"egress_isolated", desired.EgressIsolated,
		"tuple_rules", len(desired.Rules),
		"selected_policies", strings.Join(compiled.SelectedPolicies, ","))
	return nil
}

func (c *Controller) clearIfPresent(ctx context.Context, pod kube.Pod, vm fluxvm.VMRecord) error {
	current, err := c.FluxVM.GetPodPolicy(ctx, vm.ID)
	if err != nil {
		c.Metrics.APIError()
		return fmt.Errorf("get Pod policy before clear vm=%s pod=%s/%s: %w", vm.ID, pod.Metadata.Namespace, pod.Metadata.Name, err)
	}
	if current == nil {
		return nil
	}
	if err := c.FluxVM.ClearPodPolicy(ctx, vm.ID); err != nil {
		c.Metrics.APIError()
		return fmt.Errorf("clear Pod policy vm=%s pod=%s/%s: %w", vm.ID, pod.Metadata.Namespace, pod.Metadata.Name, err)
	}
	c.Metrics.PolicyCleared()
	c.Logger.Info("cleared FluxVM Pod network policy", "pod", pod.Metadata.Namespace+"/"+pod.Metadata.Name, "pod_uid", pod.Metadata.UID, "vm_id", vm.ID)
	return nil
}

func terminalPod(pod kube.Pod) bool {
	return pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed"
}
