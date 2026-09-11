// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/fluxvm"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/kube"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/metrics"
)

type set18KubeWithSlices struct {
	*fakeKube
	slices []kube.EndpointSlice
	err    error
}

func (f *set18KubeWithSlices) EndpointSlices(context.Context) ([]kube.EndpointSlice, error) {
	return f.slices, f.err
}

func TestSet18ServiceVIPModeRequiresEndpointSliceCapability(t *testing.T) {
	ff := &fakeFlux{policies: map[string]*fluxvm.PodNetworkPolicy{}}
	c := &Controller{
		Kube:                     &fakeKube{},
		FluxVM:                   ff,
		Metrics:                  metrics.New(),
		NodeName:                 "node-a",
		IncludeServiceClusterIPs: true,
	}
	err := c.Reconcile(context.Background())
	if err == nil || !strings.Contains(err.Error(), "EndpointSlice") {
		t.Fatalf("expected fail-closed EndpointSlice capability error, got %v", err)
	}
	if len(ff.set) != 0 || len(ff.cleared) != 0 {
		t.Fatal("controller wrote FluxVM policy after EndpointSlice capability failure")
	}
}

func TestSet18ServiceVIPModeUsesEndpointSliceLister(t *testing.T) {
	k := &set18KubeWithSlices{fakeKube: &fakeKube{}}
	ff := &fakeFlux{policies: map[string]*fluxvm.PodNetworkPolicy{}}
	c := &Controller{
		Kube:                     k,
		FluxVM:                   ff,
		Metrics:                  metrics.New(),
		NodeName:                 "node-a",
		IncludeServiceClusterIPs: true,
	}
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("EndpointSlice-capable Kubernetes client should reconcile: %v", err)
	}
}
