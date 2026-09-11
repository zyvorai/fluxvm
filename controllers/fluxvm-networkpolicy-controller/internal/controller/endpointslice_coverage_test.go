// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/fluxvm"
	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/metrics"
)

func TestCoverageEndpointSliceListErrorFailClosedBeforeWrites(t *testing.T) {
	k := &set18KubeWithSlices{
		fakeKube: &fakeKube{},
		err:      errors.New("endpointslice apiserver unavailable"),
	}
	ff := &fakeFlux{policies: map[string]*fluxvm.PodNetworkPolicy{}}
	c := &Controller{
		Kube:                     k,
		FluxVM:                   ff,
		Metrics:                  metrics.New(),
		NodeName:                 "node-a",
		IncludeServiceClusterIPs: true,
	}
	err := c.Reconcile(context.Background())
	if err == nil || !strings.Contains(err.Error(), "EndpointSlices") {
		t.Fatalf("expected EndpointSlice list error, got %v", err)
	}
	if len(ff.set) != 0 || len(ff.cleared) != 0 {
		t.Fatalf("FluxVM writes must not happen after EndpointSlice list failure: set=%v cleared=%v", ff.set, ff.cleared)
	}
}

func TestCoverageVIPModeOffDoesNotRequireEndpointSlices(t *testing.T) {
	ff := &fakeFlux{policies: map[string]*fluxvm.PodNetworkPolicy{}}
	c := &Controller{
		Kube:                     &fakeKube{},
		FluxVM:                   ff,
		Metrics:                  metrics.New(),
		NodeName:                 "node-a",
		IncludeServiceClusterIPs: false,
	}
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("VIP mode off should reconcile without EndpointSlice capability: %v", err)
	}
}
