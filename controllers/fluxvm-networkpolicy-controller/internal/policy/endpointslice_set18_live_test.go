// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"context"
	"net/netip"
	"os"
	"testing"

	"github.com/zyvorai/fluxvm/controllers/fluxvm-networkpolicy-controller/internal/kube"
)

// This is skipped in ordinary unit tests. scripts/test-networkpolicy-endpointslice-set18.sh
// supplies a kubectl-proxy URL and a real target Pod from a live cluster.
func TestSet18LiveEndpointSliceServiceVIP(t *testing.T) {
	base := os.Getenv("FLUXVM_SET18_LIVE_API")
	ns := os.Getenv("FLUXVM_SET18_LIVE_NAMESPACE")
	targetName := os.Getenv("FLUXVM_SET18_LIVE_TARGET")
	expect := os.Getenv("FLUXVM_SET18_EXPECT_VIP") == "1"
	if base == "" || ns == "" || targetName == "" {
		t.Skip("Set 18 live EndpointSlice gate not requested")
	}
	client, err := kube.NewClient(kube.Options{BaseURL: base})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pods, err := client.Pods(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nss, err := client.Namespaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := client.Services(ctx)
	if err != nil {
		t.Fatal(err)
	}
	slices, err := client.EndpointSlices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nps, err := client.NetworkPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var target kube.Pod
	for _, p := range pods {
		if p.Metadata.Namespace == ns && p.Metadata.Name == targetName {
			target = p
			break
		}
	}
	if target.Metadata.UID == "" {
		t.Fatalf("target Pod %s/%s not found", ns, targetName)
	}
	result, err := Compile(target, Snapshot{Pods: pods, Namespaces: nss, Services: svcs, EndpointSlices: slices, NetworkPolicies: nps}, Options{IncludeServiceClusterIPs: true})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Managed {
		t.Fatal("expected target to be NetworkPolicy-managed")
	}
	vip := os.Getenv("FLUXVM_SET18_SERVICE_IP")
	addr, err := netip.ParseAddr(vip)
	if err != nil {
		t.Fatalf("invalid Service IP %q: %v", vip, err)
	}
	wantCIDR := addr.String() + "/128"
	if addr.Is4() {
		wantCIDR = addr.String() + "/32"
	}
	found := false
	for _, r := range result.Policy.Rules {
		if r.Direction == "egress" && r.CIDR == wantCIDR && r.Protocol == "TCP" && r.PortStart == 8080 && r.PortEnd == 8080 {
			found = true
		}
	}
	if found != expect {
		t.Fatalf("Service VIP rule found=%v expect=%v vip=%s rules=%+v", found, expect, vip, result.Policy.Rules)
	}
}
