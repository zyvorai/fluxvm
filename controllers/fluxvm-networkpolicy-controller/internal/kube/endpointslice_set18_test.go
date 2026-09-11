// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSet18EndpointSlicesClientUsesDiscoveryV1AndDecodesConditions(t *testing.T) {
	ready := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/discovery.k8s.io/v1/endpointslices" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{},
			"items": []EndpointSlice{{
				Metadata:    ObjectMeta{Name: "svc-a", Namespace: "ns", Labels: map[string]string{"kubernetes.io/service-name": "svc"}},
				AddressType: "IPv4",
				Endpoints:   []Endpoint{{Addresses: []string{"10.0.0.8"}, Conditions: EndpointConditions{Ready: &ready}, TargetRef: &ObjectReference{Kind: "Pod", UID: "u1"}}},
			}},
		})
	}))
	defer server.Close()

	client, err := NewClient(Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	slices, err := client.EndpointSlices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(slices) != 1 || slices[0].AddressType != "IPv4" || len(slices[0].Endpoints) != 1 || slices[0].Endpoints[0].Conditions.Ready == nil || !*slices[0].Endpoints[0].Conditions.Ready {
		t.Fatalf("unexpected EndpointSlice decode: %#v", slices)
	}
}
