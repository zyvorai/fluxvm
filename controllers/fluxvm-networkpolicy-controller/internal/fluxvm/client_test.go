// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package fluxvm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestClientMatchesCurrentFluxVMAPIShape(t *testing.T) {
	var posted PodNetworkPolicy
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/vms":
			_, _ = w.Write([]byte(`{"items":[{"id":"vm-1","name":"pod","status":"running","request":{"pod_uid":"uid-1"}}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/vms/vm-1/network/pod-policy":
			_, _ = w.Write([]byte(`null`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/vms/vm-1/network/pod-policy":
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/vms/vm-1/network/pod-policy":
			deleted = true
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	vms, err := client.ListVMs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(vms) != 1 || vms[0].Request.PodUID == nil || *vms[0].Request.PodUID != "uid-1" {
		t.Fatalf("vms=%+v", vms)
	}
	current, err := client.GetPodPolicy(context.Background(), "vm-1")
	if err != nil || current != nil {
		t.Fatalf("current=%+v err=%v", current, err)
	}
	desired := PodNetworkPolicy{DefaultDeny: true, AllowAddresses: []string{"fd00::1", "10.0.0.2", "10.0.0.2"}}
	if err := client.SetPodPolicy(context.Background(), "vm-1", desired); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(posted.AllowAddresses, []string{"10.0.0.2", "fd00::1"}) {
		t.Fatalf("posted=%+v", posted)
	}
	if err := client.ClearPodPolicy(context.Background(), "vm-1"); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("DELETE was not sent")
	}
}

func TestEqualPolicyCanonicalizesAddressOrder(t *testing.T) {
	a := &PodNetworkPolicy{DefaultDeny: true, AllowAddresses: []string{"fd00::1", "10.0.0.2"}}
	b := &PodNetworkPolicy{DefaultDeny: true, AllowAddresses: []string{"10.0.0.2", "fd00::1", "10.0.0.2"}}
	if !EqualPolicy(a, b) {
		t.Fatal("expected policies to be equal")
	}
}

func TestEqualPolicyCanonicalizesPortRuleOrderAndDupes(t *testing.T) {
	rule1 := PodPeerPortRule{Address: "10.0.0.20", Protocol: ProtocolTCP, Port: 5432}
	rule2 := PodPeerPortRule{Address: "10.0.0.20", Protocol: ProtocolUDP, Port: 53}
	a := &PodNetworkPolicy{DefaultDeny: true, AllowPortRules: []PodPeerPortRule{rule2, rule1}}
	b := &PodNetworkPolicy{DefaultDeny: true, AllowPortRules: []PodPeerPortRule{rule1, rule1, rule2}}
	if !EqualPolicy(a, b) {
		t.Fatal("expected policies to be equal after canonicalization")
	}
	c := &PodNetworkPolicy{DefaultDeny: true, AllowPortRules: []PodPeerPortRule{rule1}}
	if EqualPolicy(a, c) {
		t.Fatal("expected policies with different port rules to differ")
	}
}
