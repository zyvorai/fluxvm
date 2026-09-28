// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package fluxvm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProcboxCreateAndDryRun(t *testing.T) {
	var bodies []map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&b)
		bodies = append(bodies, b)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sandboxes":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"id":"11111111-1111-1111-1111-111111111111","name":"pb"}`))
		default:
			_, _ = w.Write([]byte(`{"changes":{"added":["/x"],"modified":[],"deleted":[],"unchanged":0},"exit_code":0,"stdout":"","stderr":"","discarded":true,"paths":["/"]}`))
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL)
	sb, err := c.CreateSandbox(context.Background(), CreateSandboxRequest{Name: "pb", Procbox: map[string]interface{}{"timeout_seconds": 5}})
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := bodies[0]["procbox"].(map[string]interface{})
	if pb == nil || pb["timeout_seconds"] != float64(5) {
		t.Fatalf("procbox not sent: %v", bodies[0])
	}
	out, err := sb.DryRun(context.Background(), "touch x", 3, []string{"/"})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Discarded || len(out.Changes.Added) != 1 || out.Changes.Added[0] != "/x" {
		t.Fatalf("unexpected dry-run result: %+v", out)
	}
	if bodies[1]["command"] != "touch x" || bodies[1]["timeout_seconds"] != float64(3) {
		t.Fatalf("dry-run body: %v", bodies[1])
	}
}
