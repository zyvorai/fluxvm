// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPodsPaginationAndToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("authorization=%q", got)
		}
		if r.URL.Path != "/api/v1/pods" {
			t.Fatalf("path=%q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("continue") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]any{"continue": "next"},
				"items":    []any{map[string]any{"metadata": map[string]any{"name": "a", "namespace": "n", "uid": "1"}}},
			})
			return
		}
		if r.URL.Query().Get("continue") != "next" {
			t.Fatalf("unexpected continue=%q", r.URL.Query().Get("continue"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{},
			"items":    []any{map[string]any{"metadata": map[string]any{"name": "b", "namespace": "n", "uid": "2"}}},
		})
	}))
	defer server.Close()

	client, err := NewClient(Options{BaseURL: server.URL, TokenFile: tokenPath, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	pods, err := client.Pods(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(pods) != 2 || pods[0].Metadata.Name != "a" || pods[1].Metadata.Name != "b" {
		t.Fatalf("requests=%d pods=%+v", requests, pods)
	}
}

func TestMatchesSelectorOperators(t *testing.T) {
	labels := map[string]string{"env": "stage", "tier": "frontend"}
	cases := []struct {
		name string
		sel  LabelSelector
		want bool
	}{
		{"in", LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "env", Operator: "In", Values: []string{"prod", "stage"}}}}, true},
		{"not-in", LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "env", Operator: "NotIn", Values: []string{"prod"}}}}, true},
		{"exists", LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "tier", Operator: "Exists"}}}, true},
		{"missing-not-in", LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "region", Operator: "NotIn", Values: []string{"west"}}}}, true},
		{"does-not-exist", LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "region", Operator: "DoesNotExist"}}}, true},
		{"unknown-operator", LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "env", Operator: "Whatever"}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchesSelector(labels, tc.sel); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
