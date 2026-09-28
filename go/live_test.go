//go:build live

// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package fluxvm

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// Run with: FLUXVM_LIVE_URL=http://127.0.0.1:17788 go test -tags live -run Live ./...
// against a daemon that has [sandbox.procbox] enabled = true.
func TestLiveProcboxFlow(t *testing.T) {
	url := os.Getenv("FLUXVM_LIVE_URL")
	if url == "" {
		t.Skip("FLUXVM_LIVE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := NewClient(url)
	sb, err := c.CreateSandbox(ctx, CreateSandboxRequest{Name: "go-live", TTLSeconds: 300,
		Procbox: map[string]interface{}{"timeout_seconds": 20}})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Delete(ctx)

	if err := sb.WriteFile(ctx, "work/a.txt", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := sb.Baseline(ctx, []string{"/work"}); err != nil {
		t.Fatal(err)
	}
	r, err := sb.Run(ctx, "echo two > work/a.txt; echo n > work/new.txt")
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("run: %v %+v", err, r)
	}
	ch, err := sb.Changes(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Added) != 1 || len(ch.Modified) != 1 {
		t.Fatalf("changes: %+v", ch)
	}
	r, _ = sb.Run(ctx, "echo x > /tmp/go-live-escape && echo WROTE || echo BLOCKED")
	if r.Stdout != "BLOCKED\n" {
		t.Fatalf("write outside workspace not blocked: %+v", r)
	}
	if _, err := sb.ReadFile(ctx, "../../etc/passwd"); err == nil {
		t.Fatal("path traversal read succeeded")
	}
	dr, err := sb.DryRun(ctx, "rm work/a.txt", 0, []string{"/work"})
	if err != nil || !dr.Discarded || len(dr.Changes.Deleted) != 1 {
		t.Fatalf("dry-run: %v %+v", err, dr)
	}
	after, _ := sb.Changes(ctx, nil)
	if len(after.Deleted) != 0 {
		t.Fatalf("dry-run leaked a deletion into the workspace: %+v", after)
	}
	if _, err := sb.Snapshot(ctx, "/tmp/x"); err == nil {
		t.Fatal("snapshot should be unsupported on procbox")
	}
	if err := sb.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetSandbox(ctx, sb.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete want ErrNotFound, got %v", err)
	}
}
