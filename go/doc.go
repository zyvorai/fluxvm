// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

// Package fluxvm is a client for the FluxVM agent-sandbox API
// (/v1/sandboxes). It uses only the standard library and mirrors the Python
// SDK in ../python: create a sandbox, run commands, move files, snapshot it,
// call HTTP services inside it, and ask which files changed since a baseline.
//
//	c := fluxvm.NewClient("http://127.0.0.1:8080", fluxvm.WithToken(token))
//	sb, err := c.CreateSandbox(ctx, fluxvm.CreateSandboxRequest{Template: "python"})
//	if err != nil { ... }
//	defer sb.Delete(ctx)
//	res, err := sb.Run(ctx, "echo hello")
//
// Every call takes a context. Failures from the server are *APIError values
// that also match the sentinel errors (ErrAuth, ErrForbidden, ErrNotFound,
// ErrRateLimited) with errors.Is; transport failures match ErrTimeout or
// ErrConnection.
package fluxvm
