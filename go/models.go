// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package fluxvm

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// SandboxInfo is the subset of the server's VM record that is useful to
// callers. Raw keeps the complete JSON so fields not modelled here stay
// reachable. Confidential is only present on create responses when a
// confidential mode was requested.
type SandboxInfo struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Status       string                 `json:"status"`
	Backend      *string                `json:"backend"`
	GuestIP      *string                `json:"guest_ip"`
	PID          *int                   `json:"pid"`
	CreatedAt    *string                `json:"created_at"`
	ExpiresAt    *string                `json:"expires_at"`
	Confidential map[string]interface{} `json:"confidential,omitempty"`
	Raw          json.RawMessage        `json:"-"`
}

func parseSandboxInfo(data []byte) (SandboxInfo, error) {
	var info SandboxInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return SandboxInfo{}, fmt.Errorf("fluxvm: decoding sandbox record: %w", err)
	}
	if info.ID == "" {
		return SandboxInfo{}, fmt.Errorf("fluxvm: sandbox record has no id")
	}
	info.Raw = append(json.RawMessage(nil), data...)
	return info, nil
}

// Volume is a named persistent volume to attach (needs a QEMU-backed template).
type Volume struct {
	Name      string `json:"name"`
	GuestPath string `json:"guest_path"`
	ReadOnly  bool   `json:"read_only"`
}

// CreateSandboxRequest is the body of POST /v1/sandboxes. Zero-valued fields
// are omitted so the server's defaults apply. Template names a template under
// the server's templates dir; Spec is a raw create spec (as accepted by
// POST /v1/vms). Confidential is "auto" or "required".
type CreateSandboxRequest struct {
	Name           string                 `json:"name,omitempty"`
	Template       string                 `json:"template,omitempty"`
	Spec           map[string]interface{} `json:"spec,omitempty"`
	TTLSeconds     uint64                 `json:"ttl_seconds,omitempty"`
	HTTPProxyPort  uint16                 `json:"http_proxy_port,omitempty"`
	HTTPProxyPorts []uint16               `json:"http_proxy_ports,omitempty"`
	Volumes        []Volume               `json:"volumes,omitempty"`
	VCPUs          uint8                  `json:"vcpus,omitempty"`
	MemoryMiB      uint64                 `json:"memory_mib,omitempty"`
	Confidential   string                 `json:"confidential,omitempty"`
}

// ExecResult is the outcome of a command run through the guest agent.
type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// OK reports whether the command exited 0.
func (r ExecResult) OK() bool { return r.ExitCode == 0 }

// FileContent is a guest file: raw bytes plus the Unix mode bits the guest reported.
type FileContent struct {
	Data []byte
	Mode uint32
}

// BaselineSummary is the result of recording a file baseline.
type BaselineSummary struct {
	Files int      `json:"files"`
	Mode  string   `json:"mode"`
	Paths []string `json:"paths"`
}

// ChangeSet lists the files changed since the baseline. A rename shows up as
// one deletion plus one addition. Mode is the fingerprint used ("sha256", or
// the "stat" size+mtime fallback).
type ChangeSet struct {
	Added               []string `json:"added"`
	Modified            []string `json:"modified"`
	Deleted             []string `json:"deleted"`
	Unchanged           int      `json:"unchanged"`
	Mode                string   `json:"mode"`
	Paths               []string `json:"paths"`
	BaselineTakenAtUnix int64    `json:"baseline_taken_at_unix"`
}

// Clean reports whether nothing was added, modified or deleted.
func (c ChangeSet) Clean() bool {
	return len(c.Added) == 0 && len(c.Modified) == 0 && len(c.Deleted) == 0
}

// HTTPResponse is a response proxied from an HTTP service inside the guest.
// The proxy relays the guest's own status codes, so a 4xx/5xx here is not
// returned as an error; call RaiseForStatus if you want that.
type HTTPResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// OK reports whether the status is 2xx.
func (r *HTTPResponse) OK() bool { return r.Status >= 200 && r.Status < 300 }

// Text returns the body as a string.
func (r *HTTPResponse) Text() string { return string(r.Body) }

// JSON decodes the body into v.
func (r *HTTPResponse) JSON(v interface{}) error { return json.Unmarshal(r.Body, v) }

// RaiseForStatus returns an *APIError for a non-2xx status, nil otherwise.
func (r *HTTPResponse) RaiseForStatus() error {
	if r.OK() {
		return nil
	}
	return newAPIError(r.Status, r.Header, r.Body)
}
