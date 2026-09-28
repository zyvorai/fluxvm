// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package fluxvm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxFileTransferBytes mirrors fluxvm_guest_protocol::MAX_FILE_TRANSFER_BYTES:
	// the guest agent moves a whole file as one base64 JSON line and refuses
	// anything larger.
	MaxFileTransferBytes = 64 * 1024 * 1024
	// DefaultExecTimeout mirrors fluxvm_guest_protocol::DEFAULT_EXEC_TIMEOUT_SECS.
	DefaultExecTimeout = 30 * time.Second
	// The server waits timeout_seconds+5 for the guest agent; give the HTTP call
	// more so a guest-side timeout is reported by the server rather than as a
	// client-side timeout.
	execHTTPSlack = 10 * time.Second
)

// Sandbox is a handle to one sandbox.
type Sandbox struct {
	client *Client
	// Info is the last record read from the server; Refresh updates it.
	Info SandboxInfo
}

// ID returns the sandbox id.
func (s *Sandbox) ID() string { return s.Info.ID }

func (s *Sandbox) path(suffix string) string {
	return "/v1/sandboxes/" + url.PathEscape(s.Info.ID) + suffix
}

// Refresh re-reads the record (GET /v1/vms/{id}) and updates Info.
func (s *Sandbox) Refresh(ctx context.Context) error {
	var raw json.RawMessage
	if err := s.client.call(ctx, http.MethodGet, "/v1/vms/"+url.PathEscape(s.Info.ID), nil, &raw, 0); err != nil {
		return err
	}
	info, err := parseSandboxInfo(raw)
	if err != nil {
		return err
	}
	s.Info = info
	return nil
}

// Delete calls DELETE /v1/vms/{id} (204). Sandboxes are VM records, so the
// generic VM delete is what removes one. It returns an error matching
// ErrNotFound if the sandbox is already gone.
func (s *Sandbox) Delete(ctx context.Context) error {
	return s.client.call(ctx, http.MethodDelete, "/v1/vms/"+url.PathEscape(s.Info.ID), nil, nil, 0, http.StatusNoContent)
}

// RunOption configures Run.
type RunOption func(*runOpts)

type runOpts struct{ timeout time.Duration }

// WithExecTimeout sets the guest-side limit (whole seconds, default 30s). A
// command that exceeds it comes back with a non-zero exit code rather than
// an error.
func WithExecTimeout(d time.Duration) RunOption { return func(o *runOpts) { o.timeout = d } }

// Run executes a shell string in the guest (POST /process); the guest agent
// runs it with /bin/sh -c.
func (s *Sandbox) Run(ctx context.Context, command string, opts ...RunOption) (*ExecResult, error) {
	var o runOpts
	for _, opt := range opts {
		opt(&o)
	}
	payload := map[string]interface{}{"command": command}
	limit := DefaultExecTimeout
	if o.timeout > 0 {
		secs := int(o.timeout / time.Second)
		if secs < 1 {
			secs = 1
		}
		payload["timeout_seconds"] = secs
		limit = time.Duration(secs) * time.Second
	}
	var out struct {
		Result string `json:"result"`
		ExecResult
	}
	if err := s.client.call(ctx, http.MethodPost, s.path("/process"), payload, &out, limit+execHTTPSlack); err != nil {
		return nil, err
	}
	if out.Result != "exec" {
		return nil, &APIError{Status: http.StatusOK, Message: "unexpected process response"}
	}
	res := out.ExecResult
	return &res, nil
}

// RunArgs runs argv in the guest, shell-quoting each argument.
func (s *Sandbox) RunArgs(ctx context.Context, argv []string, opts ...RunOption) (*ExecResult, error) {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = shellQuote(a)
	}
	return s.Run(ctx, strings.Join(quoted, " "), opts...)
}

// shellQuote quotes one argument for /bin/sh, like Python's shlex.quote.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%+=:,./-_", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// ReadFileInfo reads a guest file with its mode (POST /fs/read).
func (s *Sandbox) ReadFileInfo(ctx context.Context, path string) (*FileContent, error) {
	var out struct {
		Result        string `json:"result"`
		ContentBase64 string `json:"content_base64"`
		Mode          uint32 `json:"mode"`
	}
	if err := s.client.call(ctx, http.MethodPost, s.path("/fs/read"), map[string]string{"path": path}, &out, 0); err != nil {
		return nil, err
	}
	if out.Result != "file-content" {
		return nil, &APIError{Status: http.StatusOK, Message: "unexpected fs/read response"}
	}
	data, err := base64.StdEncoding.DecodeString(out.ContentBase64)
	if err != nil {
		return nil, fmt.Errorf("fluxvm: decoding file content: %w", err)
	}
	return &FileContent{Data: data, Mode: out.Mode}, nil
}

// ReadFile returns a guest file's bytes.
func (s *Sandbox) ReadFile(ctx context.Context, path string) ([]byte, error) {
	fc, err := s.ReadFileInfo(ctx, path)
	if err != nil {
		return nil, err
	}
	return fc.Data, nil
}

// WriteOption configures WriteFile.
type WriteOption func(*writeOpts)

type writeOpts struct{ mode *uint32 }

// WithMode sets the Unix permission bits (server default 0o644).
func WithMode(mode uint32) WriteOption { return func(o *writeOpts) { o.mode = &mode } }

// WriteFile writes a guest file (POST /fs/write). Parent directories are
// created by the guest agent. Data above MaxFileTransferBytes returns
// ErrFileTooLarge without contacting the server.
func (s *Sandbox) WriteFile(ctx context.Context, path string, data []byte, opts ...WriteOption) error {
	if len(data) > MaxFileTransferBytes {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrFileTooLarge, len(data), MaxFileTransferBytes)
	}
	var o writeOpts
	for _, opt := range opts {
		opt(&o)
	}
	payload := map[string]interface{}{
		"path":           path,
		"content_base64": base64.StdEncoding.EncodeToString(data),
	}
	if o.mode != nil {
		payload["mode"] = *o.mode
	}
	var out struct {
		Result string `json:"result"`
	}
	if err := s.client.call(ctx, http.MethodPost, s.path("/fs/write"), payload, &out, 0); err != nil {
		return err
	}
	if out.Result != "file-written" {
		return &APIError{Status: http.StatusOK, Message: "unexpected fs/write response"}
	}
	return nil
}

// Snapshot calls POST /snapshot. path is a path on the server host where the
// snapshot is written; the path the server reports is returned.
func (s *Sandbox) Snapshot(ctx context.Context, path string) (string, error) {
	var out struct {
		Path string `json:"path"`
	}
	if err := s.client.call(ctx, http.MethodPost, s.path("/snapshot"), map[string]string{"path": path}, &out, 0); err != nil {
		return "", err
	}
	if out.Path == "" {
		return path, nil
	}
	return out.Path, nil
}

// Baseline records the regular files under paths (absolute guest directories)
// so Changes can diff against them, replacing any earlier baseline
// (POST /baseline). It needs the guest agent.
func (s *Sandbox) Baseline(ctx context.Context, paths []string) (*BaselineSummary, error) {
	if paths == nil {
		paths = []string{}
	}
	var out BaselineSummary
	if err := s.client.call(ctx, http.MethodPost, s.path("/baseline"), map[string]interface{}{"paths": paths}, &out, 0); err != nil {
		return nil, err
	}
	return &out, nil
}

// Changes lists the files added, modified or deleted since the last Baseline
// (POST /changes). A non-nil paths narrows the diff to a subset of the
// baseline directories; nil compares them all. The error matches ErrNotFound
// when no baseline exists. It reports changes only; use snapshot/restore to
// roll back.
func (s *Sandbox) Changes(ctx context.Context, paths []string) (*ChangeSet, error) {
	body := map[string]interface{}{}
	if paths != nil {
		body["paths"] = paths
	}
	var out ChangeSet
	if err := s.client.call(ctx, http.MethodPost, s.path("/changes"), body, &out, 0); err != nil {
		return nil, err
	}
	return &out, nil
}

// HTTPRequest describes a call to an HTTP service inside the guest.
type HTTPRequest struct {
	// Port selects /v1/sandboxes/{id}/http/{port}/{path}; 0 uses the
	// default-port route /sandbox/{id}/{path}.
	Port   int
	Method string
	Path   string
	// Body may be nil, []byte (application/octet-stream), string
	// (text/plain) or any value that marshals to JSON (application/json).
	Body   interface{}
	Header http.Header
	Query  url.Values
	// Timeout overrides the client default for this call.
	Timeout time.Duration
}

// HTTP calls an HTTP service inside the guest through the API's reverse
// proxy. The guest's own status codes are returned, not raised; auth failures
// on the API itself (401/403) are indistinguishable from a guest 401/403
// here. The sandbox needs a routable guest IP (network.mode=tap with a
// netns); otherwise the server answers 400/502.
func (s *Sandbox) HTTP(ctx context.Context, r HTTPRequest) (*HTTPResponse, error) {
	method := strings.ToUpper(r.Method)
	if method == "" {
		method = http.MethodGet
	}
	rel := escapeProxyPath(strings.TrimLeft(r.Path, "/"))
	sid := url.PathEscape(s.Info.ID)
	var p string
	if r.Port == 0 {
		p = "/sandbox/" + sid + "/" + rel
	} else {
		p = "/v1/sandboxes/" + sid + "/http/" + strconv.Itoa(r.Port) + "/" + rel
	}
	if len(r.Query) > 0 {
		p += "?" + r.Query.Encode()
	}
	hdr := http.Header{}
	for k, vs := range r.Header {
		hdr[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
	}
	var body []byte
	switch b := r.Body.(type) {
	case nil:
	case []byte:
		body = b
		if hdr.Get("Content-Type") == "" {
			hdr.Set("Content-Type", "application/octet-stream")
		}
	case string:
		body = []byte(b)
		if hdr.Get("Content-Type") == "" {
			hdr.Set("Content-Type", "text/plain; charset=utf-8")
		}
	default:
		enc, err := json.Marshal(b)
		if err != nil {
			return nil, fmt.Errorf("fluxvm: encoding request body: %w", err)
		}
		body = enc
		if hdr.Get("Content-Type") == "" {
			hdr.Set("Content-Type", "application/json")
		}
	}
	status, rh, data, err := s.client.do(ctx, method, p, body, hdr, r.Timeout)
	if err != nil {
		return nil, err
	}
	return &HTTPResponse{Status: status, Header: rh, Body: data}, nil
}

// escapeProxyPath percent-encodes a proxied path, keeping the same safe set
// as the Python SDK ("/:@!$&'()*+,;=-._~" plus alphanumerics).
func escapeProxyPath(p string) string {
	const safe = "/:@!$&'()*+,;=-._~"
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(safe, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
