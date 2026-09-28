// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package fluxvm

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The mock mirrors crates/fluxvm-api/src/lib.rs the same way the Python SDK's
// tests/mock_server.py does: bearer token -> role (401 otherwise), sandbox
// routes need admin (403), handler failures are 400 {"error": ...}, unknown
// sandbox ids are 404 "VM not found", and exec/file answers carry the guest
// protocol "result" tags.

const (
	adminToken    = "admin-token"
	readonlyToken = "readonly-token"
	slowPath      = "/slow"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type recorded struct {
	Method string
	Path   string // path plus query, as sent
	Header http.Header
	Body   []byte
}

type fileEntry struct {
	data []byte
	mode uint32
}

type baselineEntry struct {
	paths []string
	files map[string]fileEntry
}

type mockState struct {
	mu            sync.Mutex
	sandboxes     map[string]map[string]interface{}
	order         []string
	files         map[string]map[string]fileEntry
	baselines     map[string]baselineEntry
	requests      []recorded
	rateLimitNext bool
	execDelay     time.Duration
	nextID        int
}

func newMock() (*httptest.Server, *mockState) {
	st := &mockState{
		sandboxes: map[string]map[string]interface{}{},
		files:     map[string]map[string]fileEntry{},
		baselines: map[string]baselineEntry{},
	}
	return httptest.NewServer(http.HandlerFunc(st.handle)), st
}

func (st *mockState) last() recorded {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.requests[len(st.requests)-1]
}

func (st *mockState) reqCount() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.requests)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}, hdr map[string]string) {
	for k, val := range hdr {
		w.Header().Set(k, val)
	}
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg}, nil)
}

func (st *mockState) newID() string {
	st.nextID++
	// 8-4-4-4-12 hex, unique per call.
	return "00000000-0000-4000-8000-" + strings.Repeat("0", 12-len(itoaHex(st.nextID))) + itoaHex(st.nextID)
}

func itoaHex(n int) string {
	const digits = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%16]}, b...)
		n /= 16
	}
	return string(b)
}

func (st *mockState) sandbox(id string) map[string]interface{} {
	if !uuidRE.MatchString(id) {
		return nil
	}
	return st.sandboxes[id]
}

func (st *mockState) handle(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	st.mu.Lock()
	st.requests = append(st.requests, recorded{r.Method, r.URL.RequestURI(), r.Header.Clone(), raw})
	rateLimit := st.rateLimitNext
	st.mu.Unlock()

	path := r.URL.Path
	switch path {
	case "/healthz":
		writeJSON(w, 200, map[string]bool{"ok": true}, nil)
		return
	case "/v1/openapi.json":
		writeJSON(w, 200, map[string]string{"openapi": "3.0.0"}, nil)
		return
	}
	auth := r.Header.Get("Authorization")
	role := ""
	switch strings.TrimPrefix(auth, "Bearer ") {
	case adminToken:
		role = "admin"
	case readonlyToken:
		role = "read-only"
	}
	if !strings.HasPrefix(auth, "Bearer ") || role == "" {
		errJSON(w, 401, "missing or invalid bearer token")
		return
	}
	if rateLimit {
		st.mu.Lock()
		st.rateLimitNext = false
		st.mu.Unlock()
		writeJSON(w, 429, map[string]string{"error": "rate limit exceeded"}, map[string]string{"Retry-After": "7"})
		return
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if path == "/v1/host/confidential" && r.Method == "GET" {
		writeJSON(w, 200, map[string]bool{"sev_snp": false, "tdx": false, "launch_supported": false}, nil)
		return
	}
	if path == "/v1/sandboxes" && r.Method == "GET" {
		items := []interface{}{}
		for _, id := range st.order {
			if rec, ok := st.sandboxes[id]; ok {
				items = append(items, rec)
			}
		}
		writeJSON(w, 200, map[string]interface{}{"items": items}, nil)
		return
	}
	if path == "/v1/sandboxes" && r.Method == "POST" {
		if role != "admin" {
			errJSON(w, 403, "admin role required")
			return
		}
		var req map[string]interface{}
		_ = json.Unmarshal(raw, &req)
		if req["template"] == "missing" {
			errJSON(w, 400, "template missing not found")
			return
		}
		id := st.newID()
		name, _ := req["name"].(string)
		if name == "" {
			name = "sandbox-" + id
		}
		rec := map[string]interface{}{
			"id": id, "name": name, "backend": "fluxvm", "status": "running", "pid": 4242,
			"guest_ip": "10.0.0.2", "created_at": "2026-09-28T10:00:00Z", "expires_at": nil, "request": req,
		}
		if c, ok := req["confidential"]; ok && c != nil {
			rec["confidential"] = map[string]interface{}{"requested": c, "active": false}
		}
		st.sandboxes[id] = rec
		st.order = append(st.order, id)
		writeJSON(w, 201, rec, nil)
		return
	}

	segs := strings.Split(strings.Trim(path, "/"), "/")
	// /v1/vms/{id}: GET / DELETE
	if len(segs) == 3 && segs[0] == "v1" && segs[1] == "vms" {
		rec := st.sandbox(segs[2])
		if rec == nil {
			errJSON(w, 404, "VM not found")
			return
		}
		switch r.Method {
		case "GET":
			writeJSON(w, 200, rec, nil)
		case "DELETE":
			if role != "admin" {
				errJSON(w, 403, "admin role required")
				return
			}
			delete(st.sandboxes, segs[2])
			writeJSON(w, http.StatusNoContent, nil, nil)
		default:
			errJSON(w, 405, "method not allowed")
		}
		return
	}
	// /sandbox/{id}/{path}: default-port proxy
	if segs[0] == "sandbox" && len(segs) >= 3 {
		st.proxy(w, r, role, segs[1], "default", strings.Join(segs[2:], "/"), raw)
		return
	}
	if len(segs) >= 4 && segs[0] == "v1" && segs[1] == "sandboxes" {
		sid, op := segs[2], segs[3]
		if st.sandbox(sid) == nil {
			errJSON(w, 404, "VM not found")
			return
		}
		if op == "http" && len(segs) >= 6 {
			st.proxy(w, r, role, sid, segs[4], strings.Join(segs[5:], "/"), raw)
			return
		}
		if r.Method != "POST" {
			errJSON(w, 405, "method not allowed")
			return
		}
		if role != "admin" {
			errJSON(w, 403, "admin role required")
			return
		}
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		switch {
		case op == "snapshot":
			writeJSON(w, 200, map[string]interface{}{"ok": true, "path": body["path"]}, nil)
		case op == "baseline" && len(segs) == 4:
			st.baseline(w, sid, body)
		case op == "changes" && len(segs) == 4:
			st.changes(w, sid, body)
		case op == "process" && len(segs) == 4:
			st.process(w, body)
		case op == "fs" && len(segs) == 5:
			st.fs(w, sid, segs[4], body)
		default:
			errJSON(w, 404, "no such route")
		}
		return
	}
	errJSON(w, 404, "no such route")
}

func underAny(f string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(f, strings.TrimRight(d, "/")+"/") {
			return true
		}
	}
	return false
}

func toStrings(v interface{}) []string {
	var out []string
	if arr, ok := v.([]interface{}); ok {
		for _, x := range arr {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func (st *mockState) baseline(w http.ResponseWriter, sid string, body map[string]interface{}) {
	paths := toStrings(body["paths"])
	if len(paths) == 0 {
		errJSON(w, 400, "invalid baseline paths")
		return
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") {
			errJSON(w, 400, "invalid baseline paths")
			return
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == ".." {
				errJSON(w, 400, "invalid baseline paths")
				return
			}
		}
	}
	snap := map[string]fileEntry{}
	for f, e := range st.files[sid] {
		if underAny(f, paths) {
			snap[f] = e
		}
	}
	st.baselines[sid] = baselineEntry{paths: paths, files: snap}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "files": len(snap), "mode": "sha256", "paths": paths}, nil)
}

func (st *mockState) changes(w http.ResponseWriter, sid string, body map[string]interface{}) {
	base, ok := st.baselines[sid]
	if !ok {
		errJSON(w, 404, "no baseline recorded for this sandbox")
		return
	}
	want := toStrings(body["paths"])
	if body["paths"] == nil {
		want = base.paths
	}
	added, modified, deleted := []string{}, []string{}, []string{}
	now := map[string]fileEntry{}
	for f, e := range st.files[sid] {
		if underAny(f, want) {
			now[f] = e
		}
	}
	before := map[string]fileEntry{}
	for f, e := range base.files {
		if underAny(f, want) {
			before[f] = e
		}
	}
	for f, e := range now {
		b, seen := before[f]
		switch {
		case !seen:
			added = append(added, f)
		case string(b.data) != string(e.data):
			modified = append(modified, f)
		}
	}
	for f := range before {
		if _, seen := now[f]; !seen {
			deleted = append(deleted, f)
		}
	}
	sortStrings(added)
	sortStrings(modified)
	sortStrings(deleted)
	writeJSON(w, 200, map[string]interface{}{
		"added": added, "modified": modified, "deleted": deleted,
		"unchanged": len(now) - len(added) - len(modified),
		"mode":      "sha256", "paths": want, "baseline_taken_at_unix": 1790585116,
	}, nil)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func (st *mockState) process(w http.ResponseWriter, body map[string]interface{}) {
	cmd, _ := body["command"].(string)
	if st.execDelay > 0 {
		st.mu.Unlock()
		time.Sleep(st.execDelay)
		st.mu.Lock()
	}
	if strings.HasPrefix(cmd, "agent-error") {
		errJSON(w, 400, "guest agent error: boom")
		return
	}
	if strings.HasPrefix(cmd, "sleep") {
		if t, ok := body["timeout_seconds"].(float64); ok {
			var n int
			for _, c := range strings.TrimSpace(strings.TrimPrefix(cmd, "sleep")) {
				n = n*10 + int(c-'0')
			}
			if n > int(t) {
				writeJSON(w, 200, map[string]interface{}{"result": "exec", "exit_code": 124, "stdout": "", "stderr": "timed out"}, nil)
				return
			}
		}
	}
	if strings.HasPrefix(cmd, "echo ") {
		writeJSON(w, 200, map[string]interface{}{"result": "exec", "exit_code": 0, "stdout": strings.TrimPrefix(cmd, "echo ") + "\n", "stderr": ""}, nil)
		return
	}
	if strings.HasPrefix(cmd, "false") {
		writeJSON(w, 200, map[string]interface{}{"result": "exec", "exit_code": 1, "stdout": "", "stderr": "failed"}, nil)
		return
	}
	// Anything else: echo the command back so tests can see exactly what was sent.
	writeJSON(w, 200, map[string]interface{}{"result": "exec", "exit_code": 0, "stdout": cmd, "stderr": ""}, nil)
}

func (st *mockState) fs(w http.ResponseWriter, sid, op string, body map[string]interface{}) {
	files := st.files[sid]
	if files == nil {
		files = map[string]fileEntry{}
		st.files[sid] = files
	}
	path, _ := body["path"].(string)
	switch op {
	case "write":
		data, err := base64.StdEncoding.DecodeString(body["content_base64"].(string))
		if err != nil {
			errJSON(w, 400, "bad base64")
			return
		}
		mode := uint32(0o644)
		if m, ok := body["mode"].(float64); ok {
			mode = uint32(m)
		}
		files[path] = fileEntry{data, mode}
		writeJSON(w, 200, map[string]string{"result": "file-written"}, nil)
	case "read":
		e, ok := files[path]
		if !ok {
			errJSON(w, 400, "guest agent error: no such file: "+path)
			return
		}
		writeJSON(w, 200, map[string]interface{}{"result": "file-content", "content_base64": base64.StdEncoding.EncodeToString(e.data), "mode": e.mode}, nil)
	default:
		errJSON(w, 404, "no such route")
	}
}

func (st *mockState) proxy(w http.ResponseWriter, r *http.Request, role, sid, port, rest string, raw []byte) {
	if role != "admin" {
		errJSON(w, 403, "admin role required")
		return
	}
	if st.sandbox(sid) == nil {
		errJSON(w, 404, "VM not found")
		return
	}
	if "/"+rest == slowPath {
		st.mu.Unlock()
		time.Sleep(time.Second)
		st.mu.Lock()
	}
	if rest == "redirect" {
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(302)
		return
	}
	if rest == "teapot" {
		w.Header().Set("X-Guest", "yes")
		w.WriteHeader(418)
		_, _ = w.Write([]byte("short and stout"))
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"method": r.Method, "port": port, "path": "/" + rest, "query": r.URL.RawQuery,
		"content_type": r.Header.Get("Content-Type"), "body": string(raw),
		"x_test": r.Header.Get("X-Test"),
	}, map[string]string{"X-Guest": "hello"})
}
