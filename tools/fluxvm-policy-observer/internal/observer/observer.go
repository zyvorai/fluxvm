// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package observer

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultPinRoot  = "/sys/fs/bpf/fluxvm"
	DefaultMetaRoot = "/run/fluxvm/ebpf/vms"
	CurrentSchema   = 8
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

type DirectionStats struct {
	Allowed uint64
	Dropped uint64
	Audited uint64
}

type PolicyState struct {
	Enabled     bool
	DefaultDeny bool
	Audit       bool
}

type HookState struct {
	Required  bool
	Attached  bool
	ProgramID uint32
	Mode      string
}

type VMState struct {
	VMID             string
	PodID            uint32
	Interface        string
	SchemaVersion    uint32
	SchemaCompatible bool
	Egress           HookState
	Ingress          HookState
	EgressPolicy     PolicyState
	IngressPolicy    PolicyState
	EgressStats      DirectionStats
	IngressStats     DirectionStats
	RuleEntries      map[string]int
	Errors           []string
}

type Snapshot struct {
	CollectedAt time.Time
	VMs         []VMState
	Errors      []string
}

type Collector struct {
	PinRoot  string
	MetaRoot string
	BPFTool  string
	TC       string
	Timeout  time.Duration
	Runner   Runner
}

func (c Collector) defaults() Collector {
	if c.PinRoot == "" {
		c.PinRoot = DefaultPinRoot
	}
	if c.MetaRoot == "" {
		c.MetaRoot = DefaultMetaRoot
	}
	if c.BPFTool == "" {
		c.BPFTool = "bpftool"
	}
	if c.TC == "" {
		c.TC = "tc"
	}
	if c.Timeout <= 0 {
		c.Timeout = 2 * time.Second
	}
	if c.Runner == nil {
		c.Runner = ExecRunner{}
	}
	return c
}

func (c Collector) Collect(ctx context.Context) Snapshot {
	c = c.defaults()
	snap := Snapshot{CollectedAt: time.Now()}
	root := filepath.Join(c.PinRoot, "vms")
	entries, err := os.ReadDir(root)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			snap.Errors = append(snap.Errors, err.Error())
		}
		return snap
	}
	for _, ent := range entries {
		if !ent.IsDir() || !validVMDir(ent.Name()) {
			continue
		}
		snap.VMs = append(snap.VMs, c.collectVM(ctx, ent.Name()))
	}
	sort.Slice(snap.VMs, func(i, j int) bool { return snap.VMs[i].VMID < snap.VMs[j].VMID })
	return snap
}

func validVMDir(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func (c Collector) collectVM(parent context.Context, vm string) VMState {
	st := VMState{VMID: vm, RuleEntries: map[string]int{}}
	pin := filepath.Join(c.PinRoot, "vms", vm)
	meta := filepath.Join(c.MetaRoot, vm)
	st.PodID = uint32(readUint(filepath.Join(meta, "pod_id")))
	st.SchemaVersion = uint32(readUint(filepath.Join(meta, "schema_version")))
	st.SchemaCompatible = st.SchemaVersion == CurrentSchema
	st.Interface = readText(filepath.Join(meta, "iface"))
	mode := readText(filepath.Join(meta, "attach_mode"))
	st.Egress.Mode, st.Ingress.Mode = mode, mode

	ctx, cancel := context.WithTimeout(parent, c.Timeout)
	defer cancel()

	st.Egress.ProgramID = c.programID(ctx, filepath.Join(pin, "progs", "fluxvm_egress"), &st)
	st.Ingress.ProgramID = c.programID(ctx, filepath.Join(pin, "progs", "fluxvm_pod_ingress"), &st)
	st.Egress.Required = st.Egress.ProgramID != 0
	st.Ingress.Required = st.Ingress.ProgramID != 0

	st.Egress.Attached = c.attached(ctx, pin, st.Interface, mode, "ingress", "49152", st.Egress.ProgramID, false, &st)
	st.Ingress.Attached = c.attached(ctx, pin, st.Interface, mode, "egress", "49153", st.Ingress.ProgramID, true, &st)

	if st.PodID != 0 {
		// Set 14's fluxvm_pod_ingress program shares the main program's
		// pinned fluxvm_ppstat/fluxvm_pspol instances (loaded via `bpftool
		// prog load ... map name fluxvm_ppstat pinned <same path>`) rather
		// than owning independent "_in"-suffixed maps -- there is exactly
		// one Pod-policy stat counter and one Pod-policy flags record per
		// VM, covering both directions together. Reporting the same read
		// under both Egress/IngressStats is a deliberately honest
		// reflection of that shared counter (a hardcoded zero would wrongly
		// read as "no ingress traffic", which is worse).
		st.EgressStats = c.podStats(ctx, filepath.Join(pin, "maps", "fluxvm_ppstat"), st.PodID, &st)
		st.IngressStats = st.EgressStats
		st.EgressPolicy, st.IngressPolicy = c.policyState(ctx, filepath.Join(pin, "maps", "fluxvm_pspol"), st.PodID, &st)
		st.RuleEntries["egress_rules"], st.RuleEntries["ingress_rules"] = c.ruleCounts(ctx, filepath.Join(pin, "maps", "fluxvm_prules"), st.PodID, &st)
	}
	for _, spec := range ruleMaps() {
		st.RuleEntries[spec.name] = c.mapEntries(ctx, filepath.Join(pin, "maps", spec.file), st.PodID, spec.podOffset, &st)
	}
	return st
}

type ruleMap struct {
	name, file string
	podOffset  int
}

// Set 14 keeps these four exact-address/port maps for wire compatibility
// with a pre-Set-14 controller, shared by both directions (there is no
// per-direction split for legacy, non-rich Pod policy) -- the former CIDR/
// port-range/"_in"-suffixed maps this listed no longer exist at all,
// replaced by the unified fluxvm_prules map counted separately in
// ruleCounts.
func ruleMaps() []ruleMap {
	return []ruleMap{
		{"shared_address_v4", "fluxvm_pid4", 0}, {"shared_address_v6", "fluxvm_pid6", 0},
		{"shared_exact_port_v4", "fluxvm_pid4_port", 0}, {"shared_exact_port_v6", "fluxvm_pid6_port", 0},
	}
}

func (c Collector) programID(ctx context.Context, pin string, st *VMState) uint32 {
	if _, err := os.Stat(pin); err != nil {
		return 0
	}
	out, err := c.Runner.Run(ctx, c.BPFTool, "-j", "prog", "show", "pinned", pin)
	if err != nil {
		st.Errors = append(st.Errors, err.Error())
		return 0
	}
	return uint32(findNumberJSON(out, "id"))
}

func (c Collector) attached(ctx context.Context, pinRoot, iface, mode, direction, pref string, want uint32, ingress bool, st *VMState) bool {
	if want == 0 || iface == "" {
		return false
	}
	// The Pod-ingress program is always attached via plain tc at its own
	// reserved pref/handle (49153/2) -- never TCX, unlike the main
	// guest-egress program which prefers TCX when available. `mode` (from
	// the VM's attach_mode file) only ever describes the main program's
	// attachment, so it must not gate whether the ingress check looks for
	// a TCX link.
	if mode == "tcx" && !ingress {
		link := filepath.Join(pinRoot, "links", "tcx_ingress")
		if _, err := os.Stat(link); err != nil {
			return false
		}
		out, err := c.Runner.Run(ctx, c.BPFTool, "-j", "link", "show", "pinned", link)
		if err != nil {
			st.Errors = append(st.Errors, err.Error())
			return false
		}
		return uint32(findNumberJSON(out, "prog_id")) == want
	}
	out, err := c.Runner.Run(ctx, c.TC, "-j", "filter", "show", "dev", iface, direction, "pref", pref)
	if err == nil {
		return containsProgramID(out, want)
	}
	// Older iproute2 builds may not support JSON for this subcommand. Fall
	// back to the same text shape FluxVM itself parses, but still require the
	// exact program id. Keep the JSON error only if the fallback also fails.
	text, textErr := c.Runner.Run(ctx, c.TC, "filter", "show", "dev", iface, direction, "pref", pref)
	if textErr != nil {
		st.Errors = append(st.Errors, err.Error(), textErr.Error())
		return false
	}
	return containsProgramIDText(string(text), want)
}

func containsProgramIDText(text string, want uint32) bool {
	fields := strings.Fields(text)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "id" {
			continue
		}
		n, err := strconv.ParseUint(strings.Trim(fields[i+1], ",;"), 10, 32)
		if err == nil && uint32(n) == want {
			return true
		}
	}
	return false
}

func containsProgramID(doc []byte, want uint32) bool {
	var v any
	if json.Unmarshal(doc, &v) != nil {
		return false
	}
	return findAnyID(v, want)
}
func findAnyID(v any, want uint32) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if (k == "id" || k == "prog_id") && uint32(number(val)) == want {
				return true
			}
			if findAnyID(val, want) {
				return true
			}
		}
	case []any:
		for _, val := range x {
			if findAnyID(val, want) {
				return true
			}
		}
	}
	return false
}

func (c Collector) podStats(ctx context.Context, path string, pod uint32, st *VMState) DirectionStats {
	out := c.dumpMap(ctx, path, st)
	if out == nil {
		return DirectionStats{}
	}
	var entries []map[string]any
	if json.Unmarshal(out, &entries) != nil {
		return DirectionStats{}
	}
	var result DirectionStats
	for _, e := range entries {
		kb := bytesFromJSON(e["key"])
		if len(kb) < 4 || nativeU32(kb[:4]) != pod {
			continue
		}
		if vals, ok := e["values"].([]any); ok {
			for _, item := range vals {
				m, _ := item.(map[string]any)
				addStat(&result, bytesFromJSON(m["value"]))
			}
		} else {
			addStat(&result, bytesFromJSON(e["value"]))
		}
	}
	return result
}
func addStat(s *DirectionStats, b []byte) {
	if len(b) < 24 {
		return
	}
	s.Allowed += nativeU64(b[0:8])
	s.Dropped += nativeU64(b[8:16])
	s.Audited += nativeU64(b[16:24])
}

// policyState decodes struct fluxvm_pod_policy's flags word for the given
// pod_id and returns the egress- and ingress-direction views of it. Set 14
// keeps a single record per Pod covering both directions: bits 0/2
// (ENABLED/AUDIT) apply to both; bit 3 (RICH_RULES) selects which pair of
// isolation bits is meaningful -- bits 4/5 (EGRESS_ISOLATED/
// INGRESS_ISOLATED) for a schema-v2+ rich policy, or bit 1 (DEFAULT_DENY,
// egress-only, matching the pre-Set-14 Set 6S/13 semantics where an
// independent ingress isolation concept did not exist) for a legacy one.
func (c Collector) policyState(ctx context.Context, path string, pod uint32, st *VMState) (egress, ingress PolicyState) {
	out := c.dumpMap(ctx, path, st)
	if out == nil {
		return PolicyState{}, PolicyState{}
	}
	var entries []map[string]any
	if json.Unmarshal(out, &entries) != nil {
		return PolicyState{}, PolicyState{}
	}
	for _, e := range entries {
		kb := bytesFromJSON(e["key"])
		vb := bytesFromJSON(e["value"])
		if len(kb) < 4 || len(vb) < 4 || nativeU32(kb[:4]) != pod {
			continue
		}
		flags := nativeU32(vb[:4])
		enabled, audit := flags&1 != 0, flags&4 != 0
		if flags&8 != 0 {
			egress = PolicyState{Enabled: enabled, DefaultDeny: flags&16 != 0, Audit: audit}
			ingress = PolicyState{Enabled: enabled, DefaultDeny: flags&32 != 0, Audit: audit}
		} else {
			egress = PolicyState{Enabled: enabled, DefaultDeny: flags&2 != 0, Audit: audit}
			ingress = PolicyState{Enabled: enabled, Audit: audit}
		}
		return egress, ingress
	}
	return PolicyState{}, PolicyState{}
}

// ruleCounts scans the unified fluxvm_prules map (struct fluxvm_pod_rule:
// pod_id u32, direction u8, family u8, protocol u8, prefix_len u8, ...) and
// splits its entries for the given pod_id by direction (1=egress,
// 2=ingress) -- the only place Set 14 records independently-attributable
// per-direction rule counts, since the legacy exact-address/port maps are
// shared between directions.
func (c Collector) ruleCounts(ctx context.Context, path string, pod uint32, st *VMState) (egress, ingress int) {
	out := c.dumpMap(ctx, path, st)
	if out == nil {
		return 0, 0
	}
	var entries []map[string]any
	if json.Unmarshal(out, &entries) != nil {
		return 0, 0
	}
	for _, e := range entries {
		vb := bytesFromJSON(e["value"])
		if len(vb) < 5 || nativeU32(vb[:4]) != pod {
			continue
		}
		switch vb[4] {
		case 1:
			egress++
		case 2:
			ingress++
		}
	}
	return egress, ingress
}
func (c Collector) mapEntries(ctx context.Context, path string, pod uint32, podOffset int, st *VMState) int {
	out := c.dumpMap(ctx, path, st)
	if out == nil {
		return 0
	}
	var entries []map[string]any
	if json.Unmarshal(out, &entries) != nil {
		return 0
	}
	if pod == 0 {
		return 0
	}
	n := 0
	for _, entry := range entries {
		key := bytesFromJSON(entry["key"])
		if len(key) >= podOffset+4 && nativeU32(key[podOffset:podOffset+4]) == pod {
			n++
		}
	}
	return n
}
func (c Collector) dumpMap(ctx context.Context, path string, st *VMState) []byte {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	out, err := c.Runner.Run(ctx, c.BPFTool, "-j", "map", "dump", "pinned", path)
	if err != nil {
		st.Errors = append(st.Errors, err.Error())
		return nil
	}
	return out
}

func findNumberJSON(doc []byte, key string) uint64 {
	var v any
	if json.Unmarshal(doc, &v) != nil {
		return 0
	}
	return findNumber(v, key)
}
func findNumber(v any, key string) uint64 {
	switch x := v.(type) {
	case map[string]any:
		if z, ok := x[key]; ok {
			return uint64(number(z))
		}
		for _, z := range x {
			if n := findNumber(z, key); n != 0 {
				return n
			}
		}
	case []any:
		for _, z := range x {
			if n := findNumber(z, key); n != 0 {
				return n
			}
		}
	}
	return 0
}
func number(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case json.Number:
		n, _ := x.Float64()
		return n
	case string:
		n, _ := strconv.ParseFloat(x, 64)
		return n
	}
	return 0
}

func bytesFromJSON(v any) []byte {
	switch x := v.(type) {
	case []any:
		out := make([]byte, 0, len(x))
		for _, z := range x {
			switch q := z.(type) {
			case float64:
				if q >= 0 && q <= 255 {
					out = append(out, byte(q))
				}
			case string:
				q = strings.TrimPrefix(q, "0x")
				if n, err := strconv.ParseUint(q, 16, 8); err == nil {
					out = append(out, byte(n))
				}
			}
		}
		return out
	case string:
		x = strings.NewReplacer(":", " ", ",", " ").Replace(x)
		var out []byte
		for _, q := range strings.Fields(x) {
			q = strings.TrimPrefix(q, "0x")
			if n, err := strconv.ParseUint(q, 16, 8); err == nil {
				out = append(out, byte(n))
			}
		}
		return out
	}
	return nil
}
func nativeU32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.NativeEndian.Uint32(b[:4])
}
func nativeU64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.NativeEndian.Uint64(b[:8])
}

func readText(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
func readUint(path string) uint64 { n, _ := strconv.ParseUint(readText(path), 10, 64); return n }
