// FLUXVM_SECURE_CONTAINERS_SET17
// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package observer

import (
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestSet17RuleTelemetryAggregatesDirectionAndRuleIdentity(t *testing.T) {
	pod := uint32(77)
	rule := make([]byte, 28)
	binary.NativeEndian.PutUint32(rule[0:4], pod)
	rule[4] = 1 // egress
	rule[5] = 4 // IPv4
	rule[6] = 6 // TCP
	rule[7] = 32
	binary.NativeEndian.PutUint16(rule[8:10], 443)
	binary.NativeEndian.PutUint16(rule[10:12], 443)
	copy(rule[12:16], []byte{10, 0, 0, 9})
	slot := make([]byte, 4)
	binary.NativeEndian.PutUint32(slot, 3)

	allowKey := make([]byte, 12)
	binary.NativeEndian.PutUint32(allowKey[0:4], pod)
	binary.NativeEndian.PutUint32(allowKey[4:8], 3)
	allowKey[8], allowKey[9] = 1, 1 // egress, allow
	missKey := make([]byte, 12)
	binary.NativeEndian.PutUint32(missKey[0:4], pod)
	binary.NativeEndian.PutUint32(missKey[4:8], ruleMissIndex)
	missKey[8], missKey[9] = 2, 0 // ingress, drop

	u64 := func(v uint64) []byte { b := make([]byte, 8); binary.NativeEndian.PutUint64(b, v); return b }
	// Encode like bpftool dump JSON (int byte arrays), not Go []byte base64.
	ruleDoc, _ := json.Marshal([]map[string]any{{"key": bytesJSON(slot), "value": bytesJSON(rule)}})
	hitDoc, _ := json.Marshal([]map[string]any{
		{"key": bytesJSON(allowKey), "values": []map[string]any{{"cpu": 0, "value": bytesJSON(u64(2))}, {"cpu": 1, "value": bytesJSON(u64(3))}}},
		{"key": bytesJSON(missKey), "values": []map[string]any{{"cpu": 0, "value": bytesJSON(u64(4))}}},
	})

	egress, ingress, hits := parseRuleTelemetry(hitDoc, ruleDoc, pod)
	if egress.Allowed != 5 || egress.Dropped != 0 || ingress.Dropped != 4 {
		t.Fatalf("unexpected direction stats: egress=%+v ingress=%+v", egress, ingress)
	}
	if len(hits) != 2 {
		t.Fatalf("hits=%d want=2: %+v", len(hits), hits)
	}
	var matched *RuleHit
	for i := range hits {
		if hits[i].Matched {
			matched = &hits[i]
		}
	}
	if matched == nil || matched.RuleIndex != 3 || matched.CIDR != "10.0.0.9/32" || matched.Protocol != "tcp" || matched.PortStart != 443 {
		t.Fatalf("unexpected matched rule identity: %+v", matched)
	}
}

func TestSet17RuleTelemetryIgnoresOtherPod(t *testing.T) {
	key := make([]byte, 12)
	binary.NativeEndian.PutUint32(key[0:4], 999)
	binary.NativeEndian.PutUint32(key[4:8], ruleMissIndex)
	key[8], key[9] = 1, 0
	value := make([]byte, 8)
	binary.NativeEndian.PutUint64(value, 7)
	doc, _ := json.Marshal([]map[string]any{{"key": bytesJSON(key), "value": bytesJSON(value)}})
	egress, ingress, hits := parseRuleTelemetry(doc, nil, 77)
	if egress != (DirectionStats{}) || ingress != (DirectionStats{}) || len(hits) != 0 {
		t.Fatalf("other pod leaked into telemetry: %+v %+v %+v", egress, ingress, hits)
	}
}
