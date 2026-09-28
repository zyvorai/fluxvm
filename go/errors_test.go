// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package fluxvm

import (
	"errors"
	"testing"
)

func TestUnknownVMAnswered400IsNotFound(t *testing.T) {
	e := &APIError{Status: 400, Message: "VM not found"}
	if !errors.Is(e, ErrNotFound) {
		t.Fatalf("400 %q should match ErrNotFound", e.Message)
	}
	if errors.Is(&APIError{Status: 400, Message: "bad path"}, ErrNotFound) {
		t.Fatal("an ordinary 400 must not match ErrNotFound")
	}
}
