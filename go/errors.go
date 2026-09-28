// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package fluxvm

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors for use with errors.Is.
var (
	// ErrAuth matches a 401 or 403 response (403 is a kind of auth failure).
	ErrAuth = errors.New("fluxvm: authentication failed")
	// ErrForbidden matches a 403 response: the token is valid but its role
	// cannot call this route. Guest-reaching sandbox routes need an admin token.
	ErrForbidden = errors.New("fluxvm: forbidden")
	// ErrNotFound matches a 404 response. The API also answers 404 for another
	// tenant's sandbox id, and for /changes when no baseline exists.
	ErrNotFound = errors.New("fluxvm: not found")
	// ErrRateLimited matches a 429 response; see APIError.RetryAfter.
	ErrRateLimited = errors.New("fluxvm: rate limited")
	// ErrTimeout matches a request that hit the client-side timeout or a
	// context deadline. It also matches context.DeadlineExceeded.
	ErrTimeout = errors.New("fluxvm: request timed out")
	// ErrConnection matches a failure to reach the API (refused, DNS, TLS...).
	ErrConnection = errors.New("fluxvm: connection failed")
	// ErrFileTooLarge is returned by WriteFile for data above MaxFileTransferBytes.
	ErrFileTooLarge = errors.New("fluxvm: file exceeds the guest agent transfer limit")
)

// APIError is a non-success answer from the API. Message is the server's
// {"error": "..."} text when the body had that shape, otherwise the raw body.
// The server maps most handler failures (validation, guest-agent errors) to 400.
type APIError struct {
	Status  int
	Message string
	// Body is the raw response body.
	Body []byte
	// RetryAfter is the server's Retry-After for a 429; zero when absent.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("fluxvm: HTTP %d: %s", e.Status, e.Message)
}

// Is makes errors.Is(err, ErrAuth|ErrForbidden|ErrNotFound|ErrRateLimited)
// work on an *APIError according to its status.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrAuth:
		return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
	case ErrForbidden:
		return e.Status == http.StatusForbidden
	case ErrNotFound:
		// GET/DELETE /v1/vms/{id} answer an unknown VM with 400 "VM not found".
		return e.Status == http.StatusNotFound ||
			(e.Status == http.StatusBadRequest && strings.EqualFold(strings.TrimSpace(e.Message), "vm not found"))
	case ErrRateLimited:
		return e.Status == http.StatusTooManyRequests
	}
	return false
}

func newAPIError(status int, header http.Header, body []byte) *APIError {
	e := &APIError{Status: status, Message: string(body), Body: body}
	var parsed struct {
		Error *string `json:"error"`
	}
	if json.Unmarshal(body, &parsed) == nil && parsed.Error != nil {
		e.Message = *parsed.Error
	}
	if status == http.StatusTooManyRequests {
		if v := header.Get("Retry-After"); v != "" {
			if secs, err := strconv.ParseFloat(v, 64); err == nil && secs >= 0 {
				e.RetryAfter = time.Duration(secs * float64(time.Second))
			}
		}
	}
	return e
}
