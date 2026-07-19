package httpapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/authz"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/token"
)

func TestUnauthorizedEmailRequestDoesNotLogBodyOrAuthorization(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	signer, err := token.NewSigner(bytes.Repeat([]byte{1}, 32), "test-key", "test-issuer", time.Minute, time.Minute)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	authenticator, err := authz.New([]authz.Workload{{
		ID: "plays", Token: strings.Repeat("i", 32), Roles: []authz.Role{authz.RoleProduct}, Products: []string{"plays"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	pairwiseIDs, err := pairwise.New([]byte(strings.Repeat("p", 32)))
	if err != nil {
		t.Fatal(err)
	}
	handler := New(nil, nil, signer, authenticator, pairwiseIDs, map[string]string{"plays": "metric"}, nil, nil, false, time.Minute, logger)
	body := `{"product_id":"plays","email":"secret@example.test"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/email-identities?email=also-secret", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer wrong-secret-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", response.Code, http.StatusUnauthorized)
	}
	for _, forbidden := range []string{"secret@example.test", "also-secret", "wrong-secret-token", body} {
		if strings.Contains(logs.String(), forbidden) {
			t.Fatalf("logs contain sensitive value %q: %s", forbidden, logs.String())
		}
	}
}

func TestPublicRouteUsesExactOriginAllowlist(t *testing.T) {
	server := &Server{publicOrigins: map[string]struct{}{"https://linka.su": {}}, publicRequestLimit: newTokenBucket(10, time.Second)}
	handler := server.public(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	allowed := httptest.NewRequest(http.MethodOptions, "/v1/public/installations", nil)
	allowed.Header.Set("Origin", "https://linka.su")
	allowedResponse := httptest.NewRecorder()
	handler.ServeHTTP(allowedResponse, allowed)
	if allowedResponse.Code != http.StatusNoContent || allowedResponse.Header().Get("Access-Control-Allow-Origin") != "https://linka.su" {
		t.Fatalf("allowed response = %d %#v", allowedResponse.Code, allowedResponse.Header())
	}

	denied := httptest.NewRequest(http.MethodOptions, "/v1/public/installations", nil)
	denied.Header.Set("Origin", "https://attacker.example")
	deniedResponse := httptest.NewRecorder()
	handler.ServeHTTP(deniedResponse, denied)
	if deniedResponse.Code != http.StatusForbidden || deniedResponse.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("denied response = %d %#v", deniedResponse.Code, deniedResponse.Header())
	}
}

func TestPublicRegistrationLimiterRefills(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	limiter := newTokenBucket(2, 10*time.Second)
	limiter.now = func() time.Time { return now }
	limiter.last = now
	if !limiter.Allow() || !limiter.Allow() || limiter.Allow() {
		t.Fatal("unexpected initial token bucket state")
	}
	now = now.Add(10 * time.Second)
	if !limiter.Allow() || limiter.Allow() {
		t.Fatal("token bucket did not refill exactly one token")
	}
}
