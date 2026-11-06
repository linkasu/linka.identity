package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/accountbroker"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/installationbroker"
	"github.com/linka-cloud/linka.identity/internal/store"
)

type fakePublicAccounts struct {
	method, credential, id string
	input                  any
	err                    error
	challenge              accountbroker.ChallengeResponse
	registration           accountbroker.Registration
	profile                accountbroker.Profile
}

var _ PublicAccountBroker = (*accountbroker.Broker)(nil)

func (f *fakePublicAccounts) Begin(_ context.Context, credential string, input accountbroker.ChallengeInput) (accountbroker.ChallengeResponse, error) {
	f.method, f.credential, f.input = "begin", credential, input
	return f.challenge, f.err
}

func (f *fakePublicAccounts) Verify(_ context.Context, credential, id string, input accountbroker.VerifyInput) (accountbroker.Registration, error) {
	f.method, f.credential, f.id, f.input = "verify", credential, id, input
	return f.registration, f.err
}

func (f *fakePublicAccounts) Refresh(_ context.Context, credential string) (accountbroker.Registration, error) {
	f.method, f.credential = "refresh", credential
	return f.registration, f.err
}

func (f *fakePublicAccounts) Revoke(_ context.Context, credential string) error {
	f.method, f.credential = "revoke", credential
	return f.err
}

func (f *fakePublicAccounts) UpdateProfile(_ context.Context, credential string, input accountbroker.ProfileInput) (accountbroker.Profile, error) {
	f.method, f.credential, f.input = "profile", credential, input
	return f.profile, f.err
}

func accountHandler(module PublicAccountBroker, logs *bytes.Buffer) http.Handler {
	return New(nil, nil, nil, nil, nil, nil, nil, module, nil, map[string]struct{}{"https://linka.su": {}}, false, time.Minute, slog.New(slog.NewJSONHandler(logs, nil)))
}

func accountRequest(handler http.Handler, method, path, body, credential string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if credential != "" {
		r.Header.Set("Authorization", credential)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestPublicAccountRoutesForwardTypedInputsAndReturnOnlyContract(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	profile := accountbroker.Profile{Product: "plays", AccountKey: "account-alias", Version: 2, HolderRole: "self", Country: "RU", Region: "MOW", UpdatedAt: now}
	registration := accountbroker.Registration{
		ContractVersion: 1, Product: "plays", AccountKey: "account-alias", InstallationKey: "installation-alias", AccountProfile: profile,
		RefreshToken: "refresh-secret", RefreshExpiresAt: now, RegistrationReceipt: "offline-receipt",
	}
	challenge := accountbroker.ChallengeResponse{ContractVersion: 1, ChallengeID: "challenge-id", Status: "pending", ExpiresAt: now, ResendAfter: now}
	for _, tc := range []struct {
		name, method, path, body string
		input                    any
		status                   int
		result                   any
	}{
		{"begin", "POST", "/v1/public/email/challenges", `{"request_id":"request-id","product_id":"plays","email":"private@example.test","purpose":"product_registration","client_nonce":"private-nonce","holder_role":"self"}`, accountbroker.ChallengeInput{RequestID: "request-id", ProductID: "plays", Email: "private@example.test", Purpose: "product_registration", ClientNonce: "private-nonce", HolderRole: "self"}, 202, challenge},
		{"verify", "POST", "/v1/public/email/challenges/bound-challenge-id/verify", `{"product_id":"plays","code":"123456","client_nonce":"private-nonce"}`, accountbroker.VerifyInput{ProductID: "plays", Code: "123456", ClientNonce: "private-nonce"}, 200, registration},
		{"refresh", "POST", "/v1/public/account-sessions/refresh", `{}`, nil, 200, registration},
		{"revoke", "POST", "/v1/public/account-sessions/revoke", `{}`, nil, 200, map[string]bool{"revoked": true}},
		{"profile", "PUT", "/v1/public/account-profile", `{"version":2,"holder_role":"self","country":"RU","region":"MOW"}`, accountbroker.ProfileInput{Version: 2, HolderRole: "self", Country: "RU", Region: "MOW"}, 200, profile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakePublicAccounts{challenge: challenge, registration: registration, profile: profile}
			var logs bytes.Buffer
			w := accountRequest(accountHandler(f, &logs), tc.method, tc.path, tc.body, "Bearer private-credential")
			expected, err := json.Marshal(tc.result)
			if err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.status || w.Body.String() != string(expected)+"\n" {
				t.Fatalf("response = %d %s, want %d %s", w.Code, w.Body, tc.status, expected)
			}
			if f.method != tc.name || f.credential != "private-credential" || !reflect.DeepEqual(f.input, tc.input) {
				t.Fatalf("broker call = %#v", f)
			}
			if tc.name == "verify" && f.id != "bound-challenge-id" {
				t.Fatalf("challenge path not bound: %q", f.id)
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("headers = %v", w.Header())
			}
			if (tc.name == "verify" || tc.name == "refresh") && !strings.Contains(w.Body.String(), `"metrics_token":null`) {
				t.Fatal("missing nullable metrics_token")
			}
			for _, secret := range []string{"private@example.test", "private-credential", "private-nonce", "123456", "refresh-secret", "offline-receipt"} {
				if strings.Contains(logs.String(), secret) {
					t.Fatalf("logs contain secret %q", secret)
				}
			}
			for _, forbidden := range []string{"account_exists", "email", "code", "root_id", "installation_id", "account_id", "subject_id", "identity_id"} {
				if strings.Contains(w.Body.String(), `"`+forbidden+`"`) {
					t.Fatalf("response leaks %q: %s", forbidden, w.Body)
				}
			}
		})
	}
}

var publicAccountRoutes = []struct{ method, path string }{
	{"POST", "/v1/public/email/challenges"},
	{"POST", "/v1/public/email/challenges/id/verify"},
	{"POST", "/v1/public/account-sessions/refresh"},
	{"POST", "/v1/public/account-sessions/revoke"},
	{"PUT", "/v1/public/account-profile"},
}

func TestPublicAccountRejectsInvalidProtocolBeforeBroker(t *testing.T) {
	for _, route := range publicAccountRoutes {
		for _, tc := range []struct {
			name, body, auth, contentType, query string
			status                               int
		}{
			{"missing bearer", `{}`, "", "application/json", "", 401},
			{"basic", `{}`, "Basic secret", "application/json", "", 401},
			{"empty bearer", `{}`, "Bearer ", "application/json", "", 401},
			{"oversized bearer", `{}`, "Bearer " + strings.Repeat("x", 4097), "application/json", "", 401},
			{"bad bearer", `{}`, "Bearer one two", "application/json", "", 401},
			{"query", `{}`, "Bearer secret", "application/json", "?email=private@example.test", 400},
			{"unknown field", `{"unexpected":true}`, "Bearer secret", "application/json", "", 400},
			{"trailing json", `{} {}`, "Bearer secret", "application/json", "", 400},
			{"malformed", `{`, "Bearer secret", "application/json", "", 400},
			{"null", `null`, "Bearer secret", "application/json", "", 400},
			{"array", `[]`, "Bearer secret", "application/json", "", 400},
			{"empty", ``, "Bearer secret", "application/json", "", 400},
			{"oversize", `{}` + strings.Repeat(" ", 4096), "Bearer secret", "application/json", "", 400},
			{"content type", `{}`, "Bearer secret", "text/plain", "", 400},
			{"missing content type", `{}`, "Bearer secret", "", "", 400},
		} {
			t.Run(route.path+"/"+tc.name, func(t *testing.T) {
				f := &fakePublicAccounts{}
				var logs bytes.Buffer
				r := httptest.NewRequest(route.method, route.path+tc.query, strings.NewReader(tc.body))
				r.Header.Set("Content-Type", tc.contentType)
				r.Header.Set("Authorization", tc.auth)
				r.AddCookie(&http.Cookie{Name: "session", Value: "cookie-secret"})
				w := httptest.NewRecorder()
				accountHandler(f, &logs).ServeHTTP(w, r)
				if w.Code != tc.status || f.method != "" || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("response = %d %s, broker = %#v", w.Code, w.Body, f)
				}
				for _, secret := range []string{"private@example.test", "cookie-secret", "Bearer secret"} {
					if strings.Contains(logs.String()+w.Body.String(), secret) {
						t.Fatalf("sensitive value leaked: %q", secret)
					}
				}
			})
		}
	}
}

func TestPublicAccountErrorsAreUniformAndSanitized(t *testing.T) {
	for _, route := range publicAccountRoutes {
		for _, tc := range []struct {
			name   string
			err    error
			status int
			code   string
		}{
			{"installation credential", installationbroker.ErrInvalidCredential, 401, "invalid_credential"},
			{"account credential", accountbroker.ErrAccountCredential, 401, "invalid_credential"},
			{"not found", domain.ErrNotFound, 401, "invalid_credential"},
			{"invalid", domain.ErrInvalid, 400, "invalid_request"},
			{"conflict", domain.ErrConflict, 409, "conflict"},
			{"forbidden", domain.ErrForbidden, 403, "forbidden"},
			{"transport", errors.New("sdk email private@example.test code 123456 JWT private-jwt"), 503, "account_unavailable"},
			{"limit", &store.PublicRateLimitError{RetryAt: time.Now().Add(10 * time.Second)}, 429, "rate_limited"},
		} {
			t.Run(route.path+"/"+tc.name, func(t *testing.T) {
				f := &fakePublicAccounts{err: fmt.Errorf("private-context: %w", tc.err)}
				var logs bytes.Buffer
				w := accountRequest(accountHandler(f, &logs), route.method, route.path, `{}`, "Bearer private-jwt")
				status, code := tc.status, tc.code
				if tc.name == "not found" && strings.HasSuffix(route.path, "/verify") {
					status, code = 400, "challenge_rejected"
				}
				if w.Code != status || w.Body.String() != `{"error":"`+code+`"}`+"\n" || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("response = %d %s", w.Code, w.Body)
				}
				if tc.name == "limit" && w.Header().Get("Retry-After") != "10" {
					t.Fatalf("retry = %q", w.Header().Get("Retry-After"))
				}
				for _, secret := range []string{"private-context", "private@example.test", "123456", "private-jwt"} {
					if strings.Contains(logs.String()+w.Body.String(), secret) {
						t.Fatalf("error leaked %q", secret)
					}
				}
			})
		}
	}
}

func TestPublicAccountRateLimitRetryUsesServerTime(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	s := &Server{now: func() time.Time { return now }}
	for _, tc := range []struct {
		delay time.Duration
		want  string
	}{{1500 * time.Millisecond, "2"}, {0, "1"}, {-time.Minute, "1"}} {
		w := httptest.NewRecorder()
		s.failPublicAccount(w, fmt.Errorf("wrapped: %w", &store.PublicRateLimitError{RetryAt: now.Add(tc.delay)}), false)
		if w.Code != 429 || w.Header().Get("Retry-After") != tc.want {
			t.Fatalf("delay %v: %d %v", tc.delay, w.Code, w.Header())
		}
	}
}

func TestPublicAccountChallengeRejectionsDoNotEnumerate(t *testing.T) {
	for _, reason := range []string{"wrong code", "expired", "nonce mismatch", "consumed", "unknown challenge"} {
		t.Run(reason, func(t *testing.T) {
			f := &fakePublicAccounts{err: fmt.Errorf("%s: %w", reason, domain.ErrNotFound)}
			var logs bytes.Buffer
			w := accountRequest(accountHandler(f, &logs), "POST", "/v1/public/email/challenges/opaque-id/verify", `{"product_id":"plays","code":"123456","client_nonce":"nonce-secret"}`, "Bearer installation-secret")
			if w.Code != 400 || w.Body.String() != "{\"error\":\"challenge_rejected\"}\n" {
				t.Fatalf("response = %d %s", w.Code, w.Body)
			}
			for _, secret := range []string{reason, "123456", "nonce-secret", "installation-secret"} {
				if strings.Contains(logs.String()+w.Body.String(), secret) {
					t.Fatalf("rejection exposes %q", secret)
				}
			}
		})
	}
}

func TestPublicAccountRejectsWrongOriginAndDuplicateAuthorization(t *testing.T) {
	for _, route := range publicAccountRoutes {
		for _, duplicate := range []bool{false, true} {
			f := &fakePublicAccounts{}
			var logs bytes.Buffer
			r := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer secret")
			want := 403
			if duplicate {
				r.Header.Add("Authorization", "Bearer another")
				want = 401
			} else {
				r.Header.Set("Origin", "https://attacker.test")
			}
			w := httptest.NewRecorder()
			accountHandler(f, &logs).ServeHTTP(w, r)
			if w.Code != want || f.method != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%s duplicate=%v: %d %s", route.path, duplicate, w.Code, w.Body)
			}
		}
	}
}

func TestPublicAccountDoesNotTrustIncomingRetryAfter(t *testing.T) {
	f := &fakePublicAccounts{err: &store.PublicRateLimitError{RetryAt: time.Now().Add(-time.Minute)}}
	var logs bytes.Buffer
	r := httptest.NewRequest("POST", "/v1/public/account-sessions/refresh", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer secret")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Retry-After", "999999")
	w := httptest.NewRecorder()
	accountHandler(f, &logs).ServeHTTP(w, r)
	if w.Code != 429 || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("response = %d %v", w.Code, w.Header())
	}
}

func TestPublicAccountRouteFlagsCorsAndMethods(t *testing.T) {
	for _, route := range publicAccountRoutes {
		t.Run(route.path, func(t *testing.T) {
			var logs bytes.Buffer
			for _, method := range []string{route.method, "OPTIONS"} {
				w := accountRequest(accountHandler(nil, &logs), method, route.path, `{}`, "")
				if w.Code != 404 {
					t.Fatalf("disabled route: %d", w.Code)
				}
			}
			for _, origin := range []string{"", "https://linka.su", "https://linka.su.attacker.test", "null"} {
				f := &fakePublicAccounts{}
				r := httptest.NewRequest("OPTIONS", route.path, nil)
				r.Header.Set("Origin", origin)
				w := httptest.NewRecorder()
				accountHandler(f, &logs).ServeHTTP(w, r)
				want := 204
				if origin != "" && origin != "https://linka.su" {
					want = 403
				}
				if w.Code != want || f.method != "" || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("origin %q: %d %s", origin, w.Code, w.Body)
				}
				if origin == "https://linka.su" && (w.Header().Get("Access-Control-Allow-Origin") != origin || w.Header().Get("Access-Control-Allow-Credentials") != "") {
					t.Fatalf("cors headers = %v", w.Header())
				}
			}
			f := &fakePublicAccounts{}
			handler := accountHandler(f, &logs)
			preflight := accountRequest(handler, "OPTIONS", route.path+"?unexpected=true", "", "")
			if preflight.Code != 400 || f.method != "" {
				t.Fatalf("preflight query: %d", preflight.Code)
			}
			w := accountRequest(handler, "GET", route.path, `{}`, "Bearer secret")
			if w.Code != 405 || f.method != "" {
				t.Fatalf("wrong method: %d", w.Code)
			}
			w = accountRequest(handler, route.method, route.path+"/unknown", `{}`, "Bearer secret")
			if w.Code != 404 || f.method != "" {
				t.Fatalf("unknown route: %d", w.Code)
			}
		})
	}
}
