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

	"github.com/linka-cloud/linka.identity/internal/authz"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/productdirectory"
)

type fakeProductDirectory struct {
	method    string
	principal authz.Principal
	input     any
	page      productdirectory.Page
	checks    productdirectory.Checks
	err       error
}

var _ ProductDirectory = (*productdirectory.Directory)(nil)

func (f *fakeProductDirectory) Query(_ context.Context, p authz.Principal, input productdirectory.QueryInput) (productdirectory.Page, error) {
	f.method, f.principal, f.input = "query", p, input
	if input.ProductID != "" && !p.AllowsProduct(input.ProductID) {
		return productdirectory.Page{}, domain.ErrForbidden
	}
	return f.page, f.err
}

func (f *fakeProductDirectory) Check(_ context.Context, p authz.Principal, input productdirectory.CheckInput) (productdirectory.Checks, error) {
	f.method, f.principal, f.input = "check", p, input
	if input.ProductID != "" && !p.AllowsProduct(input.ProductID) {
		return productdirectory.Checks{}, domain.ErrForbidden
	}
	return f.checks, f.err
}

func directoryHandler(t *testing.T, module ProductDirectory, logs *bytes.Buffer) http.Handler {
	t.Helper()
	authenticator, err := authz.New([]authz.Workload{
		{ID: "crm-reader", Token: strings.Repeat("d", 32), Roles: []authz.Role{authz.RoleProductDirectoryRead}, Products: []string{"plays"}},
		{ID: "product-only", Token: strings.Repeat("p", 32), Roles: []authz.Role{authz.RoleProduct}, Products: []string{"plays"}},
		{ID: "identity-admin", Token: strings.Repeat("a", 32), Roles: []authz.Role{authz.RoleIdentityAdmin}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(nil, nil, nil, authenticator, nil, nil, nil, nil, module, nil, false, time.Minute, slog.New(slog.NewJSONHandler(logs, nil)))
}

func TestProductDirectoryReturnsTypedContractAndAuthenticatedPrincipal(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	page := productdirectory.Page{ContractVersion: 1, Product: "plays", Entries: []productdirectory.Entry{{AccountKey: "account-alias", ContactReference: "private-capability", Email: "private@example.test", Origin: "identity_product_registration", VerifiedAt: now}}, NextCursor: "private-cursor", DataAsOf: now}
	checks := productdirectory.Checks{ContractVersion: 1, Product: "plays", Results: []productdirectory.CheckResult{{ContactReference: "private-capability", AccountKey: "account-alias", State: "active"}}, CheckedAt: now}
	for _, tc := range []struct {
		method, body  string
		input, result any
	}{
		{"query", `{"product_id":"plays","cursor":"private-cursor","limit":12}`, productdirectory.QueryInput{ProductID: "plays", Cursor: "private-cursor", Limit: 12}, page},
		{"check", `{"product_id":"plays","references":["private-capability"]}`, productdirectory.CheckInput{ProductID: "plays", References: []string{"private-capability"}}, checks},
	} {
		t.Run(tc.method, func(t *testing.T) {
			f := &fakeProductDirectory{page: page, checks: checks}
			var logs bytes.Buffer
			r := httptest.NewRequest("POST", "/v1/internal/product-directory/"+tc.method, strings.NewReader(tc.body))
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("d", 32))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "https://linka.su")
			r.Header.Set("X-Workload-ID", "forged-workload")
			r = r.WithContext(context.WithValue(r.Context(), principalKey, authz.Principal{ID: "forged-context"}))
			w := httptest.NewRecorder()
			directoryHandler(t, f, &logs).ServeHTTP(w, r)
			want, err := json.Marshal(tc.result)
			if err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || w.Body.String() != string(want)+"\n" {
				t.Fatalf("response = %d %s", w.Code, w.Body)
			}
			if f.method != tc.method || !reflect.DeepEqual(f.input, tc.input) || f.principal.ID != "crm-reader" || !f.principal.Has(authz.RoleProductDirectoryRead) || f.principal.Has(authz.RoleProduct) || !f.principal.AllowsProduct("plays") || f.principal.AllowsProduct("other") {
				t.Fatalf("unexpected module call: %#v", f)
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("headers = %v", w.Header())
			}
			if tc.method == "check" && strings.Contains(w.Body.String(), "email") {
				t.Fatalf("check exposed email: %s", w.Body)
			}
			for _, key := range []string{"root_id", "account_id", "installation_id", "subject_id", "email_identity_id", "subject_root_id"} {
				if strings.Contains(w.Body.String(), `"`+key+`"`) {
					t.Fatalf("response exposed %q", key)
				}
			}
			for _, secret := range []string{"private@example.test", "private-capability", "private-cursor", strings.Repeat("d", 32)} {
				if strings.Contains(logs.String(), secret) {
					t.Fatalf("logs exposed %q", secret)
				}
			}
		})
	}
}

func TestProductDirectoryRequiresExplicitWorkloadRole(t *testing.T) {
	for _, method := range []string{"query", "check"} {
		for _, tc := range []struct {
			name, credential string
			status           int
		}{
			{"cookie only", "", 401},
			{"invalid", "Bearer wrong-workload-token", 401},
			{"basic", "Basic " + strings.Repeat("d", 32), 401},
			{"public jwt", "Bearer eyJhbGciOiJFZERTQSJ9.public-account.signature", 401},
			{"product role", "Bearer " + strings.Repeat("p", 32), 403},
			{"identity admin", "Bearer " + strings.Repeat("a", 32), 403},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				f := &fakeProductDirectory{}
				var logs bytes.Buffer
				r := httptest.NewRequest("POST", "/v1/internal/product-directory/"+method, strings.NewReader(`{"product_id":"plays"}`))
				r.Header.Set("Authorization", tc.credential)
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(&http.Cookie{Name: "session", Value: strings.Repeat("d", 32)})
				w := httptest.NewRecorder()
				directoryHandler(t, f, &logs).ServeHTTP(w, r)
				if w.Code != tc.status || f.method != "" || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("response = %d %s, module = %#v", w.Code, w.Body, f)
				}
				if strings.Contains(logs.String(), strings.Repeat("d", 32)) || (tc.credential != "" && strings.Contains(logs.String(), tc.credential)) {
					t.Fatal("logs exposed credential")
				}
			})
		}
	}
}

func TestProductDirectoryRejectsProtocolBeforeModule(t *testing.T) {
	for _, method := range []string{"query", "check"} {
		for _, tc := range []struct{ name, body, contentType, query string }{
			{"raw query", `{}`, "application/json", "?email=private@example.test"},
			{"unknown field", `{"email":"private@example.test"}`, "application/json", ""},
			{"forged principal", `{"principal":{"id":"forged"}}`, "application/json", ""},
			{"trailing json", `{} {}`, "application/json", ""},
			{"malformed", `{`, "application/json", ""},
			{"empty", ``, "application/json", ""},
			{"null", `null`, "application/json", ""},
			{"array", `[]`, "application/json", ""},
			{"oversize", `{}` + strings.Repeat(" ", maxRequestBody), "application/json", ""},
			{"missing content type", `{}`, "", ""},
			{"wrong content type", `{}`, "text/plain", ""},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				f := &fakeProductDirectory{}
				var logs bytes.Buffer
				r := httptest.NewRequest("POST", "/v1/internal/product-directory/"+method+tc.query, strings.NewReader(tc.body))
				r.Header.Set("Authorization", "Bearer "+strings.Repeat("d", 32))
				r.Header.Set("Content-Type", tc.contentType)
				w := httptest.NewRecorder()
				directoryHandler(t, f, &logs).ServeHTTP(w, r)
				if w.Code != 400 || w.Body.String() != "{\"error\":\"invalid_request\"}\n" || f.method != "" || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("response = %d %s, module = %#v", w.Code, w.Body, f)
				}
				if strings.Contains(logs.String(), "private@example.test") {
					t.Fatal("logs exposed email")
				}
			})
		}
	}
}

func TestProductDirectoryMapsErrorsWithoutSensitiveDetails(t *testing.T) {
	for _, method := range []string{"query", "check"} {
		for _, tc := range []struct {
			name   string
			err    error
			status int
			code   string
		}{
			{"invalid", domain.ErrInvalid, 400, "invalid_request"},
			{"forbidden", domain.ErrForbidden, 403, "forbidden"},
			{"conflict", domain.ErrConflict, 409, "conflict"},
			{"not found", domain.ErrNotFound, 503, "directory_unavailable"},
			{"transport", errors.New("sdk private@example.test private-capability private-cursor"), 503, "directory_unavailable"},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				f := &fakeProductDirectory{err: fmt.Errorf("private-context: %w", tc.err)}
				var logs bytes.Buffer
				w := accountRequest(directoryHandler(t, f, &logs), "POST", "/v1/internal/product-directory/"+method, `{"product_id":"plays"}`, "Bearer "+strings.Repeat("d", 32))
				if w.Code != tc.status || w.Body.String() != `{"error":"`+tc.code+`"}`+"\n" || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("response = %d %s", w.Code, w.Body)
				}
				for _, secret := range []string{"private@example.test", "private-capability", "private-cursor", "private-context"} {
					if strings.Contains(logs.String()+w.Body.String(), secret) {
						t.Fatalf("error exposed %q", secret)
					}
				}
			})
		}
	}
}

func TestProductDirectoryUsesFullInternalBodyLimit(t *testing.T) {
	for _, method := range []string{"query", "check"} {
		for _, size := range []int{maxPublicRequestBody + 1, maxRequestBody} {
			f := &fakeProductDirectory{}
			var logs bytes.Buffer
			body := `{}` + strings.Repeat(" ", size-2)
			w := accountRequest(directoryHandler(t, f, &logs), "POST", "/v1/internal/product-directory/"+method, body, "Bearer "+strings.Repeat("d", 32))
			if w.Code != 200 || f.method != method {
				t.Fatalf("%s %d bytes: %d %s", method, size, w.Code, w.Body)
			}
		}
	}
}

func TestProductDirectoryProductScopeAndRouteFlag(t *testing.T) {
	for _, method := range []string{"query", "check"} {
		t.Run(method, func(t *testing.T) {
			path := "/v1/internal/product-directory/" + method
			var logs bytes.Buffer
			f := &fakeProductDirectory{}
			w := accountRequest(directoryHandler(t, f, &logs), "POST", path, `{"product_id":"other"}`, "Bearer "+strings.Repeat("d", 32))
			if w.Code != 403 || f.method != method || f.principal.ID != "crm-reader" || f.principal.AllowsProduct("other") {
				t.Fatalf("cross-product request = %d %s, module = %#v", w.Code, w.Body, f)
			}
			w = accountRequest(directoryHandler(t, nil, &logs), "POST", path, `{}`, "Bearer "+strings.Repeat("d", 32))
			if w.Code != 404 {
				t.Fatalf("disabled route = %d", w.Code)
			}
			for _, verb := range []string{"GET", "OPTIONS"} {
				w = accountRequest(directoryHandler(t, f, &logs), verb, path, `{}`, "")
				if w.Code != 405 || w.Header().Get("Access-Control-Allow-Origin") != "" {
					t.Fatalf("%s response = %d %v", verb, w.Code, w.Header())
				}
			}
		})
	}
}
