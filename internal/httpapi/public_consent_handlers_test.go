package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/installationbroker"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

func TestGetPublicConsentNoBodyOrQuery(t *testing.T) {
	signer, _ := token.NewSigner(bytes.Repeat([]byte{1}, 32), "test", "issuer", time.Minute, time.Minute)
	generator, _ := pairwise.New(bytes.Repeat([]byte{2}, 32))
	root, product := "11111111-1111-4111-8111-111111111111", "linka-pokazhi"
	key := generator.Subject(product, "metric", "installation", root)
	repository := &refreshTestRepository{alias: store.ResolvedAlias{OpaqueKey: key, ProductID: product, Audience: "metric", SubjectType: "installation", SubjectID: root}, preference: "unknown"}
	broker, err := installationbroker.New(repository, signer, generator, installationbroker.Config{Products: map[string]installationbroker.Product{product: {Audience: "metric"}},
		RegistrationProducts: map[string]struct{}{product: {}}, PolicyVersion: "base2026-07-19-v3", RefreshTTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	credential, _, _ := signer.SignRefresh(product, key, "base2026-07-19-v3", 24*time.Hour)
	handler := New(nil, nil, signer, nil, generator, nil, broker, nil, nil, nil, false, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	path := "/v1/public/installations/telemetry-preference"
	for _, test := range []struct {
		path, body, bearer string
		want               int
	}{
		{path, "", credential, 200}, {path + "?preference=allowed", "", credential, 400}, {path + "?", "", credential, 400},
		{path, "{}", credential, 400}, {path, " ", credential, 400}, {path, "", "invalid", 401}, {path, "", "", 401},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, strings.NewReader(test.body))
		if test.bearer != "" {
			request.Header.Set("Authorization", "Bearer "+test.bearer)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Fatalf("GET status %d, want %d", response.Code, test.want)
		}
		if test.want == 200 {
			var body map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 9 || string(body["version"]) != "1" || string(body["consent_epoch"]) != "0" || string(body["metrics_token"]) != "null" || string(body["delivery_state"]) != `"completed"` || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("incorrect unmanaged GET contract")
			}
		}
	}
}
