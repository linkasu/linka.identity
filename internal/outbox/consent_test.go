package outbox

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

type consentTransport func(*http.Request) (*http.Response, error)

func (f consentTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestConsentDeliveryRouteScopeAndAcknowledgement(t *testing.T) {
	signer, _ := token.NewSigner(bytes.Repeat([]byte{1}, 32), "test", "https://identity.test", time.Minute, time.Minute)
	worker := New(nil, "https://metrics.test/v2/privacy/requests", signer, map[string]string{"linka-pokazhi": "metric"}, time.Second, 3, nil)
	id := "11111111-1111-4111-8111-111111111111"
	event := store.OutboxEvent{ID: id, Topic: "telemetry.consent.changed", Payload: json.RawMessage(`{"schema_version":2,"request_id":"` + id + `","scope":{"product":"linka-pokazhi","subject_key":"stable-alias"},"consent_epoch":3,"version":8,"preference":"allowed","recorded_at":"2026-11-08T00:00:00.000Z"}`)}
	worker.client.Transport = consentTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://metrics.test/v2/consents" || r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") != id {
			t.Fatal("incorrect control delivery route")
		}
		claims, err := signer.VerifyForTest(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if err != nil || claims.Subject != "stable-alias" || claims.SubjectType != "service" || claims.Audience != "metric" || claims.Product != "linka-pokazhi" || len(claims.Scopes) != 1 || claims.Scopes[0] != "consent:write" {
			t.Fatal("incorrect control JWT authority")
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, event.Payload) {
			t.Fatal("control payload changed in transport")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"request_id":"` + id + `","status":"completed"}`))}, nil
	})
	if _, err := worker.deliver(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	if worker.client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects allowed")
	}
	for _, configured := range []string{"http://metrics.test/v2/privacy/requests", "https://metrics.test/other", "https://user:pass@metrics.test/v2/privacy/requests", "https://metrics.test/v2/privacy/requests?secret=x", "https://metrics.test/v2/privacy/requests#fragment"} {
		if _, _, err := deliveryTarget(configured, event.Topic); err == nil {
			t.Fatal("unsafe consent target accepted")
		}
	}
	target, scope, err := deliveryTarget(worker.url, "telemetry.deletion.requested")
	if err != nil || target != worker.url || scope != "privacy:write" {
		t.Fatal("legacy privacy delivery changed")
	}
}
