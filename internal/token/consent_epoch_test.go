package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestConsentEpochExactUint64AndLegacyOmission(t *testing.T) {
	signer, err := NewSigner(bytes.Repeat([]byte{1}, 32), "test", "issuer", time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, epoch := range []uint64{0, 1, 7, ^uint64(0)} {
		encoded, _, err := signer.SignClaims(SignInput{Audience: "metric", Product: "linka-pokazhi", Subject: strings.Repeat("a", 64),
			SubjectType: "installation", Scopes: []string{"telemetry:write"}, ConsentEpoch: epoch})
		if err != nil {
			t.Fatal(err)
		}
		claims, err := signer.VerifyForTest(encoded)
		if err != nil || claims.ConsentEpoch != epoch {
			t.Fatal("signed epoch lost uint64 precision")
		}
		payload, err := base64.RawURLEncoding.DecodeString(strings.Split(encoded, ".")[1])
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(payload, &fields); err != nil {
			t.Fatal(err)
		}
		if _, present := fields["consent_epoch"]; present != (epoch > 0) {
			t.Fatal("legacy epoch was not omitted")
		}
	}
}
