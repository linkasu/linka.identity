package installationbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/store"
)

type ManagedPreferenceFields struct {
	Version       uint64       `json:"version"`
	ConsentEpoch  uint64       `json:"consent_epoch"`
	DeliveryState string       `json:"delivery_state"`
	MetricsToken  *AccessToken `json:"metrics_token"`
}

var millisecondTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$`)

func (input *PreferenceInput) UnmarshalJSON(data []byte) error {
	type plain PreferenceInput
	var value plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	_, requestPresent := fields["request_id"]
	_, versionPresent := fields["expected_version"]
	if requestPresent || versionPresent {
		if value.RequestID == nil || value.ExpectedVersion == nil {
			return domain.ErrInvalid
		}
		keys := map[string]bool{}
		fieldDecoder := json.NewDecoder(bytes.NewReader(data))
		_, _ = fieldDecoder.Token()
		for fieldDecoder.More() {
			key, err := fieldDecoder.Token()
			if err != nil || keys[key.(string)] {
				return domain.ErrInvalid
			}
			keys[key.(string)] = true
			var raw json.RawMessage
			if err := fieldDecoder.Decode(&raw); err != nil {
				return err
			}
		}
		var recorded string
		if err := json.Unmarshal(fields["recorded_at"], &recorded); err != nil || !millisecondTimestamp.MatchString(recorded) {
			return domain.ErrInvalid
		}
	}
	*input = PreferenceInput(value)
	return nil
}

func (response PreferenceResponse) MarshalJSON() ([]byte, error) {
	type plain PreferenceResponse
	if response.ManagedPreferenceFields == nil {
		return json.Marshal(plain(response))
	}
	return json.Marshal(struct {
		plain
		RecordedAt string `json:"recorded_at"`
	}{plain(response), response.RecordedAt.UTC().Format("2006-01-02T15:04:05.000Z")})
}

func (b *Broker) setVersionedPreference(ctx context.Context, credential string, input PreferenceInput) (PreferenceResponse, error) {
	if input.RequestID == nil || input.ExpectedVersion == nil || !domain.ValidUUID(*input.RequestID) || *input.ExpectedVersion == 0 ||
		(input.Preference != "allowed" && input.Preference != "denied") || !b.validConsentPolicy(input.PolicyVersion) ||
		input.RecordedAt.Before(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) || !input.RecordedAt.Before(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		input.RecordedAt.After(b.now().UTC().Add(5*time.Minute)) || input.RecordedAt.Nanosecond()%int(time.Millisecond) != 0 {
		return PreferenceResponse{}, domain.ErrInvalid
	}
	authenticated, err := b.authenticate(ctx, credential)
	if err != nil {
		return PreferenceResponse{}, err
	}
	if input.PolicyVersion != authenticated.policyVersion {
		return PreferenceResponse{}, domain.ErrConflict
	}
	state, err := b.repository.SetInstallationConsent(ctx, store.InstallationConsentDecision{
		Subject: store.Subject{Kind: "installation", ID: authenticated.alias.SubjectID}, SubjectKey: authenticated.alias.OpaqueKey,
		ProductID: authenticated.productID, RequestID: *input.RequestID, ExpectedVersion: *input.ExpectedVersion,
		Preference: input.Preference, PolicyVersion: input.PolicyVersion, RecordedAt: input.RecordedAt.UTC(),
	})
	if err != nil {
		return PreferenceResponse{}, err
	}
	return b.consentResponse(authenticated, state)
}

func (b *Broker) validConsentPolicy(policy string) bool {
	if policy == b.config.PolicyVersion {
		return true
	}
	for _, product := range b.config.Products {
		if _, ok := product.AdditionalPolicies[policy]; ok {
			return true
		}
	}
	return false
}

func (b *Broker) GetPreference(ctx context.Context, credential string) (PreferenceResponse, error) {
	authenticated, err := b.authenticate(ctx, credential)
	if err != nil {
		return PreferenceResponse{}, err
	}
	state, err := b.repository.GetInstallationConsent(ctx, store.Subject{Kind: "installation", ID: authenticated.alias.SubjectID}, authenticated.productID)
	if err != nil {
		return PreferenceResponse{}, err
	}
	return b.consentResponse(authenticated, state)
}

func (b *Broker) consentResponse(authenticated authenticatedInstallation, state store.InstallationConsent) (PreferenceResponse, error) {
	policy := state.PolicyVersion
	if policy == "" {
		policy = authenticated.policyVersion
	}
	result := PreferenceResponse{InstallationKey: authenticated.alias.OpaqueKey, Product: authenticated.productID,
		Preference: state.Preference, PolicyVersion: policy, RecordedAt: state.RecordedAt,
		ManagedPreferenceFields: &ManagedPreferenceFields{Version: state.Version, ConsentEpoch: state.ConsentEpoch, DeliveryState: state.DeliveryState}}
	if state.ConsentEpoch > 0 && state.Preference == "allowed" && !state.Suppressed && state.DeliveryState == "completed" {
		access, err := b.issueEpochAccess(authenticated.productID, authenticated.audience, authenticated.alias.OpaqueKey, state.ConsentEpoch)
		if err != nil {
			return PreferenceResponse{}, err
		}
		result.MetricsToken = &access
	}
	return result, nil
}
