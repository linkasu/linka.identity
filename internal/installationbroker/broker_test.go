package installationbroker

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/store"
	"github.com/linka-cloud/linka.identity/internal/token"
)

func TestBrokerRegistrationRefreshAndDenial(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repository := newFakeRepository()
	signer, err := token.NewSigner(bytes.Repeat([]byte{1}, 32), "active", "https://identity.test", 5*time.Minute, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pairwiseIDs, err := pairwise.New([]byte(strings.Repeat("p", 32)))
	if err != nil {
		t.Fatal(err)
	}
	broker, err := New(repository, signer, pairwiseIDs, Config{
		Products:             map[string]Product{"linka-plays": {Audience: "linka-plays-metric"}},
		RegistrationProducts: map[string]struct{}{"linka-plays": {}},
		PolicyVersion:        "2026-07-19-v3", RefreshTTL: 180 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker.now = func() time.Time { return now }
	recordedAt := now.Add(123 * time.Nanosecond)

	registered, err := broker.Register(context.Background(), RegisterInput{
		RequestID: "11111111-1111-4111-8111-111111111111",
		ProductID: "linka-plays", Platform: "windows", Preference: "allowed",
		PolicyVersion: "2026-07-19-v3", RecordedAt: recordedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pairwise.Valid(registered.InstallationKey) || registered.MetricsToken == nil || registered.RefreshToken == "" {
		t.Fatalf("registration = %#v", registered)
	}
	replayed, err := broker.Register(context.Background(), RegisterInput{
		RequestID: "11111111-1111-4111-8111-111111111111",
		ProductID: "linka-plays", Platform: "windows", Preference: "allowed",
		PolicyVersion: "2026-07-19-v3", RecordedAt: recordedAt,
	})
	if err != nil || replayed.InstallationKey != registered.InstallationKey || repository.registrations != 1 || registered.RecordedAt.Nanosecond()%1000 != 0 {
		t.Fatalf("registration replay = %#v registrations=%d err=%v", replayed, repository.registrations, err)
	}
	refreshClaims, err := signer.VerifyRefresh(registered.RefreshToken)
	if err != nil || refreshClaims.Subject != registered.InstallationKey || refreshClaims.Audience != token.RefreshAudience {
		t.Fatalf("refresh claims = %#v, err = %v", refreshClaims, err)
	}
	accessClaims, err := signer.VerifyForTest(registered.MetricsToken.AccessToken)
	if err != nil || accessClaims.Audience != "linka-plays-metric" || accessClaims.Scopes[0] != "telemetry:write" {
		t.Fatalf("access claims = %#v, err = %v", accessClaims, err)
	}
	if strings.Contains(registered.RefreshToken, repository.installation.ID) || strings.Contains(registered.MetricsToken.AccessToken, repository.installation.ID) {
		t.Fatal("a root installation ID leaked into a token")
	}
	if _, err := broker.Refresh(context.Background(), registered.RefreshToken); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	broker.config.PolicyVersion = "2026-08-01-v4"
	denied, err := broker.SetPreference(context.Background(), registered.RefreshToken, PreferenceInput{
		Preference: "denied", PolicyVersion: "2026-07-19-v3", RecordedAt: now.Add(time.Minute),
	})
	if err != nil || denied.Preference != "denied" || repository.suppressions != 1 {
		t.Fatalf("denial = %#v, suppressions = %d, err = %v", denied, repository.suppressions, err)
	}
	if _, err := broker.Refresh(context.Background(), registered.RefreshToken); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("refresh after denial error = %v", err)
	}
	if _, err := broker.SetPreference(context.Background(), registered.RefreshToken, PreferenceInput{
		Preference: "denied", PolicyVersion: "2026-07-19-v3", RecordedAt: now.Add(time.Minute),
	}); err != nil || repository.suppressions != 1 {
		t.Fatalf("replayed denial suppressions = %d, err = %v", repository.suppressions, err)
	}
}

func TestBrokerRejectsUnregisteredProductAndUnsafeReenable(t *testing.T) {
	now := time.Now().UTC()
	repository := newFakeRepository()
	signer, _ := token.NewSigner(bytes.Repeat([]byte{1}, 32), "active", "issuer", time.Minute, 15*time.Minute)
	pairwiseIDs, _ := pairwise.New([]byte(strings.Repeat("p", 32)))
	broker, _ := New(repository, signer, pairwiseIDs, Config{
		Products: map[string]Product{"linka-plays": {Audience: "metric"}}, RegistrationProducts: map[string]struct{}{"linka-plays": {}},
		PolicyVersion: "v3", RefreshTTL: 24 * time.Hour,
	})
	broker.now = func() time.Time { return now }
	if _, err := broker.Register(context.Background(), RegisterInput{
		RequestID: "22222222-2222-4222-8222-222222222222",
		ProductID: "linka-looks", Platform: "windows", Preference: "allowed", PolicyVersion: "v3", RecordedAt: now,
	}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("unknown product error = %v", err)
	}
	if _, err := broker.SetPreference(context.Background(), "invalid", PreferenceInput{
		Preference: "allowed", PolicyVersion: "v3", RecordedAt: now,
	}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("same-subject re-enable error = %v", err)
	}
}

func TestBrokerDoesNotMaskRepositoryFailures(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repository := newFakeRepository()
	signer, _ := token.NewSigner(bytes.Repeat([]byte{1}, 32), "active", "issuer", time.Minute, 15*time.Minute)
	pairwiseIDs, _ := pairwise.New([]byte(strings.Repeat("p", 32)))
	broker, _ := New(repository, signer, pairwiseIDs, Config{
		Products: map[string]Product{"linka-plays": {Audience: "metric"}}, RegistrationProducts: map[string]struct{}{"linka-plays": {}},
		PolicyVersion: "v3", RefreshTTL: 24 * time.Hour,
	})
	broker.now = func() time.Time { return now }
	registered, err := broker.Register(context.Background(), RegisterInput{
		RequestID: "33333333-3333-4333-8333-333333333333",
		ProductID: "linka-plays", Platform: "windows", Preference: "allowed", PolicyVersion: "v3", RecordedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository.aliasErr = errors.New("temporary YDB failure")
	if _, err := broker.Refresh(context.Background(), registered.RefreshToken); err == nil || errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("alias failure was masked: %v", err)
	}
	repository.aliasErr = nil
	repository.preferenceErr = errors.New("temporary YDB failure")
	if _, err := broker.Refresh(context.Background(), registered.RefreshToken); err == nil || errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("preference failure was masked: %v", err)
	}
}

type fakeRepository struct {
	installation  store.Installation
	aliases       map[string]store.ResolvedAlias
	preferences   map[string]store.TelemetryPreference
	suppressions  int
	aliasErr      error
	preferenceErr error
	registrations int
}

func newFakeRepository() *fakeRepository {
	return &fakeRepository{aliases: make(map[string]store.ResolvedAlias), preferences: make(map[string]store.TelemetryPreference)}
}

func (f *fakeRepository) RegisterPublicInstallation(_ context.Context, input store.PublicInstallationRegistration) (store.Installation, error) {
	if f.installation.ID == input.Installation.ID {
		return f.installation, nil
	}
	input.Installation.CreatedAt = time.Now().UTC()
	f.installation = input.Installation
	f.registrations++
	f.aliases[input.OpaqueKey] = store.ResolvedAlias{
		OpaqueKey: input.OpaqueKey, ProductID: input.Installation.ProductID, Audience: input.Audience,
		SubjectType: "installation", SubjectID: input.Installation.ID,
	}
	f.preferences["installation\x00"+input.Installation.ID+"\x00"+input.Installation.ProductID] = store.TelemetryPreference{
		Preference: input.Preference, RecordedAt: input.PreferenceAt,
	}
	if input.Preference == "denied" {
		f.suppressions++
	}
	return input.Installation, nil
}

func (f *fakeRepository) DenyPublicInstallation(_ context.Context, input store.PublicTelemetryDenial) (time.Time, error) {
	key := input.Subject.Kind + "\x00" + input.Subject.ID + "\x00" + input.ProductID
	previous := f.preferences[key]
	if input.RecordedAt.Before(previous.RecordedAt) {
		return time.Time{}, domain.ErrConflict
	}
	if input.RecordedAt.Equal(previous.RecordedAt) && previous.Preference != "denied" {
		return time.Time{}, domain.ErrConflict
	}
	if previous.Preference == "denied" && input.RecordedAt.Equal(previous.RecordedAt) {
		return previous.RecordedAt, nil
	}
	if previous.Preference != "denied" {
		f.suppressions++
	}
	f.preferences[key] = store.TelemetryPreference{Preference: "denied", RecordedAt: input.RecordedAt}
	return input.RecordedAt, nil
}

func (f *fakeRepository) ResolveSubjectAlias(_ context.Context, key, product, audience string) (store.ResolvedAlias, error) {
	if f.aliasErr != nil {
		return store.ResolvedAlias{}, f.aliasErr
	}
	alias, ok := f.aliases[key]
	if !ok || alias.ProductID != product || alias.Audience != audience {
		return store.ResolvedAlias{}, domain.ErrNotFound
	}
	return alias, nil
}

func (f *fakeRepository) ResolveTokenSubject(_ context.Context, product, subjectType, subjectID string) error {
	if f.installation.ProductID != product || subjectType != "installation" || f.installation.ID != subjectID {
		return domain.ErrNotFound
	}
	return nil
}

func (f *fakeRepository) GetTelemetryPreference(_ context.Context, subject store.Subject, product string) (store.TelemetryPreference, error) {
	if f.preferenceErr != nil {
		return store.TelemetryPreference{}, f.preferenceErr
	}
	preference, ok := f.preferences[subject.Kind+"\x00"+subject.ID+"\x00"+product]
	if !ok {
		return store.TelemetryPreference{}, domain.ErrNotFound
	}
	return preference, nil
}
