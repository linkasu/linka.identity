package accountbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/linka-cloud/linka.identity/internal/accountmail"
	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/service"
)

type fixtureMail struct {
	calls int
	err   error
	body  string
	to    string
}

type deliveryPersistenceFailure struct {
	Repository
	err error
}

func (r deliveryPersistenceFailure) FinishPublicEmailDelivery(context.Context, string, string, domain.PublicChallengeState) error {
	return r.err
}

func (r deliveryPersistenceFailure) DeferPublicEmailDelivery(context.Context, string, string, time.Time) error {
	return r.err
}

type deliveryKeyFailure struct {
	cryptokit.KeyProvider
	err error
}

func (p deliveryKeyFailure) DecryptDataKey(context.Context, string, []byte) ([]byte, error) {
	return nil, p.err
}

func TestOTPDeliveryDiagnosticsAreSanitizedAndPreserveOutcomes(t *testing.T) {
	const sentinelPii = "sentinelpii@example.test"
	sensitiveErr := errors.New(sentinelPii)
	failedEnvelope := cryptokit.NewEnvelope(deliveryKeyFailure{err: sensitiveErr})
	smtpError := func(stage string, code int, uncertain bool) error {
		return errors.Join(&accountmail.DeliveryError{Stage: stage, Uncertain: uncertain}, &textproto.Error{Code: code, Msg: sentinelPii}, sensitiveErr)
	}
	for _, tc := range []struct {
		name      string
		prepare   func(*Broker, *beginRepository, string)
		sendErr   error
		stage     string
		smtpStage string
		smtpCode  int
		outcome   domain.PublicChallengeState
		calls     int
	}{
		{name: "binding", stage: "binding", outcome: domain.PublicChallengeDeliveryFailed, prepare: func(b *Broker, _ *beginRepository, _ string) { b.otpKeyID = sentinelPii }},
		{name: "otp_decrypt", stage: "otp_decrypt", outcome: domain.PublicChallengeDeliveryFailed, prepare: func(b *Broker, _ *beginRepository, _ string) { b.envelope = failedEnvelope }},
		{name: "otp_integrity", stage: "otp_integrity", outcome: domain.PublicChallengeDeliveryFailed, prepare: func(_ *Broker, r *beginRepository, id string) {
			row := r.rows[id]
			row.CodeHash = []byte(sentinelPii)
			r.rows[id] = row
		}},
		{name: "email_open", stage: "email_open", outcome: domain.PublicChallengeDeliveryFailed, prepare: func(b *Broker, _ *beginRepository, _ string) {
			b.identity = service.NewIdentityService(nil, failedEnvelope, nil, false)
		}},
		{name: "smtp_rejected", stage: "smtp", smtpStage: "recipient", smtpCode: 550, sendErr: smtpError("recipient", 550, false), outcome: domain.PublicChallengeDeliveryFailed, calls: 1},
		{name: "smtp_deferred", stage: "smtp", smtpStage: "mail", smtpCode: 451, sendErr: smtpError("mail", 451, false), outcome: domain.PublicChallengeRequested, calls: 1},
		{name: "smtp_uncertain", stage: "smtp", smtpStage: "accept", sendErr: &accountmail.DeliveryError{Stage: "accept", Uncertain: true}, outcome: domain.PublicChallengeDeliveryUncertain, calls: 1},
		{name: "unknown_sender", stage: "smtp", sendErr: sensitiveErr, outcome: domain.PublicChallengeDeliveryUncertain, calls: 1},
		{name: "untrusted_stage_and_low_code", stage: "smtp", sendErr: smtpError(sentinelPii, 99, false), outcome: domain.PublicChallengeDeliveryFailed, calls: 1},
		{name: "untrusted_stage_and_high_code", stage: "smtp", sendErr: smtpError(sentinelPii, 600, false), outcome: domain.PublicChallengeDeliveryFailed, calls: 1},
		{name: "minimum_code", stage: "smtp", smtpStage: "greet", smtpCode: 100, sendErr: smtpError("greet", 100, false), outcome: domain.PublicChallengeDeliveryFailed, calls: 1},
		{name: "maximum_code", stage: "smtp", smtpStage: "data", smtpCode: 599, sendErr: smtpError("data", 599, false), outcome: domain.PublicChallengeDeliveryFailed, calls: 1},
		{name: "delivered", stage: "smtp", outcome: domain.PublicChallengeDelivered, calls: 1},
	} {
		for _, persistenceFailed := range []bool{false, true} {
			persistence := "saved"
			if persistenceFailed {
				persistence = "failed"
			}
			t.Run(tc.name+"/"+persistence, func(t *testing.T) {
				b, repository, envelope, input := newBeginBroker(t)
				var logs bytes.Buffer
				b.logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
					if a.Key == slog.TimeKey {
						return slog.Attr{}
					}
					return a
				}}))
				input.Email = sentinelPii
				response, err := b.Begin(context.Background(), "fixture-installation-refresh", input)
				if err != nil {
					t.Fatal("fixture begin failed")
				}
				row := repository.rows[response.ChallengeID]
				code, err := envelope.Decrypt(context.Background(), row.Code, otpAAD(row.ID, row.ProductID))
				if err != nil {
					t.Fatal("fixture decrypt failed")
				}
				defer clear(code)
				if tc.prepare != nil {
					tc.prepare(b, repository, row.ID)
				}
				var wantErr error
				if persistenceFailed {
					wantErr = sensitiveErr
					b.repository = deliveryPersistenceFailure{Repository: repository, err: wantErr}
				}
				sender := &fixtureMail{err: tc.sendErr}
				worked, err := b.ProcessEmail(context.Background(), sender, "42146367-e93b-4114-8299-64c13f2760d1")
				if !worked || err != wantErr || sender.calls != tc.calls {
					t.Fatal("delivery return or sender call semantics changed")
				}
				wantState := tc.outcome
				if persistenceFailed {
					wantState = domain.PublicChallengeDelivering
				}
				if repository.rows[row.ID].State != wantState {
					t.Fatal("delivery state semantics changed")
				}
				if tc.outcome == domain.PublicChallengeDelivered && !persistenceFailed {
					if logs.Len() != 0 {
						t.Fatal("successful delivery unexpectedly logged a warning")
					}
					return
				}
				for _, sensitive := range []string{sentinelPii, row.ID, row.InstallationID, input.ClientNonce, string(code), string(row.Code.Data)} {
					if strings.Contains(logs.String(), sensitive) {
						t.Fatal("diagnostic log exposed sensitive data")
					}
				}
				var event map[string]any
				if json.Unmarshal(logs.Bytes(), &event) != nil {
					t.Fatal("expected exactly one JSON diagnostic event")
				}
				if event["stage"] != tc.stage || event["outcome"] != string(tc.outcome) || event["persistence"] != persistence {
					t.Fatal("diagnostic stage, outcome or persistence is incorrect")
				}
				for key := range event {
					switch key {
					case "time", "level", "msg", "stage", "outcome", "persistence", "smtp_stage", "smtp_code":
					default:
						t.Fatal("diagnostic event contains a non-allowlisted field")
					}
				}
				if stage, ok := event["smtp_stage"]; ok != (tc.smtpStage != "") || ok && stage != tc.smtpStage {
					t.Fatal("SMTP stage sanitization failed")
				}
				if code, ok := event["smtp_code"]; ok != (tc.smtpCode != 0) || ok && code != float64(tc.smtpCode) {
					t.Fatal("SMTP reply code sanitization failed")
				}
			})
		}
	}
}

func TestOTPTemporaryRejectionStaysQueuedWithoutLosingTheCode(t *testing.T) {
	b, repository, _, input := newBeginBroker(t)
	response, err := b.Begin(context.Background(), "fixture-installation-refresh", input)
	if err != nil {
		t.Fatal(err)
	}
	sender := &fixtureMail{err: errors.Join(&accountmail.DeliveryError{Stage: "recipient"}, &textproto.Error{Code: 451})}
	if worked, err := b.ProcessEmail(context.Background(), sender, "42146367-e93b-4114-8299-64c13f2760d1"); err != nil || !worked || sender.calls != 1 {
		t.Fatalf("temporary rejection was not handled: %v", err)
	}
	queued := repository.rows[response.ChallengeID]
	if queued.State != domain.PublicChallengeRequested || len(queued.Code.Data) == 0 || len(queued.CodeHash) == 0 || !queued.MailAvailableAt.After(time.Now().UTC()) || !queued.ExpiresAt.Equal(queued.CreatedAt.Add(domain.PublicEmailQueueTTL)) {
		t.Fatal("temporary rejection lost its queued proof or deadline")
	}
	polled, err := b.Begin(context.Background(), "fixture-installation-refresh", input)
	if err != nil || polled.Status != "queued" || repository.creates != 1 {
		t.Fatalf("idempotent status poll recreated the message: %v", err)
	}
	if worked, err := b.ProcessEmail(context.Background(), sender, "2a8992f8-cdd0-422e-9292-1308ec863633"); err != nil || worked || sender.calls != 1 {
		t.Fatal("deferred delivery retried before its server deadline")
	}
}

func (m *fixtureMail) Send(_ context.Context, to, _, body string) error {
	m.calls++
	m.to, m.body = to, body
	return m.err
}

func TestOTPDeliveryDoesNotVerifyOrAutomaticallyResendUnknownOutcome(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		b, repository, _, input := newBeginBroker(t)
		response, err := b.Begin(context.Background(), "fixture-installation-refresh", input)
		if err != nil {
			t.Fatal(err)
		}
		sender := &fixtureMail{}
		want := domain.PublicChallengeDelivered
		if uncertain {
			sender.err = errors.New("unknown transport outcome")
			want = domain.PublicChallengeDeliveryUncertain
		}
		worked, err := b.ProcessEmail(context.Background(), sender, "42146367-e93b-4114-8299-64c13f2760d1")
		if err != nil || !worked || sender.calls != 1 || sender.to != "owner@example.test" || repository.rows[response.ChallengeID].State != want {
			t.Fatalf("SMTP outcome: worked=%v calls=%d state=%s error=%v", worked, sender.calls, repository.rows[response.ChallengeID].State, err)
		}
		if repository.verifications[0].VerifiedAt != nil || repository.session.ID != "" {
			t.Fatal("SMTP acceptance became account verification")
		}
		if worked, err := b.ProcessEmail(context.Background(), sender, "2a8992f8-cdd0-422e-9292-1308ec863633"); err != nil || worked || sender.calls != 1 {
			t.Fatal("a terminal sender outcome was automatically sent again")
		}
	}
}

func TestOTPDeliveryRechecksCancellationBeforeSending(t *testing.T) {
	b, repository, _, input := newBeginBroker(t)
	if _, err := b.Begin(context.Background(), "fixture-installation-refresh", input); err != nil {
		t.Fatal(err)
	}
	repository.cancelOnRead = true
	sender := &fixtureMail{}
	if worked, err := b.ProcessEmail(context.Background(), sender, "42146367-e93b-4114-8299-64c13f2760d1"); err != nil || !worked || sender.calls != 0 {
		t.Fatalf("cancelled challenge reached SMTP: calls=%d error=%v", sender.calls, err)
	}
}
