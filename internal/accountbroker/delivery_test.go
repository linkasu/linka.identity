package accountbroker

import (
	"context"
	"errors"
	"testing"

	"github.com/linka-cloud/linka.identity/internal/domain"
)

type fixtureMail struct {
	calls int
	err   error
	body  string
	to    string
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
