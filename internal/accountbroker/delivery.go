package accountbroker

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/textproto"
	"sort"
	"time"

	"github.com/linka-cloud/linka.identity/internal/accountmail"
	"github.com/linka-cloud/linka.identity/internal/domain"
)

type MailSender interface {
	Send(context.Context, string, string, string) error
}

type deliveryStage string

const (
	deliveryBinding      deliveryStage = "binding"
	deliveryOTPDecrypt   deliveryStage = "otp_decrypt"
	deliveryOTPIntegrity deliveryStage = "otp_integrity"
	deliveryEmailOpen    deliveryStage = "email_open"
	deliverySMTP         deliveryStage = "smtp"
)

func (b *Broker) logDelivery(ctx context.Context, stage deliveryStage, outcome domain.PublicChallengeState, cause, persistenceErr error) {
	persistence := "saved"
	if persistenceErr != nil {
		persistence = "failed"
	}
	attrs := []any{"stage", string(stage), "outcome", string(outcome), "persistence", persistence}
	if stage == deliverySMTP {
		var delivery *accountmail.DeliveryError
		if errors.As(cause, &delivery) && delivery != nil {
			switch delivery.Stage {
			case "config", "connect", "greet", "tls", "auth", "mail", "recipient", "data", "write", "accept":
				attrs = append(attrs, "smtp_stage", delivery.Stage)
			}
		}
		var reply *textproto.Error
		if errors.As(cause, &reply) && reply != nil && reply.Code >= 100 && reply.Code <= 599 {
			attrs = append(attrs, "smtp_code", reply.Code)
		}
	}
	b.logger.WarnContext(ctx, "public account delivery outcome", attrs...)
}

// ProcessEmail processes at most one durable job. Unknown SMTP outcomes are never
// retried; a valid code can still prove receipt without an SMTP acknowledgement.
func (b *Broker) ProcessEmail(ctx context.Context, sender MailSender, owner string) (bool, error) {
	if sender == nil || !domain.ValidUUID(owner) {
		return false, errors.New("public email delivery is not configured")
	}
	products := make([]string, 0, len(b.allowed))
	for product := range b.allowed {
		products = append(products, product)
	}
	sort.Strings(products)
	if len(products) == 0 {
		return false, nil
	}
	c, v, err := b.repository.ClaimPublicEmailDelivery(ctx, owner, products, b.dailyLimit)
	if errors.Is(err, domain.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if c.State != domain.PublicChallengeDelivering {
		return true, nil
	}
	finish := func(state domain.PublicChallengeState, stage deliveryStage, cause error) error {
		// SMTP acceptance must not be lost solely because its request context ended.
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		err := b.repository.FinishPublicEmailDelivery(writeCtx, c.ID, owner, state)
		if state != domain.PublicChallengeDelivered || err != nil {
			b.logDelivery(writeCtx, stage, state, cause, err)
		}
		return err
	}
	if _, allowed := b.allowed[c.ProductID]; !allowed || c.OTPKeyID != b.otpKeyID || c.Purpose != RegistrationPurpose || v.ProductID != c.ProductID || v.InstallationID == nil || *v.InstallationID != c.InstallationID || v.Namespace != "account" || v.LinkAcrossProducts {
		return true, finish(domain.PublicChallengeDeliveryFailed, deliveryBinding, nil)
	}
	code, err := b.envelope.Decrypt(ctx, c.Code, otpAAD(c.ID, c.ProductID))
	if err != nil {
		return true, finish(domain.PublicChallengeDeliveryFailed, deliveryOTPDecrypt, err)
	}
	defer clear(code)
	validCode := len(code) == 6
	for _, digit := range code {
		validCode = validCode && digit >= '0' && digit <= '9'
	}
	expected := b.digest("code", c.ProductID, c.InstallationID, c.ID, RegistrationPurpose, hex.EncodeToString(c.NonceHash), hex.EncodeToString(c.EmailBlindIndex), string(code))
	if !validCode || subtle.ConstantTimeCompare(c.CodeHash, expected) != 1 {
		return true, finish(domain.PublicChallengeDeliveryFailed, deliveryOTPIntegrity, nil)
	}
	email, err := b.identity.OpenVerificationEmail(ctx, v)
	if err != nil {
		return true, finish(domain.PublicChallengeDeliveryFailed, deliveryEmailOpen, err)
	}
	live, err := b.repository.PublicEmailChallenge(ctx, c.ID)
	if errors.Is(err, domain.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	if live.State != domain.PublicChallengeDelivering || live.MailClaimToken == nil || *live.MailClaimToken != owner || live.MailClaimUntil == nil || !b.now().UTC().Before(*live.MailClaimUntil) || !b.now().UTC().Before(live.ExpiresAt) {
		return true, nil
	}
	sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = sender.Send(sendCtx, email, "Код подтверждения Линки", "Код для регистрации в приложении Линки: "+string(code)+"\n\nКод действует 10 минут. Никому его не сообщайте. Если вы не запрашивали код, проигнорируйте это письмо.")
	cancel()
	if accountmail.Temporary(err) {
		writeCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer stop()
		deferErr := b.repository.DeferPublicEmailDelivery(writeCtx, c.ID, owner, b.now().UTC().Add(5*time.Minute))
		b.logDelivery(writeCtx, deliverySMTP, domain.PublicChallengeRequested, err, deferErr)
		return true, deferErr
	}
	state := domain.PublicChallengeDelivered
	if err != nil {
		state = domain.PublicChallengeDeliveryFailed
		if accountmail.Uncertain(err) {
			state = domain.PublicChallengeDeliveryUncertain
		}
	}
	return true, finish(state, deliverySMTP, err)
}
