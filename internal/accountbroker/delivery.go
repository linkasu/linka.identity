package accountbroker

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/linka-cloud/linka.identity/internal/accountmail"
	"github.com/linka-cloud/linka.identity/internal/domain"
)

type MailSender interface {
	Send(context.Context, string, string, string) error
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
	c, v, err := b.repository.ClaimPublicEmailDelivery(ctx, owner, products)
	if errors.Is(err, domain.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if c.State != domain.PublicChallengeDelivering {
		return true, nil
	}
	finish := func(state domain.PublicChallengeState) error {
		// SMTP acceptance must not be lost solely because its request context ended.
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		return b.repository.FinishPublicEmailDelivery(writeCtx, c.ID, owner, state)
	}
	if _, allowed := b.allowed[c.ProductID]; !allowed || c.OTPKeyID != b.otpKeyID || c.Purpose != RegistrationPurpose || v.ProductID != c.ProductID || v.InstallationID == nil || *v.InstallationID != c.InstallationID || v.Namespace != "account" || v.LinkAcrossProducts {
		return true, finish(domain.PublicChallengeDeliveryFailed)
	}
	code, err := b.envelope.Decrypt(ctx, c.Code, otpAAD(c.ID, c.ProductID))
	if err != nil {
		return true, finish(domain.PublicChallengeDeliveryFailed)
	}
	defer clear(code)
	validCode := len(code) == 6
	for _, digit := range code {
		validCode = validCode && digit >= '0' && digit <= '9'
	}
	expected := b.digest("code", c.ProductID, c.InstallationID, c.ID, RegistrationPurpose, hex.EncodeToString(c.NonceHash), hex.EncodeToString(c.EmailBlindIndex), string(code))
	if !validCode || subtle.ConstantTimeCompare(c.CodeHash, expected) != 1 {
		return true, finish(domain.PublicChallengeDeliveryFailed)
	}
	email, err := b.identity.OpenVerificationEmail(ctx, v)
	if err != nil {
		return true, finish(domain.PublicChallengeDeliveryFailed)
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
	state := domain.PublicChallengeDelivered
	if err != nil {
		state = domain.PublicChallengeDeliveryFailed
		if accountmail.Uncertain(err) {
			state = domain.PublicChallengeDeliveryUncertain
		}
	}
	return true, finish(state)
}
