package store

import (
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
)

// PublicEmailChallenge is private registration state, never a response DTO.
// Its ID is the device's idempotency UUID; purpose, installation and nonce bind it.
type PublicEmailChallenge struct {
	ID, ProductID, InstallationID, Purpose, HolderRole string
	RequestFingerprint, NonceHash, CodeHash            []byte
	OTPKeyID                                           string
	Code                                               cryptokit.Ciphertext
	EmailBlindIndexVersion                             int
	EmailBlindIndex                                    []byte
	State                                              domain.PublicChallengeState
	Attempts, MailAttempts                             uint64
	MailAvailableAt                                    time.Time
	MailClaimToken                                     *string
	MailClaimUntil                                     *time.Time
	CreatedAt, UpdatedAt, ExpiresAt                    time.Time
	VerifiedAt, ConsumedAt                             *time.Time
	Version                                            uint64
}
