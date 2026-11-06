package store

import (
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
)

// PublicEmailCompletion contains server-derived proofs and prepared ciphertext.
// Empty Identity/Session inputs are allowed only on the failed-code path.
type PublicEmailCompletion struct {
	ChallengeID, ProductID, InstallationID, OTPKeyID string
	NonceHash, CodeHash                              []byte
	Identity                                         NewEmailIdentity
	Indexes                                          []cryptokit.BlindIndex
	SessionID                                        string
	RefreshHash                                      []byte
	RefreshExpiresAt                                 time.Time
}

type PublicEmailRegistration struct {
	Identity EmailIdentity
	Account  ProductAccount
	Session  AccountSession
}
