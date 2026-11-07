package accountbroker

import (
	"encoding/base64"
	"math"
	"strings"

	"github.com/linka-cloud/linka.identity/internal/domain"
)

// normalized validates syntax, never authorization or product registration.
func (input ChallengeInput) normalized() (ChallengeInput, error) {
	input.RequestID = strings.ToLower(input.RequestID)
	if !domain.ValidUUID(input.RequestID) || input.RequestID[14] != '4' ||
		!domain.ValidProductID(input.ProductID) || input.Purpose != RegistrationPurpose ||
		!domain.ValidHolderRole(input.HolderRole) || !validClientNonce(input.ClientNonce) {
		return ChallengeInput{}, domain.ErrInvalid
	}
	email, err := domain.NormalizeEmail(input.Email)
	if err != nil {
		return ChallengeInput{}, domain.ErrInvalid
	}
	input.Email = email
	return input, nil
}

// valid checks syntax only; the broker validates challenge bindings and authority.
func (input VerifyInput) valid() error {
	if !domain.ValidProductID(input.ProductID) || !validClientNonce(input.ClientNonce) || len(input.Code) != 6 {
		return domain.ErrInvalid
	}
	for i := range input.Code {
		if input.Code[i] < '0' || input.Code[i] > '9' {
			return domain.ErrInvalid
		}
	}
	return nil
}

func validClientNonce(nonce string) bool {
	if len(nonce) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == nonce
}

// normalized retains only declared geography; it never infers location or identity.
func (input ProfileInput) normalized() (ProfileInput, error) {
	if input.Version == math.MaxUint64 || !domain.ValidHolderRole(input.HolderRole) {
		return ProfileInput{}, domain.ErrInvalid
	}
	var err error
	input.Country, input.Region, err = domain.NormalizeDeclaredRegion(input.Country, input.Region)
	if err != nil {
		return ProfileInput{}, err
	}
	return input, nil
}
