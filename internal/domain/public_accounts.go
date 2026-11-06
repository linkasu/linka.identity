package domain

import "time"

type PublicChallengeState string

const (
	PublicChallengeRequested         PublicChallengeState = "requested"
	PublicChallengeDelivering        PublicChallengeState = "delivering"
	PublicChallengeDelivered         PublicChallengeState = "delivered"
	PublicChallengeVerified          PublicChallengeState = "verified"
	PublicChallengeConsumed          PublicChallengeState = "consumed"
	PublicChallengeDeliveryFailed    PublicChallengeState = "delivery_failed"
	PublicChallengeDeliveryUncertain PublicChallengeState = "delivery_uncertain"
	PublicChallengeExpired           PublicChallengeState = "expired"
	PublicChallengeLocked            PublicChallengeState = "locked"
	PublicChallengeCancelled         PublicChallengeState = "cancelled"
)

// CanTransitionPublicChallenge checks state only; callers reject false with ErrConflict.
// SMTP acceptance is not verification. Verification, registration, session issuance
// and consumption must commit together in one transaction.
func CanTransitionPublicChallenge(from, to PublicChallengeState) bool {
	switch from {
	case PublicChallengeRequested:
		return to == PublicChallengeDelivering || to == PublicChallengeCancelled || to == PublicChallengeExpired
	case PublicChallengeDelivering:
		return to == PublicChallengeDelivered || to == PublicChallengeDeliveryFailed ||
			to == PublicChallengeDeliveryUncertain || to == PublicChallengeCancelled ||
			to == PublicChallengeExpired || to == PublicChallengeVerified || to == PublicChallengeLocked
	case PublicChallengeDelivered, PublicChallengeDeliveryUncertain:
		return to == PublicChallengeVerified || to == PublicChallengeLocked ||
			to == PublicChallengeCancelled || to == PublicChallengeExpired
	case PublicChallengeVerified:
		return to == PublicChallengeConsumed
	default:
		return false
	}
}

// ValidHolderRole checks a declaration, not age or legal authority.
func ValidHolderRole(role string) bool {
	return role == "self" || role == "representative"
}

type PublicSessionState string

const (
	PublicSessionActive  PublicSessionState = "active"
	PublicSessionRevoked PublicSessionState = "revoked"
	PublicSessionExpired PublicSessionState = "expired"
)

func ValidPublicSession(now, expires time.Time, status PublicSessionState) bool {
	return status == PublicSessionActive && now.Before(expires)
}
