package domain

import (
	"testing"
	"time"
)

func TestPublicChallengeTransitionMatrix(t *testing.T) {
	states := []PublicChallengeState{
		PublicChallengeRequested, PublicChallengeDelivering, PublicChallengeDelivered,
		PublicChallengeVerified, PublicChallengeConsumed, PublicChallengeDeliveryFailed,
		PublicChallengeDeliveryUncertain, PublicChallengeExpired, PublicChallengeLocked,
		PublicChallengeCancelled, "", "unknown",
	}
	allowed := map[PublicChallengeState][]PublicChallengeState{
		PublicChallengeRequested: {PublicChallengeDelivering, PublicChallengeCancelled, PublicChallengeExpired},
		PublicChallengeDelivering: {
			PublicChallengeDelivered, PublicChallengeDeliveryFailed, PublicChallengeDeliveryUncertain,
			PublicChallengeCancelled, PublicChallengeExpired, PublicChallengeVerified, PublicChallengeLocked,
		},
		PublicChallengeDelivered:         {PublicChallengeVerified, PublicChallengeLocked, PublicChallengeCancelled, PublicChallengeExpired},
		PublicChallengeDeliveryUncertain: {PublicChallengeVerified, PublicChallengeLocked, PublicChallengeCancelled, PublicChallengeExpired},
		PublicChallengeVerified:          {PublicChallengeConsumed},
	}
	for _, from := range states {
		for _, to := range states {
			t.Run(string(from)+"/"+string(to), func(t *testing.T) {
				want := false
				for _, next := range allowed[from] {
					want = want || next == to
				}
				if got := CanTransitionPublicChallenge(from, to); got != want {
					t.Fatalf("transition %q -> %q = %v, want %v", from, to, got, want)
				}
			})
		}
	}
}

func TestValidHolderRole(t *testing.T) {
	for _, role := range []string{"self", "representative", "", "Self", " self", "guardian", "child", "self\x00", "ѕelf"} {
		if got, want := ValidHolderRole(role), role == "self" || role == "representative"; got != want {
			t.Errorf("ValidHolderRole(%q) = %v, want %v", role, got, want)
		}
	}
}

func TestValidPublicSession(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	for _, status := range []PublicSessionState{PublicSessionActive, PublicSessionRevoked, PublicSessionExpired, "", "unknown"} {
		for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
			if got, want := ValidPublicSession(now, now.Add(delta), status), status == PublicSessionActive && delta > 0; got != want {
				t.Errorf("status %q, expiry delta %v: got %v, want %v", status, delta, got, want)
			}
		}
	}
}
