package domain

import "testing"

func TestPrivacyRequestStateMachine(t *testing.T) {
	tests := []struct {
		from, to string
		valid    bool
	}{
		{"requested", "processing", true},
		{"requested", "completed", false},
		{"processing", "completed", true},
		{"completed", "processing", false},
		{"rejected", "processing", false},
	}
	for _, test := range tests {
		if got := ValidPrivacyTransition(test.from, test.to); got != test.valid {
			t.Errorf("transition %s -> %s: got %v, want %v", test.from, test.to, got, test.valid)
		}
	}
}
