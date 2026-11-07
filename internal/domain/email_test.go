package domain

import "testing"

func TestNormalizeEmail(t *testing.T) {
	for _, test := range []struct{ raw, want string }{
		{" User@Example.Test ", "user@example.test"},
		{"Owner+Product@example.test", "owner+product@example.test"},
	} {
		got, err := NormalizeEmail(test.raw)
		if err != nil || got != test.want {
			t.Fatalf("normalization mismatch: %v", err)
		}
	}
	for _, raw := range []string{"", "invalid", "User <user@example.test>", "one@example.test,two@example.test", "user\x00@example.test", "user\r\n@example.test"} {
		if _, err := NormalizeEmail(raw); err == nil {
			t.Fatal("invalid address accepted")
		}
	}
}
