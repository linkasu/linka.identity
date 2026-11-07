package domain

import (
	"errors"
	"net/mail"
	"strings"
)

// NormalizeEmail is shared by workload and public registration; aliases are not
// rewritten (for example, dots and plus tags remain part of the address).
func NormalizeEmail(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) < 3 || len(trimmed) > 320 || !strings.Contains(trimmed, "@") {
		return "", errors.New("invalid email")
	}
	parsed, err := mail.ParseAddress(trimmed)
	if err != nil || parsed.Address != trimmed || strings.ContainsAny(trimmed, "\r\n\x00") {
		return "", errors.New("invalid email")
	}
	return strings.ToLower(parsed.Address), nil
}
