package domain

import (
	"regexp"
	"strings"
)

var (
	productIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func ValidProductID(value string) bool {
	return productIDPattern.MatchString(value)
}

func ValidUUID(value string) bool {
	return uuidPattern.MatchString(strings.ToLower(value))
}

func TrimmedWithin(value string, min, max int) (string, bool) {
	trimmed := strings.TrimSpace(value)
	return trimmed, len(trimmed) >= min && len(trimmed) <= max
}
