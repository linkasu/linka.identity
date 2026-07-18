package pairwise

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

type Generator struct {
	secret []byte
}

func New(secret []byte) (*Generator, error) {
	if len(secret) < 32 {
		return nil, errors.New("pairwise ID secret must contain at least 32 bytes")
	}
	return &Generator{secret: append([]byte(nil), secret...)}, nil
}

func (g *Generator) Subject(product, audience, subjectType, rootID string) string {
	mac := hmac.New(sha256.New, g.secret)
	_, _ = io.WriteString(mac, "linka-pairwise-subject-v1\x00"+product+"\x00"+audience+"\x00"+subjectType+"\x00"+rootID)
	return hex.EncodeToString(mac.Sum(nil))
}

func Valid(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
