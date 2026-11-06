package token

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

func (s *Signer) signPayload(claims any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": s.keyID})
	if err != nil {
		return "", errors.New("invalid token header")
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", errors.New("invalid token claims")
	}
	unsigned := rawBase64(header) + "." + rawBase64(payload)
	encoded := unsigned + "." + rawBase64(ed25519.Sign(s.privateKey, []byte(unsigned)))
	if len(encoded) > 8192 {
		return "", errors.New("token exceeds size limit")
	}
	return encoded, nil
}

func (s *Signer) verifyPayload(encoded string, out any) error {
	if len(encoded) > 8192 {
		return errors.New("invalid token structure")
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 3 {
		return errors.New("invalid token structure")
	}
	headerPayload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("invalid token header")
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
		KeyID     string `json:"kid"`
	}
	if err := decodeTokenJSON(headerPayload, &header); err != nil || header.Algorithm != "EdDSA" || header.Type != "JWT" {
		return errors.New("invalid token header")
	}
	publicKey, ok := s.publicKeys[header.KeyID]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ok || !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return errors.New("invalid token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("invalid token payload")
	}
	if err := decodeTokenJSON(payload, out); err != nil {
		return errors.New("invalid token claims")
	}
	return nil
}

func decodeTokenJSON(payload []byte, out any) error {
	if !utf8.Valid(payload) {
		return errors.New("invalid JSON encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("invalid JSON object")
	}
	// encoding/json alone accepts duplicate names and case-insensitive aliases.
	fields := make(map[string]bool)
	target := reflect.TypeOf(out).Elem()
	for i := 0; i < target.NumField(); i++ {
		fields[strings.Split(target.Field(i).Tag.Get("json"), ",")[0]] = false
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		seen, known := fields[name]
		if !ok || !known || seen {
			return errors.New("invalid JSON field")
		}
		fields[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("invalid trailing JSON")
	}
	return json.Unmarshal(payload, out)
}
