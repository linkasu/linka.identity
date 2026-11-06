package productdirectory

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
)

type referencePayload struct {
	Version   int    `json:"version"`
	Product   string `json:"product"`
	Account   string `json:"account"`
	ExpiresAt int64  `json:"expires_at"`
}

func (d *Directory) sealReference(ctx context.Context, purpose, product, account string) (string, error) {
	plain, _ := json.Marshal(referencePayload{Version: 1, Product: product, Account: account, ExpiresAt: d.now().UTC().Add(8 * 24 * time.Hour).Unix()})
	cipher, err := d.envelope.Encrypt(ctx, plain, referenceAAD(purpose, product))
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(cipher)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func (d *Directory) openReference(ctx context.Context, purpose, product, encoded string) (string, error) {
	if len(encoded) == 0 || len(encoded) > 4096 {
		return "", domain.ErrInvalid
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(data) != encoded {
		return "", domain.ErrInvalid
	}
	var cipher cryptokit.Ciphertext
	if strictReferenceJSON(data, &cipher) != nil {
		return "", domain.ErrInvalid
	}
	plain, err := d.envelope.Decrypt(ctx, cipher, referenceAAD(purpose, product))
	if err != nil {
		return "", domain.ErrInvalid
	}
	defer clear(plain)
	var payload referencePayload
	if strictReferenceJSON(plain, &payload) != nil || payload.Version != 1 || payload.Product != product || !domain.ValidUUID(payload.Account) || payload.ExpiresAt <= d.now().UTC().Unix() {
		return "", domain.ErrInvalid
	}
	return payload.Account, nil
}

func strictReferenceJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return domain.ErrInvalid
	}
	return nil
}

func referenceAAD(purpose, product string) []byte {
	return []byte(strings.Join([]string{"product-directory-reference-v1", purpose, product}, "\x00"))
}
