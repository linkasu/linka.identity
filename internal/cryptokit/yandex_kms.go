package cryptokit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const yandexKMSEndpoint = "https://kms.api.cloud.yandex.net"
const yandexMetadataTokenURL = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

type IAMTokenSource interface {
	Token(context.Context) (string, error)
}

type MetadataIAMTokenSource struct {
	client    *http.Client
	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func NewMetadataIAMTokenSource() *MetadataIAMTokenSource {
	return &MetadataIAMTokenSource{client: &http.Client{Timeout: 3 * time.Second, CheckRedirect: rejectRedirect}}
}

func (s *MetadataIAMTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Until(s.expiresAt) > time.Minute {
		return s.token, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, yandexMetadataTokenURL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Metadata-Flavor", "Google")
	response, err := s.client.Do(request)
	if err != nil {
		return "", errors.New("request IAM token from metadata service")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return "", fmt.Errorf("metadata service returned HTTP %d", response.StatusCode)
	}
	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || result.AccessToken == "" || result.ExpiresIn < 60 {
		return "", errors.New("metadata service returned invalid IAM token")
	}
	s.token = result.AccessToken
	s.expiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return s.token, nil
}

type YandexKMSKeyring struct {
	activeKeyID string
	keys        map[string]string
	tokens      IAMTokenSource
	client      *http.Client
	endpoint    string
}

func NewYandexKMSKeyring(activeKeyID string, keys map[string]string, tokens IAMTokenSource) (*YandexKMSKeyring, error) {
	return newYandexKMSKeyring(activeKeyID, keys, tokens, yandexKMSEndpoint, false)
}

func newYandexKMSKeyring(activeKeyID string, keys map[string]string, tokens IAMTokenSource, endpoint string, allowHTTP bool) (*YandexKMSKeyring, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http")) || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid Yandex KMS endpoint")
	}
	if activeKeyID == "" || len(keys) == 0 || tokens == nil {
		return nil, errors.New("Yandex KMS requires an active key alias, keyring, and IAM token source")
	}
	cloned := make(map[string]string, len(keys))
	for alias, keyID := range keys {
		if alias == "" || strings.TrimSpace(keyID) == "" {
			return nil, errors.New("Yandex KMS keyring contains an invalid key")
		}
		cloned[alias] = keyID
	}
	if _, ok := cloned[activeKeyID]; !ok {
		return nil, errors.New("active Yandex KMS key alias is absent from keyring")
	}
	return &YandexKMSKeyring{
		activeKeyID: activeKeyID, keys: cloned, tokens: tokens, endpoint: strings.TrimRight(parsed.String(), "/"),
		client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: rejectRedirect},
	}, nil
}

func (p *YandexKMSKeyring) GenerateDataKey(ctx context.Context) (DataKey, error) {
	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		return DataKey{}, fmt.Errorf("generate random data key: %w", err)
	}
	wrapped, err := p.encrypt(ctx, p.keys[p.activeKeyID], plaintext)
	if err != nil {
		clear(plaintext)
		return DataKey{}, err
	}
	return DataKey{Plaintext: plaintext, Wrapped: wrapped, KeyID: p.activeKeyID}, nil
}

func (p *YandexKMSKeyring) DecryptDataKey(ctx context.Context, keyAlias string, wrapped []byte) ([]byte, error) {
	keyID, ok := p.keys[keyAlias]
	if !ok {
		return nil, errors.New("unknown Yandex KMS key alias")
	}
	return p.decrypt(ctx, keyID, wrapped)
}

func (p *YandexKMSKeyring) encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	var result struct {
		Ciphertext string `json:"ciphertext"`
		KeyID      string `json:"keyId"`
		VersionID  string `json:"versionId"`
	}
	body := map[string]string{
		"plaintext":  base64.StdEncoding.EncodeToString(plaintext),
		"aadContext": base64.StdEncoding.EncodeToString(keyWrapAAD),
	}
	if err := p.call(ctx, keyID, "encrypt", body, &result); err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(result.Ciphertext)
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("Yandex KMS returned invalid ciphertext")
	}
	return decoded, nil
}

func (p *YandexKMSKeyring) decrypt(ctx context.Context, keyID string, wrapped []byte) ([]byte, error) {
	var result struct {
		Plaintext string `json:"plaintext"`
		KeyID     string `json:"keyId"`
		VersionID string `json:"versionId"`
	}
	body := map[string]string{
		"ciphertext": base64.StdEncoding.EncodeToString(wrapped),
		"aadContext": base64.StdEncoding.EncodeToString(keyWrapAAD),
	}
	if err := p.call(ctx, keyID, "decrypt", body, &result); err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(result.Plaintext)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("Yandex KMS returned invalid plaintext data key")
	}
	return decoded, nil
}

func (p *YandexKMSKeyring) call(ctx context.Context, keyID, operation string, body any, destination any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	token, err := p.tokens.Token(ctx)
	if err != nil {
		return err
	}
	endpoint := p.endpoint + "/kms/v1/keys/" + url.PathEscape(keyID) + ":" + operation
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("call Yandex KMS %s", operation)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("Yandex KMS %s returned HTTP %d", operation, response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode Yandex KMS %s response", operation)
	}
	return nil
}

func rejectRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
