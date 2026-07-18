package cryptokit

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	kms "github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// Crypto RPCs use a separate discovered endpoint from KMS key management.
const yandexKMSEndpoint = "kms.yandex:443"
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
	client      symmetricCryptoClient
	connection  *grpc.ClientConn
}

type symmetricCryptoClient interface {
	Encrypt(context.Context, *kms.SymmetricEncryptRequest, ...grpc.CallOption) (*kms.SymmetricEncryptResponse, error)
	Decrypt(context.Context, *kms.SymmetricDecryptRequest, ...grpc.CallOption) (*kms.SymmetricDecryptResponse, error)
}

func NewYandexKMSKeyring(activeKeyID string, keys map[string]string, tokens IAMTokenSource) (*YandexKMSKeyring, error) {
	connection, err := grpc.NewClient(yandexKMSEndpoint, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})))
	if err != nil {
		return nil, fmt.Errorf("connect to Yandex KMS: %w", err)
	}
	provider, err := newYandexKMSKeyring(activeKeyID, keys, tokens, kms.NewSymmetricCryptoServiceClient(connection))
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	provider.connection = connection
	return provider, nil
}

func newYandexKMSKeyring(activeKeyID string, keys map[string]string, tokens IAMTokenSource, client symmetricCryptoClient) (*YandexKMSKeyring, error) {
	if activeKeyID == "" || len(keys) == 0 || tokens == nil || client == nil {
		return nil, errors.New("Yandex KMS requires an active key alias, keyring, IAM token source, and client")
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
		activeKeyID: activeKeyID, keys: cloned, tokens: tokens, client: client,
	}, nil
}

func (p *YandexKMSKeyring) Close() error {
	if p.connection == nil {
		return nil
	}
	return p.connection.Close()
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
	authorized, err := p.authorizedContext(ctx)
	if err != nil {
		return nil, err
	}
	result, err := p.client.Encrypt(authorized, &kms.SymmetricEncryptRequest{
		KeyId: keyID, Plaintext: plaintext, AadContext: keyWrapAAD,
	})
	if err != nil {
		return nil, fmt.Errorf("call Yandex KMS encrypt: %w", err)
	}
	if len(result.GetCiphertext()) == 0 {
		return nil, errors.New("Yandex KMS returned invalid ciphertext")
	}
	return append([]byte(nil), result.GetCiphertext()...), nil
}

func (p *YandexKMSKeyring) decrypt(ctx context.Context, keyID string, wrapped []byte) ([]byte, error) {
	authorized, err := p.authorizedContext(ctx)
	if err != nil {
		return nil, err
	}
	result, err := p.client.Decrypt(authorized, &kms.SymmetricDecryptRequest{
		KeyId: keyID, Ciphertext: wrapped, AadContext: keyWrapAAD,
	})
	if err != nil {
		return nil, fmt.Errorf("call Yandex KMS decrypt: %w", err)
	}
	if len(result.GetPlaintext()) != 32 {
		return nil, errors.New("Yandex KMS returned invalid plaintext data key")
	}
	return append([]byte(nil), result.GetPlaintext()...), nil
}

func (p *YandexKMSKeyring) authorizedContext(ctx context.Context) (context.Context, error) {
	token, err := p.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token), nil
}

func rejectRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
