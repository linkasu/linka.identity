package store

import (
	"time"

	"github.com/linka-cloud/linka.identity/internal/domain"
)

// One session is a device's refresh family. Consumed refresh hashes remain
// attributable to it so that replay revokes that family, not offline data.
type AccountSession struct {
	ID, ProductID, AccountID, InstallationID string
	State                                    domain.PublicSessionState
	CreatedAt, ExpiresAt                     time.Time
	RevokedAt                                *time.Time
	Version                                  uint64
}

type AccountRefresh struct {
	Hash                []byte
	SessionID           string
	IssuedAt, ExpiresAt time.Time
	ConsumedAt          *time.Time
	Version             uint64
}
