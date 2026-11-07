package store

import (
	"time"

	"github.com/linka-cloud/linka.identity/internal/cryptokit"
)

type DirectoryPermission struct {
	Status, ID, PolicyVersion string
	RecordedAt                time.Time
}

// DirectoryAccount is private encrypted state. Public DTOs derive pairwise keys
// and short-lived opaque references; no root account/person ID is serialized.
type DirectoryAccount struct {
	Profile             ProductAccount                 `json:"-"`
	PersonID            string                         `json:"-"`
	Namespace           string                         `json:"-"`
	LinkageScope        string                         `json:"-"`
	ScopeKey            string                         `json:"-"`
	Email               cryptokit.Ciphertext           `json:"-"`
	TelemetryPreference string                         `json:"-"`
	Permissions         map[string]DirectoryPermission `json:"-"`
}
