// Package accountbroker owns public product registration and device sessions.
// Registration receipts permit local use, never online authorization.
package accountbroker

import (
	"time"

	"github.com/linka-cloud/linka.identity/internal/installationbroker"
)

const ContractVersion = 1
const RegistrationPurpose = "product_registration"

type ChallengeInput struct {
	RequestID   string `json:"request_id"`
	ProductID   string `json:"product_id"`
	Email       string `json:"email"`
	Purpose     string `json:"purpose"`
	ClientNonce string `json:"client_nonce"`
	HolderRole  string `json:"holder_role"`
}

type ChallengeResponse struct {
	ContractVersion int       `json:"contract_version"`
	ChallengeID     string    `json:"challenge_id"`
	Status          string    `json:"status"`
	ExpiresAt       time.Time `json:"expires_at"`
	ResendAfter     time.Time `json:"resend_after"`
}

type VerifyInput struct {
	ProductID   string `json:"product_id"`
	Code        string `json:"code"`
	ClientNonce string `json:"client_nonce"`
}

type Registration struct {
	ContractVersion     int                             `json:"contract_version"`
	Product             string                          `json:"product"`
	AccountKey          string                          `json:"account_key"`
	InstallationKey     string                          `json:"installation_key"`
	AccountProfile      Profile                         `json:"account_profile"`
	AccountToken        installationbroker.AccessToken  `json:"account_token"`
	RefreshToken        string                          `json:"refresh_token"`
	RefreshExpiresAt    time.Time                       `json:"refresh_expires_at"`
	RegistrationReceipt string                          `json:"registration_receipt"`
	MetricsToken        *installationbroker.AccessToken `json:"metrics_token"`
}

type ProfileInput struct {
	Version    uint64 `json:"version"`
	HolderRole string `json:"holder_role"`
	Country    string `json:"country"`
	Region     string `json:"region"`
}

type Profile struct {
	Product    string    `json:"product"`
	AccountKey string    `json:"account_key"`
	Version    uint64    `json:"version"`
	HolderRole string    `json:"holder_role"`
	Country    string    `json:"country"`
	Region     string    `json:"region"`
	UpdatedAt  time.Time `json:"updated_at"`
}
