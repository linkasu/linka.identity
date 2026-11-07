// Package productdirectory exposes minimal product contacts to scoped workloads,
// not to public account sessions or partner browsers.
package productdirectory

import "time"

type QueryInput struct {
	ProductID string `json:"product_id"`
	Cursor    string `json:"cursor"`
	Limit     uint64 `json:"limit"`
}

type CheckInput struct {
	ProductID  string   `json:"product_id"`
	References []string `json:"references"`
}

type Permission struct {
	Status        string    `json:"status"`
	EvidenceID    string    `json:"evidence_id,omitempty"`
	PolicyVersion string    `json:"policy_version,omitempty"`
	RecordedAt    time.Time `json:"recorded_at,omitempty"`
}

type Entry struct {
	AccountKey          string                `json:"account_key"`
	ContactReference    string                `json:"contact_reference"`
	Email               string                `json:"email"`
	Origin              string                `json:"origin"`
	VerifiedAt          time.Time             `json:"verified_at"`
	HolderRole          string                `json:"holder_role"`
	Country             string                `json:"country"`
	Region              string                `json:"region"`
	Version             uint64                `json:"version"`
	TelemetryPreference string                `json:"telemetry_preference"`
	Permissions         map[string]Permission `json:"permissions"`
}

type Page struct {
	ContractVersion int       `json:"contract_version"`
	Product         string    `json:"product"`
	Entries         []Entry   `json:"entries"`
	NextCursor      string    `json:"next_cursor,omitempty"`
	DataAsOf        time.Time `json:"data_as_of"`
}

type CheckResult struct {
	ContactReference string                `json:"contact_reference"`
	AccountKey       string                `json:"account_key,omitempty"`
	State            string                `json:"state"`
	Reason           string                `json:"reason,omitempty"`
	Version          uint64                `json:"version,omitempty"`
	Permissions      map[string]Permission `json:"permissions,omitempty"`
}

type Checks struct {
	ContractVersion int           `json:"contract_version"`
	Product         string        `json:"product"`
	Results         []CheckResult `json:"results"`
	CheckedAt       time.Time     `json:"checked_at"`
}
