package store

import "time"

type ProductAccount struct {
	ProductID, AccountID, EmailIdentityID string
	HolderRole, Country, Region, Status   string
	VerifiedAt, CreatedAt, UpdatedAt      time.Time
	Version                               uint64
}
