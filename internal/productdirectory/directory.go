package productdirectory

import (
	"context"
	"errors"
	"time"

	"github.com/linka-cloud/linka.identity/internal/authz"
	"github.com/linka-cloud/linka.identity/internal/cryptokit"
	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/pairwise"
	"github.com/linka-cloud/linka.identity/internal/store"
)

type Repository interface {
	DirectoryAccounts(context.Context, string, string, uint64) ([]store.DirectoryAccount, error)
	DirectoryAccount(context.Context, string, string) (store.DirectoryAccount, error)
	AuditProductDirectory(context.Context, string, string, string, time.Time) error
}

type Directory struct {
	repository Repository
	envelope   *cryptokit.Envelope
	aliases    *pairwise.Generator
	products   map[string]string
	now        func() time.Time
}

func New(repository Repository, envelope *cryptokit.Envelope, aliases *pairwise.Generator, products map[string]string) (*Directory, error) {
	if repository == nil || envelope == nil || aliases == nil || len(products) == 0 {
		return nil, errors.New("invalid product directory configuration")
	}
	registry := make(map[string]string, len(products))
	for product, audience := range products {
		if !domain.ValidProductID(product) || audience == "" {
			return nil, errors.New("invalid directory product registry")
		}
		registry[product] = audience
	}
	return &Directory{repository: repository, envelope: envelope, aliases: aliases, products: registry, now: time.Now}, nil
}

func (d *Directory) product(principal authz.Principal, requested string) (string, error) {
	if !principal.Has(authz.RoleProductDirectoryRead) {
		return "", domain.ErrForbidden
	}
	if requested == "" {
		var ok bool
		requested, ok = principal.SingleProduct()
		if !ok {
			return "", domain.ErrInvalid
		}
	}
	if d.products[requested] == "" || !principal.AllowsProduct(requested) {
		return "", domain.ErrForbidden
	}
	return requested, nil
}

func (d *Directory) Query(ctx context.Context, principal authz.Principal, input QueryInput) (Page, error) {
	product, err := d.product(principal, input.ProductID)
	if err != nil {
		return Page{}, err
	}
	if input.Limit == 0 {
		input.Limit = 25
	}
	if input.Limit > 50 {
		return Page{}, domain.ErrInvalid
	}
	after := ""
	if input.Cursor != "" {
		after, err = d.openReference(ctx, "cursor", product, input.Cursor)
		if err != nil {
			return Page{}, domain.ErrInvalid
		}
	}
	candidates, err := d.repository.DirectoryAccounts(ctx, product, after, input.Limit)
	if err != nil {
		return Page{}, err
	}
	if len(candidates) > int(input.Limit) {
		return Page{}, errors.New("invalid directory page size")
	}
	page := Page{ContractVersion: 1, Product: product, Entries: []Entry{}, DataAsOf: d.now().UTC()}
	last := after
	for _, candidate := range candidates {
		if candidate.Profile.ProductID != product || !domain.ValidUUID(candidate.Profile.AccountID) || candidate.Profile.AccountID <= last {
			return Page{}, errors.New("invalid directory cursor ordering")
		}
		last = candidate.Profile.AccountID
		record, err := d.repository.DirectoryAccount(ctx, product, last)
		if errors.Is(err, domain.ErrNotFound) {
			continue
		}
		if err != nil {
			return Page{}, err
		}
		if record.Profile.AccountID != last {
			return Page{}, errors.New("invalid authoritative directory account")
		}
		email, err := d.openEmail(ctx, product, record)
		if err != nil {
			return Page{}, err
		}
		reference, err := d.sealReference(ctx, "contact", product, last)
		if err != nil {
			return Page{}, err
		}
		page.Entries = append(page.Entries, Entry{AccountKey: d.aliases.Subject(product, d.products[product], "account", last), ContactReference: reference,
			Email: email, Origin: "identity_product_registration", VerifiedAt: record.Profile.VerifiedAt, HolderRole: record.Profile.HolderRole,
			Country: record.Profile.Country, Region: record.Profile.Region, Version: record.Profile.Version,
			TelemetryPreference: record.TelemetryPreference, Permissions: permissions(record)})
	}
	if len(candidates) == int(input.Limit) {
		page.NextCursor, err = d.sealReference(ctx, "cursor", product, last)
		if err != nil {
			return Page{}, err
		}
	}
	if err := d.repository.AuditProductDirectory(ctx, principal.ID, product, "directory.query", d.now().UTC()); err != nil {
		return Page{}, err
	}
	return page, nil
}

func (d *Directory) Check(ctx context.Context, principal authz.Principal, input CheckInput) (Checks, error) {
	product, err := d.product(principal, input.ProductID)
	if err != nil {
		return Checks{}, err
	}
	if len(input.References) == 0 || len(input.References) > 50 {
		return Checks{}, domain.ErrInvalid
	}
	result := Checks{ContractVersion: 1, Product: product, Results: []CheckResult{}, CheckedAt: d.now().UTC()}
	seen := make(map[string]bool)
	for _, reference := range input.References {
		if seen[reference] {
			return Checks{}, domain.ErrInvalid
		}
		seen[reference] = true
		item := CheckResult{ContactReference: reference, State: "unknown", Reason: "invalid_or_expired_reference"}
		account, err := d.openReference(ctx, "contact", product, reference)
		if err != nil {
			result.Results = append(result.Results, item)
			continue
		}
		record, err := d.repository.DirectoryAccount(ctx, product, account)
		if errors.Is(err, domain.ErrNotFound) {
			item.State, item.Reason = "inactive", "account_inactive_or_privacy_changed"
		} else if err != nil {
			return Checks{}, err
		} else {
			if record.Profile.ProductID != product || record.Profile.AccountID != account || record.Profile.Status != "active" {
				return Checks{}, errors.New("invalid directory account context")
			}
			item.State, item.Reason = "active", ""
			item.AccountKey, item.Version, item.Permissions = d.aliases.Subject(product, d.products[product], "account", account), record.Profile.Version, permissions(record)
		}
		result.Results = append(result.Results, item)
	}
	if err := d.repository.AuditProductDirectory(ctx, principal.ID, product, "directory.check", d.now().UTC()); err != nil {
		return Checks{}, err
	}
	return result, nil
}

func (d *Directory) openEmail(ctx context.Context, product string, record store.DirectoryAccount) (string, error) {
	if record.Profile.ProductID != product || record.Profile.Status != "active" || record.Profile.VerifiedAt.IsZero() || !domain.ValidHolderRole(record.Profile.HolderRole) || record.Namespace != "account" || record.LinkageScope != "product" || record.ScopeKey != product || !domain.ValidUUID(record.Profile.EmailIdentityID) {
		return "", errors.New("invalid directory email context")
	}
	plain, err := d.envelope.Decrypt(ctx, record.Email, cryptokit.EmailIdentityAAD(record.Profile.EmailIdentityID, record.Namespace, record.LinkageScope, record.ScopeKey))
	if err != nil {
		return "", errors.New("directory email unavailable")
	}
	defer clear(plain)
	email, err := domain.NormalizeEmail(string(plain))
	if err != nil {
		return "", errors.New("directory email unavailable")
	}
	return email, nil
}

func permissions(record store.DirectoryAccount) map[string]Permission {
	result := make(map[string]Permission, 3)
	for _, category := range []string{"news", "research", "service"} {
		value := record.Permissions[category]
		permission := Permission{Status: "unknown"}
		if (value.Status == "granted" || value.Status == "withdrawn") && domain.ValidUUID(value.ID) && value.PolicyVersion != "" && !value.RecordedAt.IsZero() {
			permission = Permission{Status: value.Status, EvidenceID: value.ID, PolicyVersion: value.PolicyVersion, RecordedAt: value.RecordedAt}
		}
		result[category] = permission
	}
	return result
}
