package authz

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

type Role string

const (
	RoleProduct       Role = "product"
	RoleEmailVerifier Role = "email_verifier"
	RoleIdentityAdmin Role = "identity_admin"
	RolePrivacyAdmin  Role = "privacy_admin"
	RolePrivacyGlobal Role = "privacy_global"
	RoleOrgAdmin      Role = "organization_admin"
)

type Workload struct {
	ID       string
	Token    string
	Roles    []Role
	Products []string
}

type Principal struct {
	ID       string
	roles    map[Role]struct{}
	products map[string]struct{}
}

type credential struct {
	principal Principal
	digest    [32]byte
}

type Authenticator struct {
	credentials []credential
}

func New(workloads []Workload) (*Authenticator, error) {
	if len(workloads) == 0 {
		return nil, errors.New("at least one workload credential is required")
	}
	credentials := make([]credential, 0, len(workloads))
	ids := make(map[string]struct{}, len(workloads))
	for _, workload := range workloads {
		if workload.ID == "" || len(workload.Token) < 32 || len(workload.Roles) == 0 {
			return nil, errors.New("invalid workload credential")
		}
		if _, exists := ids[workload.ID]; exists {
			return nil, errors.New("duplicate workload ID")
		}
		ids[workload.ID] = struct{}{}
		principal := Principal{ID: workload.ID, roles: make(map[Role]struct{}), products: make(map[string]struct{})}
		for _, role := range workload.Roles {
			switch role {
			case RoleProduct, RoleEmailVerifier, RoleIdentityAdmin, RolePrivacyAdmin, RolePrivacyGlobal, RoleOrgAdmin:
				principal.roles[role] = struct{}{}
			default:
				return nil, errors.New("unknown workload role")
			}
		}
		for _, product := range workload.Products {
			if product == "" {
				return nil, errors.New("empty workload product scope")
			}
			principal.products[product] = struct{}{}
		}
		if principal.Has(RoleProduct) && len(principal.products) == 0 {
			return nil, errors.New("product workload must have at least one product scope")
		}
		credentials = append(credentials, credential{principal: principal, digest: sha256.Sum256([]byte(workload.Token))})
	}
	return &Authenticator{credentials: credentials}, nil
}

func (a *Authenticator) Authenticate(request *http.Request) (Principal, bool) {
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") || strings.Contains(strings.TrimPrefix(authorization, "Bearer "), " ") {
		return Principal{}, false
	}
	provided := sha256.Sum256([]byte(strings.TrimPrefix(authorization, "Bearer ")))
	for _, candidate := range a.credentials {
		if subtle.ConstantTimeCompare(provided[:], candidate.digest[:]) == 1 {
			return candidate.principal, true
		}
	}
	return Principal{}, false
}

func (p Principal) Has(role Role) bool {
	_, ok := p.roles[role]
	return ok
}

func (p Principal) AllowsProduct(product string) bool {
	_, ok := p.products[product]
	return ok
}

func (p Principal) SingleProduct() (string, bool) {
	if len(p.products) != 1 {
		return "", false
	}
	for product := range p.products {
		return product, true
	}
	return "", false
}
