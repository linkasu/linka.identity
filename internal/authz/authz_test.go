package authz

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthenticatorSeparatesRolesAndProductScopes(t *testing.T) {
	authenticator, err := New([]Workload{{
		ID: "plays", Token: strings.Repeat("p", 32), Roles: []Role{RoleProduct}, Products: []string{"linka-plays"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("p", 32))
	principal, ok := authenticator.Authenticate(request)
	if !ok || !principal.Has(RoleProduct) || principal.Has(RoleOrgAdmin) || !principal.AllowsProduct("linka-plays") || principal.AllowsProduct("other") {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}
