package authz

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProductDirectoryReaderIsSeparateAndProductScoped(t *testing.T) {
	workload := Workload{ID: "crm-directory", Token: strings.Repeat("d", 32), Roles: []Role{RoleProductDirectoryRead}, Products: []string{"linka-type"}}
	a, err := New([]Workload{workload})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/internal/product-directory/query", nil)
	r.Header.Set("Authorization", "Bearer "+workload.Token)
	p, ok := a.Authenticate(r)
	if !ok || !p.Has(RoleProductDirectoryRead) || !p.AllowsProduct("linka-type") || p.AllowsProduct("linka-looks") || p.Has(RoleProduct) || p.Has(RolePrivacyAdmin) {
		t.Fatal("directory read became product mutation or unscoped access")
	}
	workload.Products = nil
	if _, err := New([]Workload{workload}); err == nil {
		t.Fatal("unscoped directory workload accepted")
	}
}
