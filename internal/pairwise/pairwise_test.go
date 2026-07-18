package pairwise

import (
	"strings"
	"testing"
)

func TestSubjectIsPairwiseByProductAndAudience(t *testing.T) {
	generator, err := New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	root := "11111111-1111-4111-8111-111111111111"
	first := generator.Subject("plays", "metric", "installation", root)
	if !Valid(first) || first == generator.Subject("other", "metric", "installation", root) || first == generator.Subject("plays", "app", "installation", root) {
		t.Fatal("pairwise subject was not isolated by product and audience")
	}
}
