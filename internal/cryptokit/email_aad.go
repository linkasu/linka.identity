package cryptokit

import "strings"

func EmailIdentityAAD(id, namespace, linkageScope, scopeKey string) []byte {
	return []byte(strings.Join([]string{"email-v1", id, namespace, linkageScope, scopeKey}, "\x00"))
}
