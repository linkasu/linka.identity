package domain

import (
	"regexp"
	"strings"
)

var declaredCountryPattern = regexp.MustCompile(`^[A-Za-z]{2}$`)
var declaredRegionPattern = regexp.MustCompile(`^[A-Za-z]{2}-[A-Za-z0-9]{1,3}$`)

// NormalizeDeclaredRegion accepts coarse declarations, never an inferred address.
func NormalizeDeclaredRegion(country, region string) (string, string, error) {
	country, region = strings.TrimSpace(country), strings.TrimSpace(region)
	if country != "" && !declaredCountryPattern.MatchString(country) || region != "" && !declaredRegionPattern.MatchString(region) {
		return "", "", ErrInvalid
	}
	country, region = strings.ToUpper(country), strings.ToUpper(region)
	if region != "" && (country == "" || !strings.HasPrefix(region, country+"-")) {
		return "", "", ErrInvalid
	}
	return country, region, nil
}
