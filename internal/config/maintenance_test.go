package config

import (
	"strings"
	"testing"
)

func TestMaintenanceLoadReadsOnlyMinimalConfiguration(t *testing.T) {
	values := map[string]string{"DEPLOYMENT_ENVIRONMENT": "production", "IDENTITY_MAINTENANCE_MODE": "true"}
	cfg, err := load(func(key string) (string, bool) {
		switch key {
		case "DEPLOYMENT_ENVIRONMENT", "HTTP_ADDR", "IDENTITY_MAINTENANCE_MODE":
		default:
			t.Fatalf("maintenance looked up workload configuration %q", key)
		}
		value, ok := values[key]
		return value, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.MaintenanceMode || cfg.Environment != "production" || cfg.HTTPAddr != ":8080" {
		t.Fatalf("unexpected minimal configuration: %+v", cfg)
	}
}

func TestMaintenanceLoadValidation(t *testing.T) {
	for _, tt := range []struct {
		name, flag, environment, wantError string
	}{
		{"absent", "", "production", "YDB_ENDPOINT is required"},
		{"disabled", "false", "production", "YDB_ENDPOINT is required"},
		{"invalid boolean", "invalid", "production", "IDENTITY_MAINTENANCE_MODE must be true or false"},
		{"invalid environment", "true", "staging", "DEPLOYMENT_ENVIRONMENT must be development or production"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(func(key string) (string, bool) {
				switch key {
				case "DEPLOYMENT_ENVIRONMENT":
					return tt.environment, true
				case "IDENTITY_MAINTENANCE_MODE":
					return tt.flag, tt.flag != ""
				default:
					return "", false
				}
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("error = %v, want %q", err, tt.wantError)
			}
		})
	}
}
