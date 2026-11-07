package main

import (
	"context"
	"errors"
	"testing"
)

func TestSchemaMode(t *testing.T) {
	oldSchema := errors.New("schema version mismatch")
	for _, tt := range []struct {
		name                 string
		args                 []string
		readyError           error
		wantReady, wantApply int
		wantError            error
	}{
		{"check old schema", []string{"-check"}, oldSchema, 1, 0, oldSchema},
		{"check current schema", []string{"-check"}, nil, 1, 0, nil},
		{"default migrates", nil, oldSchema, 0, 1, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			check, err := parseCheck(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			readyCalls, applyCalls := 0, 0
			err = run(context.Background(), check, func(context.Context) error {
				readyCalls++
				return tt.readyError
			}, func(context.Context) error { applyCalls++; return nil })
			if !errors.Is(err, tt.wantError) || readyCalls != tt.wantReady || applyCalls != tt.wantApply {
				t.Fatalf("error=%v ready=%d apply=%d", err, readyCalls, applyCalls)
			}
		})
	}
}

func TestRejectUnknownArguments(t *testing.T) {
	for _, args := range [][]string{{"-unknown"}, {"unexpected"}, {"-check", "unexpected"}, {"-check=invalid"}} {
		if _, err := parseCheck(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
}

func TestMigrationFailure(t *testing.T) {
	want := errors.New("migration failed")
	calls := 0
	err := run(context.Background(), false, func(context.Context) error {
		t.Fatal("migration must not call readiness")
		return nil
	}, func(context.Context) error {
		calls++
		return want
	})
	if !errors.Is(err, want) || calls != 1 {
		t.Fatalf("error=%v apply=%d", err, calls)
	}
}
