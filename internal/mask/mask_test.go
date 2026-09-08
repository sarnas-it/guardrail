package mask

import "testing"

func TestSecretMask(t *testing.T) {
	if got := Secret("AKIAIOSFODNN7EXAMPLE"); got != "AKIA…MPLE" {
		t.Fatalf("unexpected mask: %q", got)
	}
	if got := Secret("short"); got == "short" {
		t.Fatal("short value must not appear in clear")
	}
	if got := Secret("+7 999 123-45-67"); len(got) > 12 {
		t.Fatalf("mask too long: %q", got)
	}
}
