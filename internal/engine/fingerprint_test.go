package engine

import "testing"

func TestFingerprintStableAndDistinct(t *testing.T) {
	a := Fingerprint("aws_access_key", "x.yml", "AKIAIOSFODNN7EXAMPLE")
	b := Fingerprint("aws_access_key", "x.yml", "AKIAIOSFODNN7EXAMPLE")
	if a != b {
		t.Fatal("fingerprint must be stable")
	}
	c := Fingerprint("aws_access_key", "x.yml", "DIFFERENTVALUE")
	if a == c {
		t.Fatal("different value must differ")
	}
	d := Fingerprint("aws_access_key", "y.yml", "AKIAIOSFODNN7EXAMPLE")
	if a == d {
		t.Fatal("different file must differ")
	}
	if len(a) != 64 {
		t.Fatalf("expected sha256 hex (64), got %d", len(a))
	}
}
