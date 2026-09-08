package entropy

import (
	"math"
	"testing"
)

func TestShannonKnownValues(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"aaaa", 0},
		{"ab", 1},
		{"abcd", 2},
	}
	for _, c := range cases {
		got := Shannon(c.in)
		if math.Abs(got-c.want) > 1e-9 {
			t.Fatalf("Shannon(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
