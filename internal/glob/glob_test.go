package glob

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"vendor/**", "vendor/foo/bar.go", true},
		{"vendor/**", "vendor/x.go", true},
		{"vendor/**", "src/vendor/x.go", false},
		{"**/*.min.js", "static/app.min.js", true},
		{"**/*.min.js", "static/app.js", false},
		{"*.go", "main.go", true},
		{"*.go", "internal/x/main.go", false},
		{"internal/**", "internal/x/main.go", true},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.name); got != c.want {
			t.Fatalf("Match(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}
