package main

import "testing"

func TestDefaultConfigPath(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"unset INPUT_CONFIG defaults to repo root", "", "guardrail.yml"},
		{"INPUT_CONFIG wins over repo-root default", ".github/guardrail.yml", ".github/guardrail.yml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("INPUT_CONFIG", tc.input)
			if got := defaultConfigPath(tc.input); got != tc.want {
				t.Fatalf("defaultConfigPath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
