package engine

import (
	"strings"
	"time"

	"github.com/sarnas-it/guardrail/internal/config"
	"github.com/sarnas-it/guardrail/internal/glob"
)

var builtinIgnoredPaths = []string{
	"**/go.sum", "**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml",
	"**/Cargo.lock", "**/composer.lock", "**/Gemfile.lock", "**/poetry.lock",
	"**/*.min.js", "**/*.map", "**/*.svg", "**/*.png", "**/*.jpg",
	"**/*.jpeg", "**/*.gif", "**/*.webp", "**/*.ico", "**/*.woff",
	"**/*.woff2", "**/*.ttf", "**/*.eot",
}

func IsPathIgnored(cfg *config.Config, path string) bool {
	p := strings.TrimPrefix(path, "/")
	for _, pat := range builtinIgnoredPaths {
		if glob.Match(pat, p) {
			return true
		}
	}
	for _, pat := range cfg.Scan.ExtraIgnoredPaths {
		if glob.Match(pat, p) {
			return true
		}
	}
	for _, pat := range cfg.Ignore.Paths {
		if glob.Match(pat, p) {
			return true
		}
	}
	return false
}

// IsAllowed проверяет, попадает ли находка под ignore.matches.
// Записи с until в прошлом считаются неактивными.
func IsAllowed(cfg *config.Config, f Finding) bool {
	for _, m := range cfg.Ignore.Matches {
		if m.Rule != f.RuleID {
			continue
		}
		if m.Until != "" {
			d, err := time.Parse("2006-01-02", m.Until)
			if err == nil && time.Now().After(d.Add(24*time.Hour)) {
				continue
			}
		}
		if m.Fingerprint != "" {
			if m.Fingerprint == f.Fingerprint {
				return true
			}
			continue
		}
		pathOK := m.Path == "" || glob.Match(m.Path, f.File) || m.Path == f.File
		lineOK := m.Line == 0 || m.Line == f.Line
		if pathOK && lineOK {
			return true
		}
	}
	return false
}
