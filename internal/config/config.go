package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sarnas-it/guardrail/internal/rules"
	"gopkg.in/yaml.v3"
)

type IgnoreMatch struct {
	Rule        string `yaml:"rule"`
	Path        string `yaml:"path"`
	Line        int    `yaml:"line"`
	Fingerprint string `yaml:"fingerprint"`
	Reason      string `yaml:"reason"`
	Until       string `yaml:"until"`
}

type IgnoreConfig struct {
	Paths   []string      `yaml:"paths"`
	Matches []IgnoreMatch `yaml:"matches"`
}

type ScanConfig struct {
	MaxFileSizeKB     int      `yaml:"max_file_size_kb"`
	ExtraIgnoredPaths []string `yaml:"extra_ignored_paths"`
}

type OutputConfig struct {
	SarifFile string `yaml:"sarif_file"`
	Reveal    bool   `yaml:"reveal"`
}

type Config struct {
	Severity map[string]string `yaml:"severity"`
	Ignore   IgnoreConfig      `yaml:"ignore"`
	Scan     ScanConfig        `yaml:"scan"`
	Output   OutputConfig      `yaml:"output"`
}

func Default() *Config {
	return &Config{
		Severity: map[string]string{},
	}
}

// Load читает конфиг. Если файла нет — возвращает Default(). Валидирует
// severity-ключи и rule в allowlist по известным правилам. Неизвестные поля
// YAML считаются ошибкой (KnownFields).
func Load(path string, rs *rules.RuleSet) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return validate(cfg, rs)
}

func validate(cfg *Config, rs *rules.RuleSet) (*Config, error) {
	var unknown []string
	for id, v := range cfg.Severity {
		if _, ok := rs.Get(id); !ok {
			unknown = append(unknown, id)
		}
		if v != "block" && v != "warn" && v != "off" {
			return nil, fmt.Errorf("severity override for %q must be block|warn|off, got %q", id, v)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown rule id(s) in severity: %s", strings.Join(unknown, ", "))
	}
	for _, m := range cfg.Ignore.Matches {
		if m.Rule == "" {
			return nil, errors.New("ignore.matches entry missing rule")
		}
		if _, ok := rs.Get(m.Rule); !ok {
			return nil, fmt.Errorf("unknown rule id %q in ignore.matches", m.Rule)
		}
	}
	return cfg, nil
}
