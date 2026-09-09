package rules

import (
	"fmt"
	"regexp"
)

type Category string

const (
	CategorySecret Category = "secret"
	CategoryPII    Category = "pii"
)

type Severity string

const (
	SeverityBlock Severity = "block"
	SeverityWarn  Severity = "warn"
)

type RuleType string

const (
	RuleTypeRegex      RuleType = "regex"
	RuleTypeDictionary RuleType = "dictionary"
)

type Rule struct {
	ID          string
	Category    Category
	Severity    Severity
	Description string
	Type        RuleType
	Keywords    []string
	EntropyMin  float64
	Regex       *regexp.Regexp
}

// fileRule — структура YAML-записи правила в defaults/*.yaml.
type fileRule struct {
	ID          string   `yaml:"id"`
	Category    Category `yaml:"category"`
	Severity    Severity `yaml:"severity"`
	Description string   `yaml:"description"`
	Type        string   `yaml:"type"` // "regex" (default) | "dictionary"
	Regex       string   `yaml:"regex"`
	Keywords    []string `yaml:"keywords"`
	EntropyMin  float64  `yaml:"entropy_min"`
}

// fileRules — корневая структура YAML-файла правил.
type fileRules struct {
	Rules []fileRule `yaml:"rules"`
}

type RuleSet struct {
	rules []*Rule
	byID  map[string]*Rule
}

func (rs *RuleSet) Rules() []*Rule { return rs.rules }
func (rs *RuleSet) Get(id string) (*Rule, bool) {
	r, ok := rs.byID[id]
	return r, ok
}

func (rs *RuleSet) ValidateIDs(ids []string) error {
	for _, id := range ids {
		if _, ok := rs.byID[id]; !ok {
			return fmt.Errorf("unknown rule id %q", id)
		}
	}
	return nil
}
