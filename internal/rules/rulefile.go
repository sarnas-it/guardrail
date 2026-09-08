package rules

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"
)

//go:embed defaults/*.yaml
var defaultFS embed.FS

// LoadDefault загружает и компилирует встроенные правила из defaults/.
func LoadDefault() (*RuleSet, error) {
	return LoadFS(defaultFS)
}

// LoadFS читает все файлы *.yaml из fsys и собирает отсортированный RuleSet.
func LoadFS(fsys fs.FS) (*RuleSet, error) {
	var files []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".yaml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	rs := &RuleSet{byID: map[string]*Rule{}}
	for _, f := range files {
		data, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		if err := rs.parseYAML(f, data); err != nil {
			return nil, err
		}
	}
	rs.rules = rs.byIDList()
	return rs, nil
}

// parseYAML разбирает один файл и добавляет его правила в rs.byID.
func (rs *RuleSet) parseYAML(file string, data []byte) error {
	var fw fileRules
	if err := yaml.Unmarshal(data, &fw); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	for _, fr := range fw.Rules {
		if fr.ID == "" {
			return errors.New(file + ": rule missing id")
		}
		if fr.Category != CategorySecret && fr.Category != CategoryPII {
			return fmt.Errorf("%s: rule %q: bad category %q", file, fr.ID, fr.Category)
		}
		if fr.Severity != SeverityBlock && fr.Severity != SeverityWarn {
			return fmt.Errorf("%s: rule %q: bad severity %q", file, fr.ID, fr.Severity)
		}
		if fr.Regex == "" {
			return fmt.Errorf("%s: rule %q: missing regex", file, fr.ID)
		}
		re, err := regexp.Compile(fr.Regex)
		if err != nil {
			return fmt.Errorf("%s: rule %q: bad regex: %w", file, fr.ID, err)
		}
		if _, dup := rs.byID[fr.ID]; dup {
			return fmt.Errorf("%s: duplicate rule id %q", file, fr.ID)
		}
		rs.byID[fr.ID] = &Rule{
			ID:          fr.ID,
			Category:    fr.Category,
			Severity:    fr.Severity,
			Description: fr.Description,
			Keywords:    fr.Keywords,
			EntropyMin:  fr.EntropyMin,
			Regex:       re,
		}
	}
	return nil
}

// byIDList возвращает правила, отсортированные по ID.
func (rs *RuleSet) byIDList() []*Rule {
	ids := make([]string, 0, len(rs.byID))
	for id := range rs.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*Rule, 0, len(ids))
	for _, id := range ids {
		out = append(out, rs.byID[id])
	}
	return out
}
