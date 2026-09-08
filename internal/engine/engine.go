package engine

import (
	"sort"

	"github.com/sarnas-it/guardrail/internal/config"
	"github.com/sarnas-it/guardrail/internal/detect"
	"github.com/sarnas-it/guardrail/internal/git"
	"github.com/sarnas-it/guardrail/internal/rules"
)

type Finding struct {
	RuleID      string
	Category    rules.Category
	Severity    rules.Severity
	Description string
	File        string
	Line        int
	Value       string
	Fingerprint string
}

type Options struct {
	RepoDir string
	Base    string
	Head    string
	Cfg     *config.Config
	RS      *rules.RuleSet
	Runner  *git.Runner
}

type Result struct {
	Findings []Finding
	Allowed  int
}

func Scan(opts Options) (*Result, error) {
	runner := opts.Runner
	if runner == nil {
		runner = git.New(opts.RepoDir)
	}
	cfg := opts.Cfg
	if cfg == nil {
		cfg = config.Default()
	}

	lines, err := runner.AddedLines(opts.Base, opts.Head)
	if err != nil {
		return nil, err
	}

	// Дропаем строки игнорируемых файлов и слишком больших.
	filtered := make([]git.AddedLine, 0, len(lines))
	for _, l := range lines {
		if IsPathIgnored(cfg, l.Path) {
			continue
		}
		if cfg.Scan.MaxFileSizeKB > 0 {
			sz, err := runner.BlobSize(opts.Head, l.Path)
			if err != nil {
				continue // файл мог быть удалён в head — пропускаем
			}
			if sz > int64(cfg.Scan.MaxFileSizeKB)*1024 {
				continue
			}
		}
		filtered = append(filtered, l)
	}

	seen := map[string]bool{}
	var res Result
	for _, l := range filtered {
		ms := detect.Line(opts.RS, l.Text)
		for _, m := range ms {
			sev := effectiveSeverity(cfg, m.Rule)
			if sev == "" {
				continue
			}
			fp := Fingerprint(m.Rule.ID, l.Path, m.Value)
			if seen[fp] {
				continue
			}
			seen[fp] = true
			f := Finding{
				RuleID:      m.Rule.ID,
				Category:    m.Rule.Category,
				Severity:    sev,
				Description: m.Rule.Description,
				File:        l.Path,
				Line:        l.Line,
				Value:       m.Value,
				Fingerprint: fp,
			}
			if IsAllowed(cfg, f) {
				res.Allowed++
				continue
			}
			res.Findings = append(res.Findings, f)
		}
	}

	sort.Slice(res.Findings, func(i, j int) bool {
		if res.Findings[i].File != res.Findings[j].File {
			return res.Findings[i].File < res.Findings[j].File
		}
		if res.Findings[i].Line != res.Findings[j].Line {
			return res.Findings[i].Line < res.Findings[j].Line
		}
		return res.Findings[i].RuleID < res.Findings[j].RuleID
	})
	return &res, nil
}

// effectiveSeverity возвращает severity правила с учётом конфига:
// "" означает отключено (off).
func effectiveSeverity(cfg *config.Config, r *rules.Rule) rules.Severity {
	if v, ok := cfg.Severity[r.ID]; ok {
		switch v {
		case "block":
			return rules.SeverityBlock
		case "warn":
			return rules.SeverityWarn
		case "off":
			return ""
		}
	}
	return r.Severity
}
