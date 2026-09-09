package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sarnas-it/guardrail/internal/config"
	"github.com/sarnas-it/guardrail/internal/engine"
	"github.com/sarnas-it/guardrail/internal/git"
	"github.com/sarnas-it/guardrail/internal/names"
	"github.com/sarnas-it/guardrail/internal/output"
	"github.com/sarnas-it/guardrail/internal/rules"
)

// Run выполняет сканирование репозитория в repoDir.
// base/head могут быть пустыми: head=HEAD, base=родитель или EmptyTree.
// configPath, sarifFile, jsonFile (если относительные) резолвятся относительно repoDir.
// Возвращает exit-код 0/1 и error (код 2) для ошибок выполнения.
func Run(repoDir, base, head, configPath, sarifFile, jsonFile string, reveal bool) (int, error) {
	rs, err := rules.LoadDefault()
	if err != nil {
		return 2, err
	}
	runner := git.New(repoDir)

	head, err = ResolveHead(runner, head)
	if err != nil {
		return 2, err
	}
	base, err = ResolveBase(runner, head, base)
	if err != nil {
		return 2, err
	}

	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(repoDir, p)
	}

	cfg := config.Default()
	cfgDir := "."
	if configPath != "" {
		cfgDir = filepath.Dir(abs(configPath))
		cfg, err = config.Load(abs(configPath), rs)
		if err != nil {
			return 2, err
		}
	}

	var ns *names.Set
	if cfg.Names.SurnamesFile != "" || cfg.Names.GivenNamesFile != "" || cfg.Names.PatronymicsFile != "" {
		ns, err = names.Load(cfgDir,
			cfg.Names.SurnamesFile, cfg.Names.GivenNamesFile,
			cfg.Names.PatronymicsFile, cfg.Names.ExclusionsFile,
			cfg.Names.MinMatches, cfg.Names.Window)
		if err != nil {
			return 2, err
		}
	}

	res, err := engine.Scan(engine.Options{
		RepoDir: repoDir,
		Base:    base,
		Head:    head,
		Cfg:     cfg,
		RS:      rs,
		Runner:  runner,
		Names:   ns,
	})
	if err != nil {
		return 2, err
	}

	reveal = reveal || cfg.Output.Reveal
	block, warn := output.WriteText(os.Stdout, res.Findings, reveal)
	fmt.Fprintf(os.Stderr, "guardrail: %d finding(s) allowed by allowlist\n", res.Allowed)

	if sarifFile == "" {
		sarifFile = cfg.Output.SarifFile
	}
	if sarifFile != "" {
		sarifFile = abs(sarifFile)
		if dir := filepath.Dir(sarifFile); dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return 2, err
			}
		}
		f, err := os.Create(sarifFile)
		if err != nil {
			return 2, err
		}
		if err := output.WriteSARIF(f, res.Findings, rs, reveal); err != nil {
			f.Close()
			return 2, err
		}
		if err := f.Close(); err != nil {
			return 2, err
		}
	}
	if jsonFile != "" {
		jsonFile = abs(jsonFile)
		f, err := os.Create(jsonFile)
		if err != nil {
			return 2, err
		}
		if err := output.WriteJSON(f, res.Findings, reveal); err != nil {
			f.Close()
			return 2, err
		}
		if err := f.Close(); err != nil {
			return 2, err
		}
	}

	if block > 0 {
		return 1, nil
	}
	_ = warn
	return 0, nil
}

func ResolveHead(runner *git.Runner, given string) (string, error) {
	if given != "" {
		if !runner.RevExists(given) {
			return "", fmt.Errorf("head revision %q does not exist", given)
		}
		return given, nil
	}
	if runner.RevExists("HEAD") {
		out, err := runner.RevParse("HEAD")
		if err != nil {
			return "", err
		}
		return out, nil
	}
	return "", fmt.Errorf("no HEAD and no --head given")
}

func ResolveBase(runner *git.Runner, head, given string) (string, error) {
	if given != "" {
		return given, nil
	}
	return runner.ParentOrEmpty(head)
}
