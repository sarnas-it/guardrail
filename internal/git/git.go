package git

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

const EmptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

type Runner struct{ Dir string }

func New(dir string) *Runner { return &Runner{Dir: dir} }

func (r *Runner) run(args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = r.Dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %v: %w: %s", args, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// AddedLines возвращает добавленные строки в диапазоне base..head.
// Используется diff от merge-base(base, head) до head (семантика base...head),
// чтобы сканировать только то, что принёс head. Если merge-base недоступен
// (нет общего предка), падает в diff base..head напрямую.
func (r *Runner) AddedLines(base, head string) ([]AddedLine, error) {
	diff, err := r.threeDotOrTwoDotDiff(base, head)
	if err != nil {
		return nil, err
	}
	return parseDiffHunks(diff), nil
}

func (r *Runner) threeDotOrTwoDotDiff(base, head string) ([]byte, error) {
	if base == EmptyTree {
		// Материализуем пустое дерево в объектной БД (hash-object без -w не хранит).
		if _, err := r.run("hash-object", "-w", "-t", "tree", "/dev/null"); err != nil {
			return nil, err
		}
		return r.run("diff", "--no-color", "-U0", "--no-ext-diff", EmptyTree, head)
	}
	mb, err := r.mergeBase(base, head)
	if err == nil && mb != "" {
		return r.run("diff", "--no-color", "-U0", "--no-ext-diff", mb, head)
	}
	// Нет общего предка — сравниваем напрямую.
	return r.run("diff", "--no-color", "-U0", "--no-ext-diff", base, head)
}

func (r *Runner) mergeBase(a, b string) (string, error) {
	out, err := r.run("merge-base", a, b)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// BlobSize возвращает размер блоба файла в указанной ревизии.
func (r *Runner) BlobSize(head, path string) (int64, error) {
	out, err := r.run("cat-file", "-s", head+":"+path)
	if err != nil {
		return 0, err
	}
	var n int64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &n); err != nil {
		return 0, fmt.Errorf("parse size %q: %w", out, err)
	}
	return n, nil
}

// RevExists проверяет существование ревизии (commit/дерева).
func (r *Runner) RevExists(rev string) bool {
	_, err := r.run("rev-parse", "--verify", "--quiet", rev)
	return err == nil
}

func (r *Runner) RevParse(rev string) (string, error) {
	out, err := r.run("rev-parse", rev)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// ParentOrEmpty возвращает родителя head, либо EmptyTree для корневого коммита.
func (r *Runner) ParentOrEmpty(head string) (string, error) {
	out, err := r.run("rev-parse", "--verify", "--quiet", head+"^")
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}
	return EmptyTree, nil
}
