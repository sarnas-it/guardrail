package names

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Load читает файлы словарей. configDir — директория guardrail.yml,
// относительно которой резолвятся относительные пути. Пустая строка пути
// означает «категория не задана». Если заданный путь пуст после
// нормализации (пустой файл) категория остаётся пустой.
func Load(configDir, surnamesFile, givenNamesFile, patronymicsFile, exclusionsFile string, minMatches, window int) (*Set, error) {
	if minMatches == 0 {
		minMatches = 2
	}
	if window == 0 {
		window = 4
	}
	s := &Set{
		surnames:    map[string]struct{}{},
		givenNames:  map[string]struct{}{},
		patronymics: map[string]struct{}{},
		exclusions:  map[string]struct{}{},
		MinMatches:  minMatches,
		Window:      window,
	}
	var err error
	if s.surnames, err = readList(resolve(configDir, surnamesFile)); err != nil {
		return nil, fmt.Errorf("surnames_file: %w", err)
	}
	if s.givenNames, err = readList(resolve(configDir, givenNamesFile)); err != nil {
		return nil, fmt.Errorf("given_names_file: %w", err)
	}
	if s.patronymics, err = readList(resolve(configDir, patronymicsFile)); err != nil {
		return nil, fmt.Errorf("patronymics_file: %w", err)
	}
	if s.exclusions, err = readList(resolve(configDir, exclusionsFile)); err != nil {
		return nil, fmt.Errorf("exclusions_file: %w", err)
	}
	s.active = len(s.surnames) > 0 && len(s.givenNames) > 0 && len(s.patronymics) > 0
	return s, nil
}

func resolve(configDir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(configDir, path)
}

// readList читает файл: одна запись на строку, нормализация normalize.
// path == "" → пустой список без ошибки. Несуществующий файл → error.
func readList(path string) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		n := normalize(line)
		if n != "" {
			out[n] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
