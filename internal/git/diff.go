package git

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// maxDiffLineBytes — максимальная длина одной строки диффа. Строка длиннее
// сигнализирует об ошибке (errLineTooLong), а не молча отбрасывается: для
// сканера секретов потерянная добавленная строка — пропущенная утечка.
const maxDiffLineBytes = 1024 * 1024

var errLineTooLong = errors.New("diff line exceeds scanner limit; refusing to silently drop it")

type AddedLine struct {
	Path string
	Line int
	Text string
}

// parseDiffHunks разбирает unified-дифф (git diff -U0 --no-color base head)
// и возвращает добавленные строки с номерами строк в новой версии файла.
func parseDiffHunks(diff []byte) ([]AddedLine, error) {
	var out []AddedLine
	sc := bufio.NewScanner(bytes.NewReader(diff))
	sc.Buffer(make([]byte, maxDiffLineBytes), maxDiffLineBytes)

	var path string
	var newLine int
	inHunk := false

	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "+++ "):
			path = parseNewPath(line)
		case strings.HasPrefix(line, "@@ "):
			start, ok := parseHunkNewStart(line)
			if !ok {
				continue
			}
			newLine = start
			inHunk = true
		default:
			if !inHunk {
				continue
			}
			switch {
			case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
				out = append(out, AddedLine{Path: path, Line: newLine, Text: strings.TrimPrefix(line, "+")})
				newLine++
			case strings.HasPrefix(line, "-"):
				// удалённые строки не двигают счётчик новой версии
			case strings.HasPrefix(line, "\\"):
				// маркер "No newline at end of file"
			default:
				newLine++
			}
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, errLineTooLong
		}
		return nil, fmt.Errorf("scan diff: %w", err)
	}
	return out, nil
}

func parseNewPath(header string) string {
	p := strings.TrimSpace(strings.TrimPrefix(header, "+++ "))
	p = strings.TrimPrefix(p, "b/")
	// git может выводить кавычки для спецсимволов; в MVP не декодируем.
	return p
}

// parseHunkNewStart извлекает стартовую строку новой стороны из "@@ -a,b +c,d @@".
func parseHunkNewStart(hunk string) (int, bool) {
	parts := strings.Split(hunk, " ")
	if len(parts) < 3 {
		return 0, false
	}
	newPart := strings.TrimPrefix(parts[2], "+")
	comma := strings.IndexByte(newPart, ',')
	if comma >= 0 {
		newPart = newPart[:comma]
	}
	n, err := strconv.Atoi(newPart)
	if err != nil {
		return 0, false
	}
	return n, true
}
