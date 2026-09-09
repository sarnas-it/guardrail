package detect

import (
	"strings"
	"unicode/utf8"

	"github.com/sarnas-it/guardrail/internal/names"
	"github.com/sarnas-it/guardrail/internal/rules"
)

type token struct {
	word      string // нормализованные буквы токена (нижний регистр)
	mask      names.Categories
	byteStart int
	byteEnd   int
}

// FullName ищет в строке окно из set.Window соседних кириллических токенов,
// в котором >= set.MinMatches РАЗЛИЧНЫХ категорий имён представлены как
// минимум двумя разными токенами. Возвращает не более одного Match на строку
// с нормализованной фразой-кандидатом. Возвращает nil, если set не активен
// или совпадения нет.
func FullName(line string, set *names.Set, rule *rules.Rule) []Match {
	if set == nil || !set.Active() {
		return nil
	}
	toks := tokenize(line, set) // все кириллические токены строки
	if len(toks) == 0 {
		return nil
	}
	window := set.Window
	if window < 2 {
		window = 2
	}

	// Ищем первое окно, где набралось >= MinMatches категорий от >= 2 токенов.
	bestStart, bestEnd := -1, -1
	for start := 0; start < len(toks); start++ {
		var union names.Categories
		named := 0
		// Внутренний цикл намеренно доходит до края окна без break на первом
		// кандидате: bestStart/bestEnd перезаписываются при каждом расширении,
		// оставляя максимальный span для последующей обрезки к именным границам.
		for end := start; end < len(toks) && end-start < window; end++ {
			if toks[end].mask != 0 {
				named++
			}
			union |= toks[end].mask
			if named >= 2 && popcount(union) >= set.MinMatches {
				bestStart, bestEnd = start, end
			}
		}
		if bestStart >= 0 {
			break
		}
	}
	if bestStart < 0 {
		return nil
	}

	// Исключения сравниваются с полной фразой целиком (см. names.IsExcluded),
	// поэтому span держится максимальным: если соседний словарный токен
	// расширяет фразу (например, «Мария Анна Каренина»), она уже не совпадёт
	// с исключением «анна каренина» и будет найдена — это осознанное решение.
	// Сокращаем окно до первой/последней именной границы, оставляя порог.
	first := bestStart
	for first < bestEnd && toks[first].mask == 0 {
		first++
	}
	last := bestEnd
	for last > first && toks[last].mask == 0 {
		last--
	}
	phrase := phraseOf(toks[first : last+1])
	if phrase == "" || set.IsExcluded(phrase) {
		return nil
	}
	return []Match{{
		Rule:  rule,
		Value: phrase,
		Start: toks[first].byteStart,
		End:   toks[last].byteEnd,
	}}
}

// tokenize проходит строку по байтам, выделяя все кириллические
// последовательности букв (служебные слова тоже — они раздвигают окно),
// классифицирует каждую по словарям и запоминает байтовые границы.
func tokenize(line string, set *names.Set) []token {
	var out []token
	i := 0
	for i < len(line) {
		r, size := utf8.DecodeRuneInString(line[i:])
		if !isLetter(r) {
			i += size
			continue
		}
		start := i
		for i < len(line) {
			r, size = utf8.DecodeRuneInString(line[i:])
			if !isLetter(r) {
				break
			}
			i += size
		}
		word := strings.ToLower(line[start:i])
		out = append(out, token{word: word, mask: set.Classify(word), byteStart: start, byteEnd: i})
	}
	return out
}

func isLetter(r rune) bool {
	return r >= 'а' && r <= 'я' || r >= 'А' && r <= 'Я' || r == 'ё' || r == 'Ё'
}

// phraseOf собирает нормализованную фразу (нижний регистр, токены через пробел).
func phraseOf(toks []token) string {
	if len(toks) == 0 {
		return ""
	}
	var b strings.Builder
	for i, t := range toks {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(t.word)
	}
	return b.String()
}

func popcount(c names.Categories) int {
	n := int(c)
	cnt := 0
	for n > 0 {
		cnt += n & 1
		n >>= 1
	}
	return cnt
}
