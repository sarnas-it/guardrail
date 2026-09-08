package mask

import "unicode/utf8"

// Secret маскирует строку: первые 4 и последние 4 руны, между ними '…'.
// Если рун <= 8 — возвращает фиксированный плейсхолдер.
func Secret(s string) string {
	n := utf8.RuneCountInString(s)
	if n <= 8 {
		return "<redacted>"
	}
	runes := []rune(s)
	return string(runes[:4]) + "…" + string(runes[n-4:])
}
