package entropy

import "math"

// Shannon возвращает энтропию Шеннона строки в битах на символ.
// Для пустой строки возвращает 0.
func Shannon(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	n := len([]rune(s))
	var h float64
	for _, c := range freq {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}
