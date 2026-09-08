package glob

import "strings"

// Match сравнивает pattern с именем файла/пути (разделитель '/'),
// поддерживая '*' (в пределах сегмента) и '**' (любое число сегментов).
func Match(pattern, name string) bool {
	return match(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func match(pat, name []string) bool {
	if len(pat) == 0 {
		return len(name) == 0
	}
	switch pat[0] {
	case "**":
		// ** съедает ноль и более сегментов.
		if match(pat[1:], name) {
			return true
		}
		if len(name) == 0 {
			return false
		}
		return match(pat, name[1:])
	case "*":
		if len(name) == 0 {
			return false
		}
		return match(pat[1:], name[1:])
	default:
		if len(name) == 0 || !segment(pat[0], name[0]) {
			return false
		}
		return match(pat[1:], name[1:])
	}
}

func segment(p, n string) bool {
	return simple(p, n)
}

func simple(p, s string) bool {
	for len(p) > 0 {
		if p[0] == '*' {
			for i := 0; i <= len(s); i++ {
				if simple(p[1:], s[i:]) {
					return true
				}
			}
			return false
		}
		if len(s) == 0 {
			return false
		}
		if p[0] == '?' || p[0] == s[0] {
			p, s = p[1:], s[1:]
			continue
		}
		return false
	}
	return len(s) == 0
}
