package names

type Categories int

const (
	Surname Categories = 1 << iota
	GivenName
	Patronymic
)

type Set struct {
	surnames    map[string]struct{}
	givenNames  map[string]struct{}
	patronymics map[string]struct{}
	exclusions  map[string]struct{}
	MinMatches  int
	Window      int
	active      bool
}

// Active сообщает, что загружены все три списка (непустые) — только тогда
// правило full_name_ru может срабатывать.
func (s *Set) Active() bool { return s != nil && s.active }

// Classify возвращает битмаску категорий для токена. Пустой/неизвестный → 0.
func (s *Set) Classify(token string) Categories {
	n := normalize(token)
	var c Categories
	if _, ok := s.surnames[n]; ok {
		c |= Surname
	}
	if _, ok := s.givenNames[n]; ok {
		c |= GivenName
	}
	if _, ok := s.patronymics[n]; ok {
		c |= Patronymic
	}
	return c
}

// IsExcluded проверяет нормализованную фразу по списку исключений.
func (s *Set) IsExcluded(phrase string) bool {
	if s == nil {
		return false
	}
	_, ok := s.exclusions[normalize(phrase)]
	return ok
}

// normalize приводит к нижнему регистру и оставляет только буквы.
// Для целых фраз исключений пробелы сохраняются.
func normalize(s string) string {
	runes := make([]rune, 0, len(s))
	inSpace := false
	for _, r := range s {
		switch {
		case r >= 'а' && r <= 'я' || r >= 'А' && r <= 'Я' || r == 'ё' || r == 'Ё':
			if inSpace && len(runes) > 0 {
				runes = append(runes, ' ')
			}
			inSpace = false
			runes = append(runes, toLower(r))
		case r == ' ' || r == '\t':
			inSpace = true
		}
	}
	return string(runes)
}

func toLower(r rune) rune {
	if r >= 'А' && r <= 'Я' {
		return r + ('а' - 'А')
	}
	if r == 'Ё' {
		return 'ё'
	}
	return r
}
