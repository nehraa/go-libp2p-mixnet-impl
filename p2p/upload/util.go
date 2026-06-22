package upload

import (
	"fmt"
	"strings"
	"unicode"
)

func normalizeUploadID(uploadID string) (string, error) {
	trimmed := strings.TrimSpace(uploadID)
	if trimmed == "" {
		return "", fmt.Errorf("%w: upload id is required", ErrInvalidRequest)
	}
	if len(trimmed) > maxUploadIDLen {
		return "", fmt.Errorf("%w: upload id too long", ErrInvalidRequest)
	}

	var b strings.Builder
	b.Grow(len(trimmed))
	for _, r := range trimmed {
		switch {
		case unicode.IsLetter(r), unicode.IsNumber(r):
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	id := b.String()
	if id == "" {
		return "", fmt.Errorf("%w: upload id normalized to empty value", ErrInvalidRequest)
	}
	return id, nil
}
