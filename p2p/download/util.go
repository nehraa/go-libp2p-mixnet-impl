package download

import (
	"fmt"
	"strings"
	"unicode"
)

const maxUploadIDLen = 512

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
	out := b.String()
	if out == "" {
		return "", fmt.Errorf("%w: upload id normalized to empty", ErrInvalidRequest)
	}
	return out, nil
}
