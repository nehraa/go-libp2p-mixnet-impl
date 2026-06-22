package upload

import (
	"strings"
	"testing"
)

func TestNormalizeUploadIDTrimsAndSanitizes(t *testing.T) {
	got, err := normalizeUploadID("  shard/../upload  ")
	if err != nil {
		t.Fatalf("normalize upload id: %v", err)
	}
	if got != "shard_.._upload" {
		t.Fatalf("unexpected normalized id: %q", got)
	}
}

func TestNormalizeUploadIDRejectsEmptyValue(t *testing.T) {
	_, err := normalizeUploadID("   ")
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected required validation error, got %v", err)
	}
}

func TestNormalizeUploadIDRejectsLongValue(t *testing.T) {
	_, err := normalizeUploadID(strings.Repeat("a", maxUploadIDLen+1))
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("expected length validation error, got %v", err)
	}
}
