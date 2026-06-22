package download

import "testing"

func TestNormalizeUploadIDRejectsEmptyValue(t *testing.T) {
	if _, err := normalizeUploadID("   "); err == nil {
		t.Fatal("expected empty upload id rejection")
	}
}

func TestNormalizeUploadIDReplacesUnsafeCharacters(t *testing.T) {
	got, err := normalizeUploadID("a/b c")
	if err != nil {
		t.Fatalf("normalize upload id: %v", err)
	}
	if got != "a_b_c" {
		t.Fatalf("unexpected normalized id: %q", got)
	}
}
