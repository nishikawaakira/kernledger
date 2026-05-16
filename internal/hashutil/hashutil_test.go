package hashutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBytesSHA256(t *testing.T) {
	// Known: SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	got := BytesSHA256([]byte("hello"))
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestFileSHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, n, err := FileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("size = %d, want 5", n)
	}
	if got != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Errorf("got %s", got)
	}
}
