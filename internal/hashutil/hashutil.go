// Package hashutil computes SHA-256 hashes for evidence files.
//
// Evidence integrity is non-negotiable for IR work. Every artifact
// referenced from a manifest MUST have a hash computed by this package.
package hashutil

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// FileSHA256 streams the file and returns the lowercase hex digest.
// Streaming (not reading into memory) matters because memory images
// can be tens of GiB.
func FileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// BytesSHA256 returns the hex digest of an in-memory blob.
func BytesSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
