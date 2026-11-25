//go:build windows

package collector

import (
	"context"
	"testing"
)

func TestFrameworkLegacyHashesKnownIISVector(t *testing.T) {
	t.Parallel()
	applicationHash, applicationIDHash, err := frameworkLegacyHashes(
		context.Background(),
		"/",
		"/LM/W3SVC/1/ROOT",
	)
	if err != nil {
		t.Fatal(err)
	}
	if applicationHash != 0x4EBA98B2 {
		t.Fatalf("application hash = %08X, want 4EBA98B2", applicationHash)
	}
	if applicationIDHash != 0xB1BF55D3 {
		t.Fatalf("application ID hash = %08X, want B1BF55D3", applicationIDHash)
	}
}
