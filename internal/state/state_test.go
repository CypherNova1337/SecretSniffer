package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

func TestOnlyNewFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	f := &finding.Finding{RuleID: "stripe-key", Secret: "sk_live_supersecretvalue123", Status: finding.Likely}

	s1, _ := Load(path)
	if !s1.IsNew(f) {
		t.Fatal("first sighting must be new")
	}
	if err := s1.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), f.Secret) {
		t.Fatal("state file must not contain the secret")
	}

	s2, _ := Load(path)
	if s2.IsNew(f) || s2.Skipped() != 1 {
		t.Fatal("second sighting must be hidden")
	}
	upgraded := *f
	upgraded.Status = finding.Verified
	if !s2.IsNew(&upgraded) {
		t.Fatal("likely -> verified is news and must be shown")
	}
	other := *f
	other.Parts = map[string]string{"shop": "other.myshopify.com"}
	if !s2.IsNew(&other) {
		t.Fatal("same secret with a different pairing is a different finding")
	}
}

func TestRejectsGarbageStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(path, []byte("not json"), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error")
	}
}
