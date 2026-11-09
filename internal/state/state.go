// Package state remembers what earlier runs reported, so scheduled scans
// only surface what's new. It stores fingerprints, never secrets.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

type record struct {
	Rule      string `json:"rule"`
	Status    string `json:"status"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// File is a loaded state file.
type File struct {
	path    string
	mu      sync.Mutex
	Seen    map[string]*record `json:"seen"`
	Version int                `json:"version"`
	now     func() time.Time
	skipped int
}

// Load reads a state file, or starts an empty one if it doesn't exist yet.
func Load(path string) (*File, error) {
	f := &File{path: path, Seen: map[string]*record{}, Version: 1, now: time.Now}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, f); err != nil {
		return nil, errors.New("not a SecretSniffer state file: " + err.Error())
	}
	if f.Seen == nil {
		f.Seen = map[string]*record{}
	}
	return f, nil
}

// Fingerprint identifies a credential without storing it.
func Fingerprint(f *finding.Finding) string {
	h := sha256.New()
	h.Write([]byte(f.RuleID + "\x00" + f.Secret))
	keys := make([]string, 0, len(f.Parts))
	for k := range f.Parts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte("\x00" + k + "=" + f.Parts[k]))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func rank(s string) int {
	switch finding.Status(s) {
	case finding.Verified:
		return 2
	case finding.Likely:
		return 1
	}
	return 0
}

// IsNew records f and reports whether it should be shown: never seen, or
// its status improved since last time (likely -> verified). Dropped
// findings are never recorded.
func (s *File) IsNew(f *finding.Finding) bool {
	if f.Status == finding.Dropped {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	today := s.now().UTC().Format("2006-01-02")
	fp := Fingerprint(f)
	r, ok := s.Seen[fp]
	if !ok {
		s.Seen[fp] = &record{Rule: f.RuleID, Status: string(f.Status), FirstSeen: today, LastSeen: today}
		return true
	}
	r.LastSeen = today
	if rank(string(f.Status)) > rank(r.Status) {
		r.Status = string(f.Status)
		return true
	}
	s.skipped++
	return false
}

// Skipped is how many findings were hidden because an earlier run reported them.
func (s *File) Skipped() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.skipped
}

// Save writes the state atomically.
func (s *File) Save() error {
	s.mu.Lock()
	data, err := json.MarshalIndent(s, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".secretsniffer-state-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()
	return os.Rename(tmp.Name(), s.path)
}
