// Package testutil builds realistic-looking but fake credentials at runtime,
// so no token-shaped literal ever sits in the repository.
package testutil

import (
	"math/rand"
)

const (
	Alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	Hex   = "0123456789abcdef"
	B64   = Alnum + "+/"
)

var rng = rand.New(rand.NewSource(1337))

// Rand returns n random characters from set.
func Rand(set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[rng.Intn(len(set))]
	}
	return string(b)
}

// J joins parts; used to keep prefixes and bodies apart in source.
func J(parts ...string) string {
	s := ""
	for _, p := range parts {
		s += p
	}
	return s
}
