package source

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/CypherNova1337/SecretSniffer/internal/engine"
	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".hg": true, ".svn": true,
	"__pycache__": true, ".venv": true, ".tox": true, ".gradle": true, ".idea": true,
}

var skipExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true,
	".bmp": true, ".tiff": true, ".svg": true, ".woff": true, ".woff2": true, ".ttf": true,
	".eot": true, ".otf": true, ".mp3": true, ".mp4": true, ".mov": true, ".avi": true,
	".webm": true, ".wav": true, ".flac": true, ".zip": true, ".gz": true, ".tgz": true,
	".bz2": true, ".xz": true, ".7z": true, ".rar": true, ".tar": true, ".pdf": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".class": true, ".pyc": true,
	".o": true, ".a": true, ".bin": true, ".iso": true, ".dmg": true, ".psd": true,
}

// Files walks paths (files or directories) and scans every text file.
func Files(ctx context.Context, paths []string, maxBytes int64, out chan<- engine.Chunk, logf func(string, ...any)) {
	for _, root := range paths {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if p != root && skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || skipExt[strings.ToLower(filepath.Ext(p))] {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() == 0 || info.Size() > maxBytes {
				if err == nil && info.Size() > maxBytes && logf != nil {
					logf("skipping %s: larger than the size limit", p)
				}
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil || isBinary(data) {
				return nil
			}
			if strings.HasSuffix(p, ".map") {
				if emitLocalMap(p, data, out) {
					return nil
				}
			}
			out <- engine.Chunk{Loc: finding.Location{Source: p}, Data: data, Local: true}
			return nil
		})
	}
}

func emitLocalMap(p string, data []byte, out chan<- engine.Chunk) bool {
	chunks := sourceMapChunks(p, data)
	for _, c := range chunks {
		c.Local = true
		out <- c
	}
	return len(chunks) > 0
}

func isBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(b[:n], 0) >= 0
}
