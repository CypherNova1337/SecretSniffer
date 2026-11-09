package source

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/CypherNova1337/SecretSniffer/internal/engine"
	"github.com/CypherNova1337/SecretSniffer/internal/finding"
)

// IsRemoteRepo reports whether s looks like something git can clone.
func IsRemoteRepo(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "git@") || strings.HasPrefix(s, "ssh://") || strings.HasPrefix(s, "git://")
}

// Git scans every line ever added in every commit on every branch of a
// repository, so secrets that were "removed" in a later commit are still
// found. Remote repositories are cloned (bare) into a temporary directory.
func Git(ctx context.Context, repo string, maxBytes int64, out chan<- engine.Chunk, logf func(string, ...any)) error {
	if _, err := exec.LookPath("git"); err != nil {
		return errors.New("git is not installed")
	}
	dir := repo
	if IsRemoteRepo(repo) {
		tmp, err := os.MkdirTemp("", "secretsniffer-git-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		if logf != nil {
			logf("cloning %s", repo)
		}
		cmd := exec.CommandContext(ctx, "git", "clone", "--bare", "--quiet", repo, tmp)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if msg, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("clone %s: %v: %s", repo, err, strings.TrimSpace(string(msg)))
		}
		dir = tmp
	}

	cmd := exec.CommandContext(ctx, "git", "-C", dir, "log", "--all", "--full-history", "-p", "-U0",
		"--no-color", "--no-ext-diff", "--no-renames", "--format=\x1ecommit\x1f%H\x1f%an <%ae>\x1f%aI")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	parseGitLog(stdout, repo, maxBytes, out)
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("git log in %s: %v: %s", repo, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func parseGitLog(r io.Reader, repo string, maxBytes int64, out chan<- engine.Chunk) {
	br := bufio.NewReaderSize(r, 1<<20)
	var (
		commit, author, date, file string
		buf                        strings.Builder
		lines                      []int
		next                       int
		inHeader                   bool
	)
	flush := func() {
		if file != "" && buf.Len() > 0 {
			out <- engine.Chunk{
				Loc:   finding.Location{Source: repo, Commit: commit, Author: author, Date: date, File: file},
				Data:  []byte(buf.String()),
				Lines: lines,
				Local: true,
			}
		}
		buf.Reset()
		lines = nil
	}
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			line = strings.TrimSuffix(line, "\n")
			switch {
			case strings.HasPrefix(line, "\x1ecommit\x1f"):
				flush()
				f := strings.Split(line, "\x1f")
				if len(f) >= 4 {
					commit, author, date = f[1], f[2], f[3]
				}
				file = ""
			case strings.HasPrefix(line, "diff --git "):
				flush()
				file = ""
				inHeader = true
			case inHeader && strings.HasPrefix(line, "+++ "):
				p := strings.TrimPrefix(line, "+++ ")
				if p == "/dev/null" {
					file = ""
				} else {
					file = strings.TrimPrefix(p, "b/")
				}
			case strings.HasPrefix(line, "@@ "):
				inHeader = false
				next = hunkStart(line)
			case !inHeader && strings.HasPrefix(line, "+") && file != "":
				if int64(buf.Len()) < maxBytes {
					buf.WriteString(line[1:])
					buf.WriteByte('\n')
					lines = append(lines, next)
				}
				next++
			}
		}
		if err != nil {
			break
		}
	}
	flush()
}

// hunkStart reads the new-file start line from "@@ -a,b +c,d @@".
func hunkStart(h string) int {
	i := strings.Index(h, " +")
	if i < 0 {
		return 1
	}
	s := h[i+2:]
	end := strings.IndexAny(s, ", ")
	if end >= 0 {
		s = s[:end]
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 1
	}
	return n
}
