package test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDocumentationSnippets executes every code snippet in the user-facing
// documentation against the current source tree:
//
//   - ```go blocks must be complete programs; each is vetted, built and run
//     inside a throwaway module that replaces the library with this checkout.
//   - ```bash blocks are executed in order, per document, in one shared
//     working directory with the freshly built CLI on PATH, under
//     `bash -euo pipefail`; any non-zero exit fails the test.
//   - ```sh blocks are illustrative (installation, cross-compilation, tools
//     that may be absent) and are only checked for balanced fences.
//
// Keep this list in sync with the documents that contain runnable snippets.
var documentedFiles = []string{"README.md", "CLI.md"}

type snippet struct {
	lang string
	line int
	code string
}

var fenceRE = regexp.MustCompile("^```([A-Za-z0-9_-]*)\\s*$")

func parseSnippets(t *testing.T, path string) []snippet {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []snippet
	var cur *snippet
	var buf []string
	for i, line := range strings.Split(string(data), "\n") {
		if cur == nil {
			if m := fenceRE.FindStringSubmatch(line); m != nil {
				cur = &snippet{lang: m[1], line: i + 1}
				buf = buf[:0]
			}
			continue
		}
		if strings.HasPrefix(line, "```") {
			cur.code = strings.Join(buf, "\n") + "\n"
			out = append(out, *cur)
			cur = nil
			continue
		}
		buf = append(buf, line)
	}
	if cur != nil {
		t.Fatalf("%s: unterminated code fence opened at line %d", path, cur.line)
	}
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestDocumentationSnippets(t *testing.T) {
	if testing.Short() {
		t.Skip("documentation snippets take a while; skipped with -short")
	}
	root := repoRoot(t)
	bin := filepath.Join(t.TempDir(), "k-mosaic-cli")
	build := exec.Command("go", "build", "-o", bin, "./cmd/k-mosaic-cli")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building CLI: %v\n%s", err, out)
	}

	for _, doc := range documentedFiles {
		doc := doc
		t.Run(doc, func(t *testing.T) {
			snippets := parseSnippets(t, filepath.Join(root, doc))
			workDir := t.TempDir()
			goCount, bashCount := 0, 0
			for _, s := range snippets {
				switch s.lang {
				case "go":
					goCount++
					runGoSnippet(t, root, doc, s)
				case "bash":
					bashCount++
					runBashSnippet(t, bin, workDir, doc, s)
				case "sh", "shell", "json", "text", "":
					// illustrative only
				default:
					t.Errorf("%s:%d: unknown snippet language %q (use go, bash, sh, json or text)", doc, s.line, s.lang)
				}
			}
			t.Logf("%s: %d Go snippets built and run, %d bash snippets executed", doc, goCount, bashCount)
		})
	}
}

func runGoSnippet(t *testing.T, root, doc string, s snippet) {
	t.Helper()
	if !strings.Contains(s.code, "package main") {
		t.Errorf("%s:%d: Go snippet must be a complete program (package main)", doc, s.line)
		return
	}
	dir := t.TempDir()
	goMod := fmt.Sprintf("module docsnippet\n\ngo 1.24\n\nrequire github.com/BackendStack21/k-mosaic-go v0.0.0\n\nreplace github.com/BackendStack21/k-mosaic-go => %s\n", root)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(s.code), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"vet", "."}, {"run", "."}} {
		cmd := exec.Command("go", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s:%d: go %s failed: %v\n%s", doc, s.line, args[0], err, out)
			return
		}
	}
}

func runBashSnippet(t *testing.T, bin, workDir, doc string, s snippet) {
	t.Helper()
	script := "set -euo pipefail\n" + s.code
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HOME="+workDir,
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Errorf("%s:%d: bash snippet failed: %v\n--- snippet ---\n%s--- output ---\n%s", doc, s.line, err, s.code, out.String())
	}
}
