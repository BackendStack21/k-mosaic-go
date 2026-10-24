package main_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestUnknownOptionIsAnError pins the fix for misspelled options being
// silently ignored (a typo in --output used to print the secret key).
func TestUnknownOptionIsAnError(t *testing.T) {
	out, _, err := runCLI(t, 60*time.Second, "kem", "keygen", "--ouput", "x.json")
	if err == nil || !strings.Contains(out, "unknown option") {
		t.Fatalf("misspelled option accepted: err=%v out=%s", err, out)
	}
	out, _, err = runCLI(t, 60*time.Second, "kem", "keygen", "stray")
	if err == nil || !strings.Contains(out, "unexpected argument") {
		t.Fatalf("stray positional argument accepted: err=%v out=%s", err, out)
	}
	out, _, err = runCLI(t, 60*time.Second, "benchmark", "--iterations", "1x")
	if err == nil || !strings.Contains(out, "invalid --iterations") {
		t.Fatalf("non-numeric iterations accepted: err=%v out=%s", err, out)
	}
}

// TestEmptyMessageOptionIsLiteral checks that -m "" signs the empty message
// instead of falling back to stdin.
func TestEmptyMessageOptionIsLiteral(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "s.json")
	if out, _, err := runCLI(t, 120*time.Second, "sign", "keygen", "--output", keys); err != nil {
		t.Fatalf("keygen: %v %s", err, out)
	}
	sig := filepath.Join(dir, "sig.json")
	out, _, err := runCLIWithStdin(t, 120*time.Second, "this must be ignored", "sign", "sign", "--secret-key", keys, "--message", "", "--output", sig)
	if err != nil {
		t.Fatalf("sign: %v %s", err, out)
	}
	var exported struct {
		Message string `json:"message"`
	}
	data, _ := os.ReadFile(sig)
	if err := json.Unmarshal(data, &exported); err != nil || exported.Message != "" {
		t.Fatalf("empty --message was not signed literally: %q (%v)", exported.Message, err)
	}
	if out, _, err := runCLI(t, 120*time.Second, "sign", "verify", "--public-key", keys+".pub", "--signature", sig, "--message", ""); err != nil {
		t.Fatalf("verify of empty message failed: %v %s", err, out)
	}
}

// TestOutputFileReplacesSymlinkAtomically checks that key files are written
// through a private temporary file and renamed into place: a symlink at the
// destination is replaced, not followed, and the result has mode 0600.
func TestOutputFileReplacesSymlinkAtomically(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "k.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks not supported")
	}
	if out, _, err := runCLI(t, 120*time.Second, "kem", "keygen", "--output", link); err != nil {
		t.Fatalf("keygen: %v %s", err, out)
	}
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("destination is still a symlink (err=%v)", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %o, want 0600", info.Mode().Perm())
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("secret key was written through the symlink target")
	}
	if entries, _ := filepath.Glob(filepath.Join(dir, ".*.tmp-*")); len(entries) != 0 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}
