package main_test

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runCLI executes the k-mosaic-cli via `go run ./cmd/k-mosaic-cli` from the repository root.
func runCLI(t *testing.T, timeout time.Duration, args ...string) (stdout string, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmdArgs := append([]string{"run", "./cmd/k-mosaic-cli"}, args...)
	cmd := exec.CommandContext(ctx, "go", cmdArgs...)
	// ensure we run from repo root (cmd/k-mosaic-cli tests are executed from that directory)
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), string(out), err
	}
	return string(out), "", nil
}

func TestHelpAndVersion(t *testing.T) {
	stdout, _, err := runCLI(t, 10*time.Second, "help")
	if err != nil {
		t.Fatalf("help command failed: %v, out: %s", err, stdout)
	}
	if !strings.Contains(stdout, "k-mosaic-cli - kMOSAIC") {
		t.Fatalf("help output does not contain expected header, got: %s", stdout)
	}

	stdout, _, err = runCLI(t, 10*time.Second, "version")
	if err != nil {
		t.Fatalf("version command failed: %v, out: %s", err, stdout)
	}
	if !strings.Contains(stdout, "version") {
		t.Fatalf("version output unexpected: %s", stdout)
	}
}

func TestKEMKeygenEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	kpFile := filepath.Join(dir, "kem_kp.json")
	ctFile := filepath.Join(dir, "kem_ct.json")
	message := "Hello kMOSAIC"

	// Keygen
	_, stderr, err := runCLI(t, 20*time.Second, "kem", "keygen", "--level", "128", "--output", kpFile)
	if err != nil {
		t.Fatalf("kem keygen failed: %v, stderr: %s", err, stderr)
	}

	// Encrypt
	_, stderr, err = runCLI(t, 20*time.Second, "kem", "encrypt", "--public-key", kpFile, "--message", message, "--output", ctFile)
	if err != nil {
		t.Fatalf("kem encrypt failed: %v, stderr: %s", err, stderr)
	}

	// Decrypt (should print plaintext to stdout)
	stdout, stderr, err := runCLI(t, 20*time.Second, "kem", "decrypt", "--secret-key", kpFile, "--public-key", kpFile, "--ciphertext", ctFile)
	if err != nil {
		t.Fatalf("kem decrypt failed: %v, stderr: %s, stdout: %s", err, stderr, stdout)
	}

	out := strings.TrimSpace(stdout)
	if out != message {
		t.Fatalf("decrypted message mismatch: expected %q got %q", message, out)
	}
}

func TestSignKeygenSignVerify(t *testing.T) {
	dir := t.TempDir()
	kpFile := filepath.Join(dir, "sign_kp.json")
	sigFile := filepath.Join(dir, "sig.json")
	message := "A signed message"

	// Keygen
	_, stderr, err := runCLI(t, 20*time.Second, "sign", "keygen", "--level", "128", "--output", kpFile)
	if err != nil {
		t.Fatalf("sign keygen failed: %v, stderr: %s", err, stderr)
	}

	// Sign
	_, stderr, err = runCLI(t, 20*time.Second, "sign", "sign", "--secret-key", kpFile, "--public-key", kpFile, "--message", message, "--output", sigFile)
	if err != nil {
		t.Fatalf("sign failed: %v, stderr: %s", err, stderr)
	}

	// Verify
	stdout, stderr, err := runCLI(t, 20*time.Second, "sign", "verify", "--public-key", kpFile, "--message", message, "--signature", sigFile)
	if err != nil {
		t.Fatalf("verify failed: %v, stderr: %s, stdout: %s", err, stderr, stdout)
	}

	var res map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("unable to parse verify output as json: %v, out: %s", err, stdout)
	}
	valid, ok := res["valid"].(bool)
	if !ok {
		t.Fatalf("verify output missing 'valid' bool: %v", res)
	}
	if !valid {
		t.Fatalf("signature reported invalid: %v", res)
	}
}
