// Package main provides the k-mosaic-cli command line interface for kMOSAIC operations.
//
// Exit codes: 0 success (or valid signature), 1 invalid signature or
// authentication failure, 2 usage or runtime error.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	kmosaic "github.com/BackendStack21/k-mosaic-go/v4"
	"github.com/BackendStack21/k-mosaic-go/v4/entanglement"
	"github.com/BackendStack21/k-mosaic-go/v4/internal/wire"
	"github.com/BackendStack21/k-mosaic-go/v4/kem"
	"github.com/BackendStack21/k-mosaic-go/v4/sign"
	"github.com/BackendStack21/k-mosaic-go/v4/utils"
)

const (
	version = "4.2.0"
	appName = "k-mosaic-cli"

	exitOK      = 0
	exitInvalid = 1
	exitError   = 2

	maxInputFileSize = 100 * 1024 * 1024
)

// OutputFormat selects the text encoding of binary fields in JSON output.
type OutputFormat string

const (
	FormatHex    OutputFormat = "hex"
	FormatBase64 OutputFormat = "base64"
)

// CLIConfig holds the options common to every command.
type CLIConfig struct {
	SecurityLevel kmosaic.SecurityLevel
	OutputFormat  OutputFormat
	OutputFile    string
	Verbose       bool
	Timing        bool
}

// KeyPairExport is the JSON layout of a key-pair file. The secret key is
// always base64; the public key follows --format.
type KeyPairExport struct {
	SecurityLevel string `json:"security_level"`
	PublicKey     string `json:"public_key"`
	SecretKey     string `json:"secret_key,omitempty"`
	CreatedAt     string `json:"created_at"`
}

// EncapsulationExport is the JSON layout of an encapsulation result.
type EncapsulationExport struct {
	Ciphertext   string `json:"ciphertext"`
	SharedSecret string `json:"shared_secret"`
}

// SignatureExport is the JSON layout of a signature file.
type SignatureExport struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

// EncryptedExport is the JSON layout of an encrypted message file.
type EncryptedExport struct {
	Ciphertext string `json:"ciphertext"`
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(exitError)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(exitError)
	}
	switch os.Args[1] {
	case "help", "--help", "-h":
		printUsage()
	case "version", "--version":
		fmt.Printf("%s version %s\n", appName, version)
		fmt.Printf("kMOSAIC library version %s\n", kmosaic.Version)
	case "kem":
		handleKEM(os.Args[2:])
	case "sign":
		handleSign(os.Args[2:])
	case "benchmark":
		handleBenchmark(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(exitError)
	}
}

func printUsage() {
	fmt.Printf(`%[1]s - kMOSAIC Post-Quantum Cryptography CLI

USAGE:
    %[1]s <COMMAND> [OPTIONS]

COMMANDS:
    kem         Key Encapsulation Mechanism operations
    sign        Digital signature operations
    benchmark   Run performance benchmarks
    version     Show version information
    help        Show this help message

Use "%[1]s <COMMAND> --help" for more information about a command.

EXAMPLES:
    # Generate a KEM key pair: writes keys.json (both keys) and keys.json.pub (public only)
    %[1]s kem keygen --level 128 --output keys.json

    # Encrypt and decrypt a message
    %[1]s kem encrypt --public-key keys.json.pub --message "Hello World" --output enc.json
    %[1]s kem decrypt --secret-key keys.json --public-key keys.json.pub --ciphertext enc.json

    # Encapsulate and decapsulate
    %[1]s kem encapsulate --public-key keys.json.pub --output encap.json
    %[1]s kem decapsulate --secret-key keys.json --public-key keys.json.pub --ciphertext encap.json

    # Generate a signature key pair, sign, verify
    %[1]s sign keygen --level 128 --output sig-keys.json
    %[1]s sign sign --secret-key sig-keys.json --public-key sig-keys.json.pub --message "Document" --output sig.json
    %[1]s sign verify --public-key sig-keys.json.pub --message "Document" --signature sig.json

    # Run benchmarks
    %[1]s benchmark --level 128 --iterations 10

EXIT CODES:
    0 success / signature valid, 1 signature invalid or authentication failed, 2 error
`, appName)
}

// ============================================================================
// KEM Commands
// ============================================================================

func handleKEM(args []string) {
	if len(args) < 1 {
		printKEMUsage()
		os.Exit(exitError)
	}
	switch args[0] {
	case "keygen":
		kemKeygen(args[1:])
	case "encapsulate", "encap":
		kemEncapsulate(args[1:])
	case "decapsulate", "decap":
		kemDecapsulate(args[1:])
	case "encrypt", "enc":
		kemEncrypt(args[1:])
	case "decrypt", "dec":
		kemDecrypt(args[1:])
	case "pk-inspect":
		kemPKInspect(args[1:])
	case "help", "--help", "-h":
		printKEMUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown KEM subcommand: %s\n", args[0])
		printKEMUsage()
		os.Exit(exitError)
	}
}

func printKEMUsage() {
	fmt.Printf(`%[1]s kem - Key Encapsulation Mechanism operations

USAGE:
    %[1]s kem <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    keygen          Generate a new KEM key pair
    encapsulate     Create a shared secret and ciphertext for a public key
    decapsulate     Recover the shared secret from a ciphertext
    encrypt         Encrypt a message (KEM + AES-256-GCM)
    decrypt         Decrypt a message
    pk-inspect      Show the components and binding of a serialized public key
    help            Show this help message

OPTIONS:
    --level, -l <128|256>         Parameter set (default: 128)
    --output, -o <file>           Output file (default: stdout); keygen also writes <file>.pub
    --format, -f <hex|base64>     Encoding of binary fields in JSON output (default: base64)
    --public-key, -pk <file>      Public key file (JSON key file or raw)
    --secret-key, -sk <file>      Secret key file (JSON key file or raw)
    --ciphertext, -ct <file>      Ciphertext / encrypted message file
    --message, -m <text>          Message text
    --input, -i <file>            Message file (stdin if neither --message nor --input)
    --timing, -t                  Print timing information to stderr
    --verbose, -v                 Verbose output to stderr
`, appName)
}

func kemKeygen(args []string) {
	config := parseConfig(args)
	start := time.Now()
	kp, err := kem.GenerateKeyPair(config.SecurityLevel)
	elapsed := time.Since(start)
	if err != nil {
		fail("generating key pair: %v", err)
	}
	if config.Timing {
		fmt.Fprintf(os.Stderr, "Key generation took: %v\n", elapsed)
	}
	pkBytes := kem.SerializePublicKey(&kp.PublicKey)
	skBytes := kem.SerializeSecretKey(&kp.SecretKey, kp.PublicKey.Params)
	writeKeyPair(config, pkBytes, skBytes)
}

func kemEncapsulate(args []string) {
	config := parseConfig(args)
	pk := loadKEMPublicKey(requireArg(args, "--public-key", "-pk"))

	start := time.Now()
	result, err := kem.Encapsulate(pk)
	elapsed := time.Since(start)
	if err != nil {
		fail("encapsulating: %v", err)
	}
	if config.Timing {
		fmt.Fprintf(os.Stderr, "Encapsulation took: %v\n", elapsed)
	}
	ctBytes := kem.SerializeCiphertext(&result.Ciphertext, pk.Params)
	writeJSON(config, EncapsulationExport{
		Ciphertext:   encodeBytes(ctBytes, config.OutputFormat),
		SharedSecret: encodeBytes(result.SharedSecret, config.OutputFormat),
	})
	if config.Verbose {
		fmt.Fprintf(os.Stderr, "Ciphertext size: %d bytes\n", len(ctBytes))
	}
}

func kemDecapsulate(args []string) {
	config := parseConfig(args)
	skFile := requireArg(args, "--secret-key", "-sk")
	pkFile := requireArg(args, "--public-key", "-pk")
	ctFile := requireArg(args, "--ciphertext", "-ct")

	sk := loadKEMSecretKey(skFile)
	pk := loadKEMPublicKey(pkFile)
	ctData := loadField(ctFile, "ciphertext")
	ct, ctParams, err := kem.DeserializeCiphertext(ctData)
	if err != nil {
		fail("deserializing ciphertext: %v", err)
	}
	if ctParams.Level != pk.Params.Level {
		fail("ciphertext level %s does not match key level %s", ctParams.Level, pk.Params.Level)
	}

	start := time.Now()
	sharedSecret, err := kem.Decapsulate(sk, pk, ct)
	elapsed := time.Since(start)
	if err != nil {
		fail("decapsulating: %v", err)
	}
	if config.Timing {
		fmt.Fprintf(os.Stderr, "Decapsulation took: %v\n", elapsed)
	}
	writeJSON(config, map[string]string{"shared_secret": encodeBytes(sharedSecret, config.OutputFormat)})
}

func kemEncrypt(args []string) {
	config := parseConfig(args)
	pk := loadKEMPublicKey(requireArg(args, "--public-key", "-pk"))
	msgBytes := readMessage(args)

	start := time.Now()
	encrypted, err := kem.Encrypt(pk, msgBytes)
	elapsed := time.Since(start)
	if err != nil {
		fail("encrypting: %v", err)
	}
	if config.Timing {
		fmt.Fprintf(os.Stderr, "Encryption took: %v\n", elapsed)
	}
	encBytes := kem.SerializeEncryptedMessage(encrypted, pk.Params)
	writeJSON(config, EncryptedExport{Ciphertext: encodeBytes(encBytes, config.OutputFormat)})
	if config.Verbose {
		fmt.Fprintf(os.Stderr, "Plaintext size: %d bytes, ciphertext size: %d bytes\n", len(msgBytes), len(encBytes))
	}
}

func kemDecrypt(args []string) {
	config := parseConfig(args)
	skFile := requireArg(args, "--secret-key", "-sk")
	pkFile := requireArg(args, "--public-key", "-pk")
	ctFile := requireArg(args, "--ciphertext", "-ct")

	sk := loadKEMSecretKey(skFile)
	pk := loadKEMPublicKey(pkFile)
	em, emParams, err := kem.DeserializeEncryptedMessage(loadField(ctFile, "ciphertext"))
	if err != nil {
		fail("deserializing encrypted message: %v", err)
	}
	if emParams.Level != pk.Params.Level {
		fail("message level %s does not match key level %s", emParams.Level, pk.Params.Level)
	}

	start := time.Now()
	decrypted, err := kem.Decrypt(sk, pk, em)
	elapsed := time.Since(start)
	if errors.Is(err, kmosaic.ErrAuthentication) {
		fmt.Fprintf(os.Stderr, "Decryption failed: %v\n", err)
		os.Exit(exitInvalid)
	}
	if err != nil {
		fail("decrypting: %v", err)
	}
	if config.Timing {
		fmt.Fprintf(os.Stderr, "Decryption took: %v\n", elapsed)
	}
	if config.OutputFile != "" {
		writeFile(config.OutputFile, decrypted, 0600)
	} else {
		_, _ = os.Stdout.Write(decrypted)
	}
	if config.Verbose {
		fmt.Fprintf(os.Stderr, "\nPlaintext size: %d bytes\n", len(decrypted))
	}
}

func kemPKInspect(args []string) {
	config := parseConfig(args)
	pkData := loadField(requireArg(args, "--public-key", "-pk"), "public_key")

	// Parse the layout without validating the binding so a corrupted key can
	// still be inspected: header || [slss] || [code] || binding:32.
	level, body, err := wire.ParseHeader(pkData, wire.TypeKEMPublicKey)
	if err != nil {
		fail("invalid public key header: %v", err)
	}
	r := wire.NewReader(body)
	slssBytes, err := r.LV(kem.MaxComponentSize)
	if err != nil {
		fail("invalid public key: SLSS component: %v", err)
	}
	codeBytes, err := r.LV(kem.MaxComponentSize)
	if err != nil {
		fail("invalid public key: code component: %v", err)
	}
	embedded, err := r.Fixed(32)
	if err != nil || r.Done() != nil {
		fail("invalid public key: binding has wrong length")
	}
	computed := entanglement.ComputeBinding(slssBytes, codeBytes)
	writeJSON(config, map[string]string{
		"level":            string(level),
		"format_version":   fmt.Sprint(wire.Version),
		"embedded_binding": encodeBytes(embedded, config.OutputFormat),
		"computed_binding": encodeBytes(computed, config.OutputFormat),
		"slss_hash":        encodeBytes(utils.SHA3256(slssBytes), config.OutputFormat),
		"code_hash":        encodeBytes(utils.SHA3256(codeBytes), config.OutputFormat),
		"binding_valid":    fmt.Sprintf("%v", utils.ConstantTimeEqual(embedded, computed)),
	})
}

// ============================================================================
// Sign Commands
// ============================================================================

func handleSign(args []string) {
	if len(args) < 1 {
		printSignUsage()
		os.Exit(exitError)
	}
	switch args[0] {
	case "keygen":
		signKeygen(args[1:])
	case "sign":
		signSign(args[1:])
	case "verify":
		signVerify(args[1:])
	case "help", "--help", "-h":
		printSignUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown sign subcommand: %s\n", args[0])
		printSignUsage()
		os.Exit(exitError)
	}
}

func printSignUsage() {
	fmt.Printf(`%[1]s sign - Digital signature operations

USAGE:
    %[1]s sign <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    keygen      Generate a new signature key pair (writes <output> and <output>.pub)
    sign        Sign a message
    verify      Verify a signature (exit code 0 valid, 1 invalid, 2 error)
    help        Show this help message

OPTIONS:
    --level, -l <128|256>         Parameter set (default: 128)
    --output, -o <file>           Output file (default: stdout)
    --format, -f <hex|base64>     Encoding of binary fields in JSON output (default: base64)
    --public-key, -pk <file>      Public key file
    --secret-key, -sk <file>      Secret key file
    --signature, -sig <file>      Signature file
    --message, -m <text>          Message text
    --input, -i <file>            Message file (stdin if neither --message nor --input)
    --timing, -t                  Print timing information to stderr
    --verbose, -v                 Verbose output to stderr

The message to verify must be given with --message or --input; the copy
stored in a signature file is informational only.
`, appName)
}

func signKeygen(args []string) {
	config := parseConfig(args)
	start := time.Now()
	kp, err := sign.GenerateKeyPair(config.SecurityLevel)
	elapsed := time.Since(start)
	if err != nil {
		fail("generating key pair: %v", err)
	}
	if config.Timing {
		fmt.Fprintf(os.Stderr, "Key generation took: %v\n", elapsed)
	}
	writeKeyPair(config, sign.SerializePublicKey(&kp.PublicKey), sign.SerializeSecretKey(&kp.SecretKey))
}

func signSign(args []string) {
	config := parseConfig(args)
	skFile := requireArg(args, "--secret-key", "-sk")
	pkFile := getArg(args, "--public-key", "-pk")
	msgBytes := readMessage(args)

	sk, err := sign.DeserializeSecretKey(loadField(skFile, "secret_key"))
	if err != nil {
		fail("deserializing secret key: %v", err)
	}
	var pk *kmosaic.MOSAICSignPublicKey
	if pkFile != "" {
		pk = loadSignPublicKey(pkFile)
	}

	start := time.Now()
	sig, err := sign.Sign(sk, pk, msgBytes)
	elapsed := time.Since(start)
	if err != nil {
		fail("signing: %v", err)
	}
	if config.Timing {
		fmt.Fprintf(os.Stderr, "Signing took: %v\n", elapsed)
	}
	sigBytes := sign.SerializeSignature(sig, sk.Params)
	writeJSON(config, SignatureExport{
		Message:   encodeBytes(msgBytes, config.OutputFormat),
		Signature: encodeBytes(sigBytes, config.OutputFormat),
	})
	if config.Verbose {
		fmt.Fprintf(os.Stderr, "Message size: %d bytes, signature size: %d bytes\n", len(msgBytes), len(sigBytes))
	}
}

func signVerify(args []string) {
	config := parseConfig(args)
	pkFile := requireArg(args, "--public-key", "-pk")
	sigFile := requireArg(args, "--signature", "-sig")
	if !hasFlag(args, "--message", "-m") && !hasFlag(args, "--input", "-i") {
		fail("--message or --input is required for verification")
	}
	msgBytes := readMessage(args)

	pk := loadSignPublicKey(pkFile)
	sig, sigParams, err := sign.DeserializeSignature(loadField(sigFile, "signature"))
	if err != nil {
		fail("deserializing signature: %v", err)
	}
	if sigParams.Level != pk.Params.Level {
		fail("signature level %s does not match key level %s", sigParams.Level, pk.Params.Level)
	}

	start := time.Now()
	valid := sign.Verify(pk, msgBytes, sig)
	elapsed := time.Since(start)
	if config.Timing {
		fmt.Fprintf(os.Stderr, "Verification took: %v\n", elapsed)
	}
	writeJSON(config, map[string]interface{}{"valid": valid, "message": encodeBytes(msgBytes, config.OutputFormat)})
	if !valid {
		if config.Verbose {
			fmt.Fprintf(os.Stderr, "Signature is INVALID\n")
		}
		os.Exit(exitInvalid)
	}
	if config.Verbose {
		fmt.Fprintf(os.Stderr, "Signature is VALID\n")
	}
}

// ============================================================================
// Benchmark Command
// ============================================================================

func handleBenchmark(args []string) {
	config := parseConfig(args)
	iterations := 10
	if s := getArg(args, "--iterations", "-n"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 1000000 {
			fail("invalid --iterations value %q", s)
		}
		iterations = n
	}
	avg := func(total time.Duration) time.Duration { return total / time.Duration(iterations) }

	fmt.Printf("kMOSAIC Benchmark Results\nSecurity Level: %s\nIterations: %d\n\n", config.SecurityLevel, iterations)
	fmt.Println("Key Encapsulation Mechanism (KEM)")

	var kp *kmosaic.MOSAICKeyPair
	var total time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		var err error
		if kp, err = kem.GenerateKeyPair(config.SecurityLevel); err != nil {
			fail("KEM keygen: %v", err)
		}
		total += time.Since(start)
	}
	fmt.Printf("  KeyGen:      %v (avg)\n", avg(total))

	var encResult *kmosaic.EncapsulationResult
	total = 0
	for i := 0; i < iterations; i++ {
		start := time.Now()
		var err error
		if encResult, err = kem.Encapsulate(&kp.PublicKey); err != nil {
			fail("encapsulate: %v", err)
		}
		total += time.Since(start)
	}
	fmt.Printf("  Encapsulate: %v (avg)\n", avg(total))

	total = 0
	for i := 0; i < iterations; i++ {
		start := time.Now()
		ss, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &encResult.Ciphertext)
		if err != nil || !bytes.Equal(ss, encResult.SharedSecret) {
			fail("decapsulate: %v", err)
		}
		total += time.Since(start)
	}
	fmt.Printf("  Decapsulate: %v (avg)\n", avg(total))

	testMessage := bytes.Repeat([]byte("Hello, kMOSAIC!"), 10)
	var encrypted *kmosaic.EncryptedMessage
	total = 0
	for i := 0; i < iterations; i++ {
		start := time.Now()
		var err error
		if encrypted, err = kem.Encrypt(&kp.PublicKey, testMessage); err != nil {
			fail("encrypt: %v", err)
		}
		total += time.Since(start)
	}
	fmt.Printf("  Encrypt:     %v (avg)\n", avg(total))
	total = 0
	for i := 0; i < iterations; i++ {
		start := time.Now()
		if _, err := kem.Decrypt(&kp.SecretKey, &kp.PublicKey, encrypted); err != nil {
			fail("decrypt: %v", err)
		}
		total += time.Since(start)
	}
	fmt.Printf("  Decrypt:     %v (avg)\n\n", avg(total))

	fmt.Println("Digital Signatures")
	var signKp *kmosaic.MOSAICSignKeyPair
	total = 0
	for i := 0; i < iterations; i++ {
		start := time.Now()
		var err error
		if signKp, err = sign.GenerateKeyPair(config.SecurityLevel); err != nil {
			fail("sign keygen: %v", err)
		}
		total += time.Since(start)
	}
	fmt.Printf("  KeyGen:      %v (avg)\n", avg(total))
	var sig *kmosaic.MOSAICSignature
	total = 0
	for i := 0; i < iterations; i++ {
		start := time.Now()
		var err error
		if sig, err = sign.Sign(&signKp.SecretKey, &signKp.PublicKey, testMessage); err != nil {
			fail("sign: %v", err)
		}
		total += time.Since(start)
	}
	fmt.Printf("  Sign:        %v (avg)\n", avg(total))
	total = 0
	for i := 0; i < iterations; i++ {
		start := time.Now()
		if !sign.Verify(&signKp.PublicKey, testMessage, sig) {
			fail("verify failed")
		}
		total += time.Since(start)
	}
	fmt.Printf("  Verify:      %v (avg)\n\nBenchmark complete!\n", avg(total))
}

// ============================================================================
// Utility Functions
// ============================================================================

func parseConfig(args []string) CLIConfig {
	checkArgs(args)
	config := CLIConfig{SecurityLevel: kmosaic.MOS_128, OutputFormat: FormatBase64}
	switch level := getArg(args, "--level", "-l"); level {
	case "128", "MOS-128", "MOS_128":
		config.SecurityLevel = kmosaic.MOS_128
	case "256", "MOS-256", "MOS_256":
		config.SecurityLevel = kmosaic.MOS_256
	case "":
	default:
		fail("invalid security level '%s'. Must be one of: 128, 256", level)
	}
	switch format := getArg(args, "--format", "-f"); format {
	case "hex":
		config.OutputFormat = FormatHex
	case "base64", "":
		config.OutputFormat = FormatBase64
	default:
		fail("invalid format '%s'. Must be one of: hex, base64", format)
	}
	config.OutputFile = getArg(args, "--output", "-o")
	config.Verbose = hasFlag(args, "--verbose", "-v")
	config.Timing = hasFlag(args, "--timing", "-t")
	return config
}

// valueFlags lists the options that consume the following argument, so that
// their values are never mistaken for flags.
var valueFlags = map[string]bool{
	"--level": true, "-l": true, "--format": true, "-f": true, "--output": true, "-o": true,
	"--public-key": true, "-pk": true, "--secret-key": true, "-sk": true, "--ciphertext": true, "-ct": true,
	"--message": true, "-m": true, "--input": true, "-i": true, "--signature": true, "-sig": true,
	"--iterations": true, "-n": true,
}

// boolFlags lists the options that take no value.
var boolFlags = map[string]bool{
	"--verbose": true, "-v": true, "--timing": true, "-t": true,
}

// checkArgs rejects unknown options, options without a value, and stray
// positional arguments, so that a misspelled option (for example "--ouput")
// is an error instead of being silently ignored.
func checkArgs(args []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case valueFlags[a]:
			if i+1 >= len(args) {
				fail("option %s requires a value", a)
			}
			i++
		case boolFlags[a]:
		case strings.HasPrefix(a, "-"):
			fail("unknown option %q", a)
		default:
			fail("unexpected argument %q", a)
		}
	}
}

// getArg returns the value of the first occurrence of an option, or "" if it
// is absent. An option given with an empty value ("-m ”") also returns "";
// use hasFlag to tell the two apart.
func getArg(args []string, long, short string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == long || args[i] == short {
			if i+1 >= len(args) {
				fail("option %s requires a value", args[i])
			}
			return args[i+1]
		}
		if valueFlags[args[i]] {
			i++ // skip the value of another option
		}
	}
	return ""
}

func hasFlag(args []string, long, short string) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == long || args[i] == short {
			return true
		}
		if valueFlags[args[i]] {
			i++
		}
	}
	return false
}

func requireArg(args []string, long, short string) string {
	v := getArg(args, long, short)
	if v == "" {
		fail("%s is required", long)
	}
	return v
}

// readMessage returns the message from --message, --input or stdin.
func readMessage(args []string) []byte {
	if hasFlag(args, "--message", "-m") {
		return []byte(getArg(args, "--message", "-m")) // possibly empty
	}
	if hasFlag(args, "--input", "-i") {
		data, err := readFileLimited(getArg(args, "--input", "-i"))
		if err != nil {
			fail("reading input file: %v", err)
		}
		return data
	}
	data, err := readLimited(os.Stdin)
	if err != nil {
		fail("reading from stdin: %v", err)
	}
	return data
}

// readLimited reads at most maxInputFileSize bytes and fails if more are
// available, so that no input is silently truncated.
func readLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxInputFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxInputFileSize {
		return nil, fmt.Errorf("input too large: more than %d bytes", maxInputFileSize)
	}
	return data, nil
}

func encodeBytes(data []byte, format OutputFormat) string {
	if format == FormatHex {
		return hex.EncodeToString(data)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// decodeString decodes a value written by encodeBytes, accepting hex or
// base64. Hex is tried first whenever the string looks like hex (even length,
// only hex digits); every hex digit is a valid base64 character, so a hex
// string of length divisible by four would otherwise decode as base64 garbage.
// The converse ambiguity (a base64 string made only of hex digits, such as
// "eDA3") cannot arise for values this tool writes: every serialized object
// starts with the "kMOS" header, which is "a01PUw" in base64, and the
// 32-byte shared secret is 44 base64 characters ending in "=", while hex
// output is always even-length hex.
func decodeString(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if looksLikeHex(s) {
		if data, err := hex.DecodeString(s); err == nil {
			return data, nil
		}
	}
	if data, err := base64.StdEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	if data, err := hex.DecodeString(s); err == nil {
		return data, nil
	}
	return nil, errors.New("unable to decode string")
}

func looksLikeHex(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
		if !isHex {
			return false
		}
	}
	return true
}

// readFileLimited reads a file through the same byte limit as stdin; the
// limit applies to what is read, not to a size reported beforehand, so
// growing files, FIFOs and device files cannot bypass it.
func readFileLimited(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readLimited(f)
}

// loadField loads a binary field from a JSON file (by field name, with a few
// aliases) or from a raw hex/base64 file.
func loadField(filename, keyField string) []byte {
	data, err := readFileLimited(filename)
	if err != nil {
		fail("reading %s: %v", filename, err)
	}
	var jsonData map[string]interface{}
	if err := json.Unmarshal(data, &jsonData); err == nil {
		aliases := map[string][]string{
			"public_key": {"public_key", "publicKey", "pk"},
			"secret_key": {"secret_key", "secretKey", "sk"},
			"ciphertext": {"ciphertext", "ct", "encrypted"},
			"signature":  {"signature", "sig"},
		}
		for _, field := range append([]string{keyField}, aliases[keyField]...) {
			if val, ok := jsonData[field].(string); ok {
				decoded, err := decodeString(val)
				if err != nil {
					fail("decoding field %q of %s: %v", field, filename, err)
				}
				return decoded
			}
		}
		fail("%s contains no %q field", filename, keyField)
	}
	decoded, err := decodeString(string(data))
	if err != nil {
		fail("unable to parse %s as JSON, hex or base64", filename)
	}
	return decoded
}

func loadKEMPublicKey(file string) *kmosaic.MOSAICPublicKey {
	pk, err := kem.DeserializePublicKey(loadField(file, "public_key"))
	if err != nil {
		fail("deserializing public key: %v", err)
	}
	return pk
}

func loadKEMSecretKey(file string) *kmosaic.MOSAICSecretKey {
	sk, err := kem.DeserializeSecretKey(loadField(file, "secret_key"))
	if err != nil {
		fail("deserializing secret key: %v", err)
	}
	return sk
}

func loadSignPublicKey(file string) *kmosaic.MOSAICSignPublicKey {
	pk, err := sign.DeserializePublicKey(loadField(file, "public_key"))
	if err != nil {
		fail("deserializing public key: %v", err)
	}
	return pk
}

// writeKeyPair writes the key-pair file (0600) and, when an output file is
// given, a public-only companion file "<output>.pub" (0644).
func writeKeyPair(config CLIConfig, pkBytes, skBytes []byte) {
	now := time.Now().UTC().Format(time.RFC3339)
	full := KeyPairExport{
		SecurityLevel: string(config.SecurityLevel),
		PublicKey:     encodeBytes(pkBytes, config.OutputFormat),
		SecretKey:     base64.StdEncoding.EncodeToString(skBytes),
		CreatedAt:     now,
	}
	writeJSON(config, full)
	if config.OutputFile != "" {
		pub := KeyPairExport{SecurityLevel: full.SecurityLevel, PublicKey: full.PublicKey, CreatedAt: now}
		out, _ := json.MarshalIndent(pub, "", "  ")
		writeFile(config.OutputFile+".pub", out, 0644)
	}
	if config.Verbose {
		fmt.Fprintf(os.Stderr, "Generated key pair with security level %s: public key %d bytes, secret key %d bytes\n",
			config.SecurityLevel, len(pkBytes), len(skBytes))
	}
}

func writeJSON(config CLIConfig, v interface{}) {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fail("marshaling output: %v", err)
	}
	if config.OutputFile != "" {
		writeFile(config.OutputFile, out, 0600)
	} else {
		fmt.Println(string(out))
	}
}

// writeFile writes data to filename atomically: the content goes to a new
// temporary file in the same directory, created exclusively with mode 0600,
// and is renamed over the destination once written and synced. The data is
// therefore never readable under a looser mode, a pre-existing symlink at
// the destination is replaced rather than followed, and a failed write
// leaves any previous file intact. The final mode is set on the open file
// before the rename, so umask does not affect it.
func writeFile(filename string, data []byte, mode os.FileMode) {
	dir := filepath.Dir(filename)
	f, err := os.CreateTemp(dir, "."+filepath.Base(filename)+".tmp-*")
	if err != nil {
		fail("creating output file: %v", err)
	}
	tmp := f.Name()
	cleanup := func() { _ = f.Close(); _ = os.Remove(tmp) }
	if _, err := f.Write(data); err != nil {
		cleanup()
		fail("writing output file: %v", err)
	}
	if err := f.Chmod(mode); err != nil {
		cleanup()
		fail("setting file permissions: %v", err)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		fail("syncing output file: %v", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		fail("closing output file: %v", err)
	}
	if err := os.Rename(tmp, filename); err != nil {
		_ = os.Remove(tmp)
		fail("writing output file: %v", err)
	}
}
