// Package main provides the k-mosaic-cli command line interface for kMOSAIC operations.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/entanglement"
	"github.com/BackendStack21/k-mosaic-go/kem"
	"github.com/BackendStack21/k-mosaic-go/sign"
	"github.com/BackendStack21/k-mosaic-go/utils"
)

const (
	version = "2.0.0"
	appName = "k-mosaic-cli"
)

// OutputFormat represents the output format for serialization
type OutputFormat string

const (
	FormatHex    OutputFormat = "hex"
	FormatBase64 OutputFormat = "base64"
	FormatJSON   OutputFormat = "json"
)

// CLIConfig holds CLI configuration
type CLIConfig struct {
	SecurityLevel kmosaic.SecurityLevel
	OutputFormat  OutputFormat
	OutputFile    string
	InputFile     string
	Verbose       bool
	Timing        bool
}

// KEMKeyPairExport represents an exported KEM key pair
type KEMKeyPairExport struct {
	SecurityLevel string `json:"security_level"`
	PublicKey     string `json:"public_key"`
	SecretKey     string `json:"secret_key"`
	CreatedAt     string `json:"created_at"`
	KeyHMAC       string `json:"key_hmac,omitempty"` // HMAC for integrity verification
}

// SignKeyPairExport represents an exported signature key pair
type SignKeyPairExport struct {
	SecurityLevel string `json:"security_level"`
	PublicKey     string `json:"public_key"`
	SecretKey     string `json:"secret_key"`
	CreatedAt     string `json:"created_at"`
	KeyHMAC       string `json:"key_hmac,omitempty"` // HMAC for integrity verification
}

// EncapsulationExport represents an exported encapsulation result
type EncapsulationExport struct {
	Ciphertext   string `json:"ciphertext"`
	SharedSecret string `json:"shared_secret"`
}

// SignatureExport represents an exported signature
type SignatureExport struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

// EncryptedExport represents an exported encrypted message
type EncryptedExport struct {
	Ciphertext string `json:"ciphertext"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "help", "--help", "-h":
		printUsage()
	case "version", "--version", "-v":
		fmt.Printf("%s version %s\n", appName, version)
		fmt.Printf("kMOSAIC library version %s\n", kmosaic.Version)
	case "kem":
		handleKEM(os.Args[2:])
	case "sign":
		handleSign(os.Args[2:])
	case "benchmark":
		handleBenchmark(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`%s - kMOSAIC Post-Quantum Cryptography CLI

USAGE:
    %s <COMMAND> [OPTIONS]

COMMANDS:
    kem         Key Encapsulation Mechanism operations
    sign        Digital signature operations
    benchmark   Run performance benchmarks
    version     Show version information
    help        Show this help message

Use "%s <COMMAND> --help" for more information about a command.

EXAMPLES:
    # Generate a KEM key pair
    %s kem keygen --level 128 --output keypair.json

    # Encapsulate using a public key
    %s kem encapsulate --public-key pk.json --output encap.json

    # Decapsulate using a secret key
    %s kem decapsulate --secret-key sk.json --ciphertext ct.json

    # Encrypt a message
    %s kem encrypt --public-key pk.json --message "Hello World"

    # Decrypt a message
    %s kem decrypt --secret-key sk.json --ciphertext enc.json

    # Generate a signature key pair
    %s sign keygen --level 128 --output signkp.json

    # Sign a message
    %s sign sign --secret-key sk.json --message "Document to sign"

    # Verify a signature
    %s sign verify --public-key pk.json --message "Document" --signature sig.json

    # Run benchmarks
    %s benchmark --level 128 --iterations 10

For more information, visit: https://github.com/BackendStack21/k-mosaic-go
`, appName, appName, appName, appName, appName, appName, appName, appName, appName, appName, appName, appName)
}

// SafeAdd performs addition with overflow detection.
func SafeAdd(a, b int) (int, error) {
	// Detect overflow/underflow using result comparison.
	// When adding positive b, result should be > a.
	// When adding negative b, result should be < a.
	// If this relationship breaks, overflow/underflow has occurred.
	result := a + b
	if (b > 0 && result < a) || (b < 0 && result > a) {
		if b > 0 {
			return 0, fmt.Errorf("integer overflow: %d + %d exceeds max int", a, b)
		}
		return 0, fmt.Errorf("integer underflow: %d + %d exceeds min int", a, b)
	}
	return result, nil
}

// ============================================================================
// KEM Commands
// ============================================================================

func handleKEM(args []string) {
	if len(args) < 1 {
		printKEMUsage()
		os.Exit(1)
	}

	subcommand := args[0]
	switch subcommand {
	case "keygen":
		kemKeygen(args[1:])
	case "encapsulate", "encap":
		kemEncapsulate(args[1:])
	case "encapsulate-deterministic", "encap-det":
		kemEncapsulateDet(args[1:])
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
		fmt.Fprintf(os.Stderr, "Unknown KEM subcommand: %s\n", subcommand)
		printKEMUsage()
		os.Exit(1)
	}
}

func printKEMUsage() {
	fmt.Printf(`%s kem - Key Encapsulation Mechanism operations

USAGE:
    %s kem <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    keygen          Generate a new KEM key pair
    encapsulate     Encapsulate (create shared secret and ciphertext)
    decapsulate     Decapsulate (recover shared secret from ciphertext)
    encrypt         Encrypt a message using hybrid encryption
    decrypt         Decrypt a message using hybrid decryption
    help            Show this help message

OPTIONS:
    --level <128|256>       Security level (default: 128)
    --output <file>         Output file (default: stdout)
    --format <hex|base64|json>  Output format (default: json)
    --timing                Show timing information
    --verbose               Verbose output

EXAMPLES:
    %s kem keygen --level 128 --output keypair.json
    %s kem encapsulate --public-key pk.json
    %s kem decapsulate --secret-key sk.json --public-key pk.json --ciphertext ct.json
    %s kem encrypt --public-key pk.json --message "Hello World"
    %s kem encrypt --public-key pk.json --input message.txt
    %s kem decrypt --secret-key sk.json --public-key pk.json --ciphertext enc.json
`, appName, appName, appName, appName, appName, appName, appName, appName)
}

// generateKeyHMAC computes HMAC-SHA256 of key material for basic integrity verification.
// WARNING: This only detects accidental corruption, NOT malicious tampering. The HMAC uses
// the public key as the key material, which is not secret, so an attacker can easily forge
// valid HMACs. For security-critical applications, use cryptographic signatures instead.
func generateKeyHMAC(publicKey string, secretKey string) (string, error) {
	// Use public key for HMAC computation (provides only accidental corruption detection)
	h := hmac.New(sha256.New, []byte(publicKey))
	h.Write([]byte(secretKey))
	hmacResult := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hmacResult), nil
}

func kemKeygen(args []string) {
	config := parseConfig(args)

	start := time.Now()
	kp, err := kem.GenerateKeyPair(config.SecurityLevel)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key pair: %v\n", err)
		os.Exit(1)
	}

	if config.Timing {
		fmt.Fprintf(os.Stderr, "Key generation took: %v\n", elapsed)
	}

	// Serialize key pair
	pkBytes := kem.SerializePublicKey(&kp.PublicKey)
	skBytes := kem.SerializeSecretKey(&kp.SecretKey)

	export := KEMKeyPairExport{
		SecurityLevel: string(config.SecurityLevel),
		PublicKey:     encodeBytes(pkBytes, config.OutputFormat),
		SecretKey:     base64.StdEncoding.EncodeToString(skBytes),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	keyHMAC, err := generateKeyHMAC(export.PublicKey, export.SecretKey)
	if err == nil {
		export.KeyHMAC = keyHMAC
	}

	output, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling output: %v\n", err)
		os.Exit(1)
	}

	writeOutput(output, config.OutputFile)

	if config.Verbose {
		fmt.Fprintf(os.Stderr, "Generated KEM key pair with security level: %s\n", config.SecurityLevel)
		fmt.Fprintf(os.Stderr, "Public key size: %d bytes\n", len(pkBytes))
		fmt.Fprintf(os.Stderr, "Secret key size: %d bytes\n", len(skBytes))
	}
}

func kemEncapsulate(args []string) {
	config := parseConfig(args)
	pkFile := getArg(args, "--public-key", "-pk")

	if pkFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --public-key is required\n")
		os.Exit(1)
	}

	// Load public key
	pkData, err := loadKeyFromFile(pkFile, "public_key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
		os.Exit(1)
	}

	pk, err := kem.DeserializePublicKey(pkData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing public key: %v\n", err)
		os.Exit(1)
	}

	start := time.Now()
	result, err := kem.Encapsulate(pk)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encapsulating: %v\n", err)
		os.Exit(1)
	}

	if config.Timing {
		fmt.Fprintf(os.Stderr, "Encapsulation took: %v\n", elapsed)
	}

	ctBytes := kem.SerializeCiphertext(&result.Ciphertext)

	export := EncapsulationExport{
		Ciphertext:   encodeBytes(ctBytes, config.OutputFormat),
		SharedSecret: encodeBytes(result.SharedSecret, config.OutputFormat),
	}

	output, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling output: %v\n", err)
		os.Exit(1)
	}

	writeOutput(output, config.OutputFile)

	if config.Verbose {
		fmt.Fprintf(os.Stderr, "Encapsulation successful\n")
		fmt.Fprintf(os.Stderr, "Ciphertext size: %d bytes\n", len(ctBytes))
		fmt.Fprintf(os.Stderr, "Shared secret size: %d bytes\n", len(result.SharedSecret))
	}
}

func kemEncapsulateDet(args []string) {
	config := parseConfig(args)
	pkFile := getArg(args, "--public-key", "-pk")
	ephemeralHex := getArg(args, "--ephemeral-secret", "-es")

	if pkFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --public-key is required\n")
		os.Exit(1)
	}

	if ephemeralHex == "" {
		fmt.Fprintf(os.Stderr, "Error: --ephemeral-secret is required (hex 64 chars)\n")
		os.Exit(1)
	}

	ephemeral, err := hex.DecodeString(ephemeralHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid ephemeral-secret hex: %v\n", err)
		os.Exit(1)
	}
	if len(ephemeral) != 32 {
		fmt.Fprintf(os.Stderr, "Ephemeral secret must be exactly 32 bytes\n")
		os.Exit(1)
	}

	// Load public key
	pkData, err := loadKeyFromFile(pkFile, "public_key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
		os.Exit(1)
	}

	pk, err := kem.DeserializePublicKey(pkData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing public key: %v\n", err)
		os.Exit(1)
	}

	start := time.Now()
	result, err := kem.EncapsulateDeterministic(pk, ephemeral)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encapsulating deterministically: %v\n", err)
		os.Exit(1)
	}

	if config.Timing {
		fmt.Fprintf(os.Stderr, "Deterministic encapsulation took: %v\n", elapsed)
	}

	ctBytes := kem.SerializeCiphertext(&result.Ciphertext)

	export := EncapsulationExport{
		Ciphertext:   encodeBytes(ctBytes, config.OutputFormat),
		SharedSecret: encodeBytes(result.SharedSecret, config.OutputFormat),
	}

	output, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling output: %v\n", err)
		os.Exit(1)
	}

	writeOutput(output, config.OutputFile)

	if config.Verbose {
		fmt.Fprintf(os.Stderr, "Encapsulation (deterministic) successful\n")
		fmt.Fprintf(os.Stderr, "Ciphertext size: %d bytes\n", len(ctBytes))
		fmt.Fprintf(os.Stderr, "Shared secret size: %d bytes\n", len(result.SharedSecret))
	}
}

func kemPKInspect(args []string) {
	config := parseConfig(args)
	pkFile := getArg(args, "--public-key", "-pk")

	if pkFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --public-key is required\n")
		os.Exit(1)
	}

	pkData, err := loadKeyFromFile(pkFile, "public_key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
		os.Exit(1)
	}

	off := 0
	if len(pkData) < 4 {
		fmt.Fprintf(os.Stderr, "Invalid public key: too short to read level\n")
		os.Exit(1)
	}
	levelLen := int(binary.LittleEndian.Uint32(pkData[off:]))
	var newOff int
	newOff, err = SafeAdd(off, 4+levelLen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: offset overflow: %v\n", err)
		os.Exit(1)
	}
	off = newOff
	if off+4 > len(pkData) {
		fmt.Fprintf(os.Stderr, "Invalid public key: truncated\n")
		os.Exit(1)
	}
	slssLen := int(binary.LittleEndian.Uint32(pkData[off:]))
	newOff, err = SafeAdd(off, 4)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: offset overflow: %v\n", err)
		os.Exit(1)
	}
	off = newOff
	if off+slssLen > len(pkData) {
		fmt.Fprintf(os.Stderr, "Invalid public key: SLSS truncated\n")
		os.Exit(1)
	}
	slssBytes := pkData[off : off+slssLen]
	newOff, err = SafeAdd(off, slssLen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: offset overflow: %v\n", err)
		os.Exit(1)
	}
	off = newOff
	if off+4 > len(pkData) {
		fmt.Fprintf(os.Stderr, "Invalid public key: truncated after SLSS\n")
		os.Exit(1)
	}
	tddLen := int(binary.LittleEndian.Uint32(pkData[off:]))
	newOff, err = SafeAdd(off, 4)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: offset overflow: %v\n", err)
		os.Exit(1)
	}
	off = newOff
	if off+tddLen > len(pkData) {
		fmt.Fprintf(os.Stderr, "Invalid public key: TDD truncated\n")
		os.Exit(1)
	}
	tddBytes := pkData[off : off+tddLen]
	newOff, err = SafeAdd(off, tddLen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: offset overflow: %v\n", err)
		os.Exit(1)
	}
	off = newOff
	if off+4 > len(pkData) {
		fmt.Fprintf(os.Stderr, "Invalid public key: truncated after TDD\n")
		os.Exit(1)
	}
	egrwLen := int(binary.LittleEndian.Uint32(pkData[off:]))
	newOff, err = SafeAdd(off, 4)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: offset overflow: %v\n", err)
		os.Exit(1)
	}
	off = newOff
	if off+egrwLen > len(pkData) {
		fmt.Fprintf(os.Stderr, "Invalid public key: EGRW truncated\n")
		os.Exit(1)
	}
	egrwBytes := pkData[off : off+egrwLen]
	newOff, err = SafeAdd(off, egrwLen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: offset overflow: %v\n", err)
		os.Exit(1)
	}
	off = newOff
	if off+32 > len(pkData) {
		fmt.Fprintf(os.Stderr, "Invalid public key: binding truncated\n")
		os.Exit(1)
	}
	embedded := pkData[off : off+32]

	computed := entanglement.ComputeBinding(slssBytes, tddBytes, egrwBytes)
	// Compute component hashes for comparison
	slssHash := utils.SHA3256(slssBytes)
	tddHash := utils.SHA3256(tddBytes)
	egrwHash := utils.SHA3256(egrwBytes)

	out := map[string]string{
		"embedded_binding": encodeBytes(embedded, config.OutputFormat),
		"computed_binding": encodeBytes(computed, config.OutputFormat),
		"slss_hash":        encodeBytes(slssHash, config.OutputFormat),
		"tdd_hash":         encodeBytes(tddHash, config.OutputFormat),
		"egrw_hash":        encodeBytes(egrwHash, config.OutputFormat),
	}
	j, _ := json.MarshalIndent(out, "", "  ")
	writeOutput(j, config.OutputFile)
}

func kemDecapsulate(args []string) {
	config := parseConfig(args)
	skFile := getArg(args, "--secret-key", "-sk")
	pkFile := getArg(args, "--public-key", "-pk")
	ctFile := getArg(args, "--ciphertext", "-ct")

	if skFile == "" || pkFile == "" || ctFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --secret-key, --public-key, and --ciphertext are required\n")
		os.Exit(1)
	}

	// Load secret key (handles JSON format)
	sk, err := loadSecretKeyFromFile(skFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading secret key: %v\n", err)
		os.Exit(1)
	}

	pkData, err := loadKeyFromFile(pkFile, "public_key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
		os.Exit(1)
	}

	ctData, err := loadKeyFromFile(ctFile, "ciphertext")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading ciphertext: %v\n", err)
		os.Exit(1)
	}

	pk, err := kem.DeserializePublicKey(pkData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing public key: %v\n", err)
		os.Exit(1)
	}

	ct, err := kem.DeserializeCiphertext(ctData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing ciphertext: %v\n", err)
		os.Exit(1)
	}

	start := time.Now()
	sharedSecret, err := kem.Decapsulate(sk, pk, ct)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decapsulating: %v\n", err)
		os.Exit(1)
	}

	if config.Timing {
		fmt.Fprintf(os.Stderr, "Decapsulation took: %v\n", elapsed)
	}

	result := map[string]string{
		"shared_secret": encodeBytes(sharedSecret, config.OutputFormat),
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling output: %v\n", err)
		os.Exit(1)
	}

	writeOutput(output, config.OutputFile)

	if config.Verbose {
		fmt.Fprintf(os.Stderr, "Decapsulation successful\n")
		fmt.Fprintf(os.Stderr, "Shared secret size: %d bytes\n", len(sharedSecret))
	}
}

func kemEncrypt(args []string) {
	config := parseConfig(args)
	pkFile := getArg(args, "--public-key", "-pk")
	message := getArg(args, "--message", "-m")
	inputFile := getArg(args, "--input", "-i")

	if pkFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --public-key is required\n")
		os.Exit(1)
	}

	// Get message from argument or file
	var msgBytes []byte
	if message != "" {
		msgBytes = []byte(message)
	} else if inputFile != "" {
		var err error
		msgBytes, err = os.ReadFile(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Read from stdin
		var err error
		msgBytes, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
			os.Exit(1)
		}
	}

	// Load public key
	pkData, err := loadKeyFromFile(pkFile, "public_key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
		os.Exit(1)
	}

	pk, err := kem.DeserializePublicKey(pkData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing public key: %v\n", err)
		os.Exit(1)
	}

	start := time.Now()
	encrypted, err := kem.Encrypt(pk, msgBytes)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting: %v\n", err)
		os.Exit(1)
	}

	if config.Timing {
		fmt.Fprintf(os.Stderr, "Encryption took: %v\n", elapsed)
	}

	encBytes := kem.SerializeEncryptedMessage(encrypted)

	export := EncryptedExport{
		Ciphertext: encodeBytes(encBytes, config.OutputFormat),
	}

	output, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling output: %v\n", err)
		os.Exit(1)
	}

	writeOutput(output, config.OutputFile)

	if config.Verbose {
		fmt.Fprintf(os.Stderr, "Encryption successful\n")
		fmt.Fprintf(os.Stderr, "Plaintext size: %d bytes\n", len(msgBytes))
		fmt.Fprintf(os.Stderr, "Ciphertext size: %d bytes\n", len(encBytes))
	}
}

func kemDecrypt(args []string) {
	config := parseConfig(args)
	skFile := getArg(args, "--secret-key", "-sk")
	pkFile := getArg(args, "--public-key", "-pk")
	ctFile := getArg(args, "--ciphertext", "-ct")

	if skFile == "" || pkFile == "" || ctFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --secret-key, --public-key, and --ciphertext are required\n")
		os.Exit(1)
	}

	// Load secret key (handles JSON format)
	sk, err := loadSecretKeyFromFile(skFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading secret key: %v\n", err)
		os.Exit(1)
	}

	pkData, err := loadKeyFromFile(pkFile, "public_key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
		os.Exit(1)
	}

	ctData, err := loadKeyFromFile(ctFile, "ciphertext")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading ciphertext: %v\n", err)
		os.Exit(1)
	}

	pk, err := kem.DeserializePublicKey(pkData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing public key: %v\n", err)
		os.Exit(1)
	}

	em, err := kem.DeserializeEncryptedMessage(ctData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing encrypted message: %v\n", err)
		os.Exit(1)
	}

	start := time.Now()
	decrypted, err := kem.Decrypt(sk, pk, em)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting: %v\n", err)
		os.Exit(1)
	}

	if config.Timing {
		fmt.Fprintf(os.Stderr, "Decryption took: %v\n", elapsed)
	}

	// Write decrypted message
	if config.OutputFile != "" {
		if err := os.WriteFile(config.OutputFile, decrypted, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Print(string(decrypted))
	}

	if config.Verbose {
		fmt.Fprintf(os.Stderr, "\nDecryption successful\n")
		fmt.Fprintf(os.Stderr, "Plaintext size: %d bytes\n", len(decrypted))
	}
}

// ============================================================================
// Sign Commands
// ============================================================================

func handleSign(args []string) {
	if len(args) < 1 {
		printSignUsage()
		os.Exit(1)
	}

	subcommand := args[0]
	switch subcommand {
	case "keygen":
		signKeygen(args[1:])
	case "sign":
		signSign(args[1:])
	case "verify":
		signVerify(args[1:])
	case "help", "--help", "-h":
		printSignUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown sign subcommand: %s\n", subcommand)
		printSignUsage()
		os.Exit(1)
	}
}

func printSignUsage() {
	fmt.Printf(`%s sign - Digital signature operations

USAGE:
    %s sign <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    keygen      Generate a new signature key pair
    sign        Sign a message
    verify      Verify a signature
    help        Show this help message

OPTIONS:
    --level <128|256>       Security level (default: 128)
    --output <file>         Output file (default: stdout)
    --format <hex|base64|json>  Output format (default: json)
    --timing                Show timing information
    --verbose               Verbose output

EXAMPLES:
    %s sign keygen --level 128 --output signkp.json
    %s sign sign --secret-key sk.json --public-key pk.json --message "Hello"
    %s sign sign --secret-key sk.json --public-key pk.json --input document.txt
    %s sign verify --public-key pk.json --message "Hello" --signature sig.json
`, appName, appName, appName, appName, appName, appName)
}

func signKeygen(args []string) {
	config := parseConfig(args)

	start := time.Now()
	kp, err := sign.GenerateKeyPair(config.SecurityLevel)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key pair: %v\n", err)
		os.Exit(1)
	}

	if config.Timing {
		fmt.Fprintf(os.Stderr, "Key generation took: %v\n", elapsed)
	}

	// Serialize key pair
	pkBytes := sign.SerializePublicKey(&kp.PublicKey)
	skBytes := sign.SerializeSecretKey(&kp.SecretKey)

	export := SignKeyPairExport{
		SecurityLevel: string(config.SecurityLevel),
		PublicKey:     encodeBytes(pkBytes, config.OutputFormat),
		SecretKey:     base64.StdEncoding.EncodeToString(skBytes),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	keyHMAC, err := generateKeyHMAC(export.PublicKey, export.SecretKey)
	if err == nil {
		export.KeyHMAC = keyHMAC
	}

	output, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling output: %v\n", err)
		os.Exit(1)
	}

	writeOutput(output, config.OutputFile)

	if config.Verbose {
		fmt.Fprintf(os.Stderr, "Generated signature key pair with security level: %s\n", config.SecurityLevel)
		fmt.Fprintf(os.Stderr, "Public key size: %d bytes\n", len(pkBytes))
		fmt.Fprintf(os.Stderr, "Secret key size: %d bytes\n", len(skBytes))
	}
}

func signSign(args []string) {
	config := parseConfig(args)
	skFile := getArg(args, "--secret-key", "-sk")
	pkFile := getArg(args, "--public-key", "-pk")
	message := getArg(args, "--message", "-m")
	inputFile := getArg(args, "--input", "-i")

	if skFile == "" || pkFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --secret-key and --public-key are required\n")
		os.Exit(1)
	}

	// Get message from argument or file
	var msgBytes []byte
	if message != "" {
		msgBytes = []byte(message)
	} else if inputFile != "" {
		var err error
		msgBytes, err = os.ReadFile(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Read from stdin
		var err error
		msgBytes, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
			os.Exit(1)
		}
	}

	// Load secret key (handles JSON format)
	sk, err := loadSignSecretKeyFromFile(skFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading secret key: %v\n", err)
		os.Exit(1)
	}

	pkData, err := loadKeyFromFile(pkFile, "public_key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
		os.Exit(1)
	}

	pk, err := sign.DeserializePublicKey(pkData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing public key: %v\n", err)
		os.Exit(1)
	}

	start := time.Now()
	sig, err := sign.Sign(sk, pk, msgBytes)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing: %v\n", err)
		os.Exit(1)
	}

	if config.Timing {
		fmt.Fprintf(os.Stderr, "Signing took: %v\n", elapsed)
	}

	sigBytes := sign.SerializeSignature(sig)

	export := SignatureExport{
		Message:   encodeBytes(msgBytes, config.OutputFormat),
		Signature: encodeBytes(sigBytes, config.OutputFormat),
	}

	output, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling output: %v\n", err)
		os.Exit(1)
	}

	writeOutput(output, config.OutputFile)

	if config.Verbose {
		fmt.Fprintf(os.Stderr, "Signature successful\n")
		fmt.Fprintf(os.Stderr, "Message size: %d bytes\n", len(msgBytes))
		fmt.Fprintf(os.Stderr, "Signature size: %d bytes\n", len(sigBytes))
	}
}

func signVerify(args []string) {
	config := parseConfig(args)
	pkFile := getArg(args, "--public-key", "-pk")
	message := getArg(args, "--message", "-m")
	inputFile := getArg(args, "--input", "-i")
	sigFile := getArg(args, "--signature", "-sig")

	if pkFile == "" || sigFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --public-key and --signature are required\n")
		os.Exit(1)
	}

	// Get message from argument or file
	var msgBytes []byte
	if message != "" {
		msgBytes = []byte(message)
	} else if inputFile != "" {
		var err error
		msgBytes, err = os.ReadFile(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Try to get message from signature file
		sigData, err := os.ReadFile(sigFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading signature file: %v\n", err)
			os.Exit(1)
		}
		var sigExport SignatureExport
		if err := json.Unmarshal(sigData, &sigExport); err == nil && sigExport.Message != "" {
			msgBytes, err = decodeString(sigExport.Message)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding message: %v\n", err)
				os.Exit(1)
			}
		}
	}

	if len(msgBytes) == 0 {
		fmt.Fprintf(os.Stderr, "Error: message is required (use --message, --input, or include in signature file)\n")
		os.Exit(1)
	}

	// Load public key
	pkData, err := loadKeyFromFile(pkFile, "public_key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
		os.Exit(1)
	}

	pk, err := sign.DeserializePublicKey(pkData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing public key: %v\n", err)
		os.Exit(1)
	}

	// Load signature
	sigData, err := loadKeyFromFile(sigFile, "signature")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading signature: %v\n", err)
		os.Exit(1)
	}

	sig, err := sign.DeserializeSignature(sigData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing signature: %v\n", err)
		os.Exit(1)
	}

	start := time.Now()
	valid := sign.Verify(pk, msgBytes, sig)
	elapsed := time.Since(start)

	if config.Timing {
		fmt.Fprintf(os.Stderr, "Verification took: %v\n", elapsed)
	}

	result := map[string]interface{}{
		"valid":   valid,
		"message": encodeBytes(msgBytes, config.OutputFormat),
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling output: %v\n", err)
		os.Exit(1)
	}

	writeOutput(output, config.OutputFile)

	if valid {
		if config.Verbose {
			fmt.Fprintf(os.Stderr, "✓ Signature is VALID\n")
		}
		os.Exit(0)
	} else {
		if config.Verbose {
			fmt.Fprintf(os.Stderr, "✗ Signature is INVALID\n")
		}
		os.Exit(1)
	}
}

// ============================================================================
// Benchmark Command
// ============================================================================

func handleBenchmark(args []string) {
	config := parseConfig(args)
	iterationsStr := getArg(args, "--iterations", "-n")

	iterations := 10
	if iterationsStr != "" {
		_, _ = fmt.Sscanf(iterationsStr, "%d", &iterations)
	}

	if iterations < 1 {
		iterations = 1
	}

	fmt.Printf("kMOSAIC Benchmark Results\n")
	fmt.Printf("=========================\n")
	fmt.Printf("Security Level: %s\n", config.SecurityLevel)
	fmt.Printf("Iterations: %d\n\n", iterations)

	// KEM Benchmarks
	fmt.Println("Key Encapsulation Mechanism (KEM)")
	fmt.Println("---------------------------------")

	// KeyGen
	var kemKeygenTotal time.Duration
	var kp *kmosaic.MOSAICKeyPair
	for i := 0; i < iterations; i++ {
		start := time.Now()
		var err error
		kp, err = kem.GenerateKeyPair(config.SecurityLevel)
		kemKeygenTotal += time.Since(start)
		if err != nil {
			fmt.Fprintf(os.Stderr, "KEM keygen error: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("  KeyGen:      %v (avg)\n", kemKeygenTotal/time.Duration(iterations))

	// Encapsulate
	var encapTotal time.Duration
	var encResult *kmosaic.EncapsulationResult
	for i := 0; i < iterations; i++ {
		start := time.Now()
		var err error
		encResult, err = kem.Encapsulate(&kp.PublicKey)
		encapTotal += time.Since(start)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Encapsulate error: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("  Encapsulate: %v (avg)\n", encapTotal/time.Duration(iterations))

	// Decapsulate
	var decapTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, err := kem.Decapsulate(&kp.SecretKey, &kp.PublicKey, &encResult.Ciphertext)
		decapTotal += time.Since(start)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Decapsulate error: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("  Decapsulate: %v (avg)\n", decapTotal/time.Duration(iterations))

	// Encrypt/Decrypt
	testMessage := bytes.Repeat([]byte("Hello, kMOSAIC!"), 10)
	var encryptTotal time.Duration
	var encrypted *kmosaic.EncryptedMessage
	for i := 0; i < iterations; i++ {
		start := time.Now()
		var err error
		encrypted, err = kem.Encrypt(&kp.PublicKey, testMessage)
		encryptTotal += time.Since(start)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Encrypt error: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("  Encrypt:     %v (avg)\n", encryptTotal/time.Duration(iterations))

	var decryptTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, err := kem.Decrypt(&kp.SecretKey, &kp.PublicKey, encrypted)
		decryptTotal += time.Since(start)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Decrypt error: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("  Decrypt:     %v (avg)\n", decryptTotal/time.Duration(iterations))

	fmt.Println()

	// Signature Benchmarks
	fmt.Println("Digital Signatures")
	fmt.Println("------------------")

	// KeyGen
	var signKeygenTotal time.Duration
	var signKp *kmosaic.MOSAICSignKeyPair
	for i := 0; i < iterations; i++ {
		start := time.Now()
		var err error
		signKp, err = sign.GenerateKeyPair(config.SecurityLevel)
		signKeygenTotal += time.Since(start)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Sign keygen error: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("  KeyGen:      %v (avg)\n", signKeygenTotal/time.Duration(iterations))

	// Sign
	var signTotal time.Duration
	var sig *kmosaic.MOSAICSignature
	for i := 0; i < iterations; i++ {
		start := time.Now()
		var err error
		sig, err = sign.Sign(&signKp.SecretKey, &signKp.PublicKey, testMessage)
		signTotal += time.Since(start)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Sign error: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("  Sign:        %v (avg)\n", signTotal/time.Duration(iterations))

	// Verify
	var verifyTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		valid := sign.Verify(&signKp.PublicKey, testMessage, sig)
		verifyTotal += time.Since(start)
		if !valid {
			fmt.Fprintf(os.Stderr, "Verify failed\n")
			os.Exit(1)
		}
	}
	fmt.Printf("  Verify:      %v (avg)\n", verifyTotal/time.Duration(iterations))

	fmt.Println()
	fmt.Println("Benchmark complete!")
}

// ============================================================================
// Utility Functions
// ============================================================================

func parseConfig(args []string) CLIConfig {
	config := CLIConfig{
		SecurityLevel: kmosaic.MOS_128,
		OutputFormat:  FormatBase64,
	}

	level := getArg(args, "--level", "-l")
	switch level {
	case "128", "MOS-128", "MOS_128":
		config.SecurityLevel = kmosaic.MOS_128
	case "256", "MOS-256", "MOS_256":
		config.SecurityLevel = kmosaic.MOS_256
	case "":
		// No level specified, use default
	default:
		// Invalid level provided
		fmt.Fprintf(os.Stderr, "Error: invalid security level '%s'. Must be one of: 128, 256\n", level)
		os.Exit(1)
	}

	format := getArg(args, "--format", "-f")
	switch format {
	case "hex":
		config.OutputFormat = FormatHex
	case "base64":
		config.OutputFormat = FormatBase64
	case "json":
		config.OutputFormat = FormatJSON
	case "":
		// No format specified, use default
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid format '%s'. Must be one of: hex, base64, json\n", format)
		os.Exit(1)
	}

	config.OutputFile = getArg(args, "--output", "-o")
	config.InputFile = getArg(args, "--input", "-i")
	config.Verbose = hasFlag(args, "--verbose", "-v")
	config.Timing = hasFlag(args, "--timing", "-t")

	return config
}

func getArg(args []string, long, short string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == long || args[i] == short {
			return args[i+1]
		}
	}
	return ""
}

func hasFlag(args []string, long, short string) bool {
	for _, arg := range args {
		if arg == long || arg == short {
			return true
		}
	}
	return false
}

func encodeBytes(data []byte, format OutputFormat) string {
	switch format {
	case FormatHex:
		return hex.EncodeToString(data)
	case FormatBase64:
		return base64.StdEncoding.EncodeToString(data)
	default:
		return base64.StdEncoding.EncodeToString(data)
	}
}

// decodeString decodes a value written by encodeBytes, accepting either hex
// or base64.
//
// Hex is tried first whenever the string looks like hex (even length, only
// hex digits). Every hex digit is also a valid base64 character, so a hex
// string whose length is a multiple of four would otherwise be silently
// "decoded" as base64 into garbage and the key or ciphertext would then fail
// to parse. A base64 string consisting purely of hex digits is astronomically
// unlikely for the key, ciphertext and signature sizes this CLI produces.
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
	return nil, fmt.Errorf("unable to decode string")
}

// looksLikeHex reports whether s is a non-empty, even-length string made only
// of hexadecimal digits.
func looksLikeHex(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isLower := c >= 'a' && c <= 'f'
		isUpper := c >= 'A' && c <= 'F'
		if !isDigit && !isLower && !isUpper {
			return false
		}
	}
	return true
}

// loadSecretKeyFromFile loads a KEM secret key from a JSON key-pair file
// (base64 "secret_key" field) or a raw binary file.
// With file size validation to prevent unbounded file operations
func loadSecretKeyFromFile(filename string) (*kmosaic.MOSAICSecretKey, error) {
	const MaxInputFileSize = 100 * 1024 * 1024 // 100 MB limit

	// Check file size before reading
	info, err := os.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}
	if info.Size() > MaxInputFileSize {
		return nil, fmt.Errorf("input file too large: %d > %d bytes", info.Size(), MaxInputFileSize)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Try to parse file as JSON keypair
	var jsonData map[string]interface{}
	if err := json.Unmarshal(data, &jsonData); err == nil {
		// JSON format - extract secret_key field
		if val, ok := jsonData["secret_key"]; ok {
			if strVal, ok := val.(string); ok {
				// Decode base64
				skBytes, err := base64.StdEncoding.DecodeString(strVal)
				if err != nil {
					return nil, fmt.Errorf("failed to decode secret key: %w", err)
				}
				return kem.DeserializeSecretKey(skBytes)
			}
		}
	}

	// Try raw binary
	return kem.DeserializeSecretKey(data)
}

// loadSignSecretKeyFromFile loads a signature secret key from a JSON key-pair
// file (base64 "secret_key" field) or a raw binary file.
// With file size validation to prevent unbounded file operations
func loadSignSecretKeyFromFile(filename string) (*kmosaic.MOSAICSignSecretKey, error) {
	const MaxInputFileSize = 100 * 1024 * 1024 // 100 MB limit

	// Check file size before reading
	info, err := os.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}
	if info.Size() > MaxInputFileSize {
		return nil, fmt.Errorf("input file too large: %d > %d bytes", info.Size(), MaxInputFileSize)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Try to parse file as JSON keypair
	var jsonData map[string]interface{}
	if err := json.Unmarshal(data, &jsonData); err == nil {
		// JSON format - extract secret_key field
		if val, ok := jsonData["secret_key"]; ok {
			if strVal, ok := val.(string); ok {
				// Decode base64
				skBytes, err := base64.StdEncoding.DecodeString(strVal)
				if err != nil {
					return nil, fmt.Errorf("failed to decode secret key: %w", err)
				}
				return sign.DeserializeSecretKey(skBytes)
			}
		}
	}

	// Try raw binary
	return sign.DeserializeSecretKey(data)
}

func loadKeyFromFile(filename, keyField string) ([]byte, error) {
	const MaxInputFileSize = 100 * 1024 * 1024 // 100 MB limit

	// Check file size before reading
	info, err := os.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}
	if info.Size() > MaxInputFileSize {
		return nil, fmt.Errorf("input file too large: %d > %d bytes", info.Size(), MaxInputFileSize)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Try to parse as JSON
	var jsonData map[string]interface{}
	if err := json.Unmarshal(data, &jsonData); err == nil {
		// JSON format - extract the specific key
		if val, ok := jsonData[keyField]; ok {
			if strVal, ok := val.(string); ok {
				return decodeString(strVal)
			}
		}
		// If no specific field, try common field names based on keyField
		fieldMappings := map[string][]string{
			"public_key":    {"public_key", "publicKey", "pk"},
			"secret_key":    {"secret_key", "secretKey", "sk"},
			"ciphertext":    {"ciphertext", "ct", "encrypted"},
			"signature":     {"signature", "sig"},
			"shared_secret": {"shared_secret", "sharedSecret", "ss"},
		}
		if fields, ok := fieldMappings[keyField]; ok {
			for _, field := range fields {
				if val, ok := jsonData[field]; ok {
					if strVal, ok := val.(string); ok {
						return decodeString(strVal)
					}
				}
			}
		}
	}

	// Try raw encoding (hex or base64)
	if decoded, err := decodeString(string(data)); err == nil {
		return decoded, nil
	}

	return nil, fmt.Errorf("unable to parse file format")
}

func writeOutput(data []byte, filename string) {
	if filename != "" {
		// Create file with restrictive permissions (0600 read-write for owner only).
		// This follows the standard practice for sensitive key material: secure against
		// other users/processes while remaining usable by the owner.
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		if _, err := f.Write(data); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}

		// Ensure permissions are enforced even if umask is permissive
		if err := os.Chmod(filename, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting file permissions: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println(string(data))
	}
}
