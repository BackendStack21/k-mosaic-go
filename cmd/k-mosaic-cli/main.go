// Package main provides the k-mosaic-cli command line interface for kMOSAIC operations.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	kmosaic "github.com/BackendStack21/k-mosaic-go"
	"github.com/BackendStack21/k-mosaic-go/kem"
	"github.com/BackendStack21/k-mosaic-go/sign"
)

const (
	version = "1.0.0"
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
}

// SignKeyPairExport represents an exported signature key pair
type SignKeyPairExport struct {
	SecurityLevel string `json:"security_level"`
	PublicKey     string `json:"public_key"`
	SecretKey     string `json:"secret_key"`
	CreatedAt     string `json:"created_at"`
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
	case "decapsulate", "decap":
		kemDecapsulate(args[1:])
	case "encrypt", "enc":
		kemEncrypt(args[1:])
	case "decrypt", "dec":
		kemDecrypt(args[1:])
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
		SecretKey:     encodeBytes(skBytes, config.OutputFormat),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
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

func kemDecapsulate(args []string) {
	config := parseConfig(args)
	skFile := getArg(args, "--secret-key", "-sk")
	pkFile := getArg(args, "--public-key", "-pk")
	ctFile := getArg(args, "--ciphertext", "-ct")

	if skFile == "" || pkFile == "" || ctFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --secret-key, --public-key, and --ciphertext are required\n")
		os.Exit(1)
	}

	// Load keys
	skData, err := loadKeyFromFile(skFile, "secret_key")
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

	sk, err := kem.DeserializeSecretKey(skData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing secret key: %v\n", err)
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

	// Load keys
	skData, err := loadKeyFromFile(skFile, "secret_key")
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

	sk, err := kem.DeserializeSecretKey(skData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing secret key: %v\n", err)
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
		SecretKey:     encodeBytes(skBytes, config.OutputFormat),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
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

	// Load keys
	skData, err := loadKeyFromFile(skFile, "secret_key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading secret key: %v\n", err)
		os.Exit(1)
	}

	pkData, err := loadKeyFromFile(pkFile, "public_key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
		os.Exit(1)
	}

	sk, err := sign.DeserializeSecretKey(skData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing secret key: %v\n", err)
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
	}

	format := getArg(args, "--format", "-f")
	switch format {
	case "hex":
		config.OutputFormat = FormatHex
	case "base64":
		config.OutputFormat = FormatBase64
	case "json":
		config.OutputFormat = FormatJSON
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

func decodeString(s string) ([]byte, error) {
	// Try base64 first
	if data, err := base64.StdEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	// Try hex
	if data, err := hex.DecodeString(s); err == nil {
		return data, nil
	}
	return nil, fmt.Errorf("unable to decode string")
}

func loadKeyFromFile(filename, keyField string) ([]byte, error) {
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

	// Try raw encoding
	trimmed := strings.TrimSpace(string(data))

	// Try base64
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return decoded, nil
	}

	// Try hex
	if decoded, err := hex.DecodeString(trimmed); err == nil {
		return decoded, nil
	}

	return nil, fmt.Errorf("unable to parse file format")
}

func writeOutput(data []byte, filename string) {
	if filename != "" {
		if err := os.WriteFile(filename, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println(string(data))
	}
}
