package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Constants for encryption
const (
	KeyLength  = 32 // AES-256
	NonceSize  = 12 // AES-GCM standard nonce size
	InfoString = "solana-key-share-encryption"
)

// SecureBytes wraps sensitive data with secure wiping
type SecureBytes struct {
	data []byte
}

func NewSecureBytes(data []byte) *SecureBytes {
	newData := make([]byte, len(data))
	copy(newData, data)
	return &SecureBytes{data: newData}
}

func (s *SecureBytes) Wipe() {
	if s.data != nil {
		for i := range s.data {
			s.data[i] = 0
		}
		runtime.KeepAlive(s.data)
		s.data = nil
	}
}

func (s *SecureBytes) Data() []byte {
	return s.data
}

// EncryptedShare represents an encrypted key share
type EncryptedShare struct {
	SenderPublicKey string `json:"sender_public_key"`
	EncryptedData   string `json:"encrypted_data"`
}

// ReadKeypair reads a Solana keypair from a JSON file
func ReadKeypair(filePath string) (*SecureBytes, error) {
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keypair file: %v", err)
	}

	var keypair []byte
	err = json.Unmarshal(fileContent, &keypair)
	if err != nil {
		return nil, fmt.Errorf("failed to parse keypair JSON: %v", err)
	}

	if len(keypair) != 64 {
		return nil, fmt.Errorf("invalid keypair length: expected 64 bytes, got %d", len(keypair))
	}

	return NewSecureBytes(keypair), nil
}

// ConvertEd25519ToX25519 converts an Ed25519 private key to X25519
func ConvertEd25519ToX25519(ed25519Priv []byte) (*SecureBytes, error) {
	if len(ed25519Priv) != 32 {
		return nil, fmt.Errorf("invalid Ed25519 private key length")
	}

	hash := sha512.Sum512(ed25519Priv)
	defer func() {
		for i := range hash {
			hash[i] = 0
		}
	}()

	hash[0] &= 248
	hash[31] &= 127
	hash[31] |= 64

	return NewSecureBytes(hash[:32]), nil
}

// DeriveSharedSecret performs X25519 key exchange
func DeriveSharedSecret(privateKey, publicKey []byte) (*SecureBytes, error) {
	var pub, priv, shared [32]byte
	copy(pub[:], publicKey)
	copy(priv[:], privateKey)

	curve25519.ScalarMult(&shared, &priv, &pub)

	reader := hkdf.New(sha512.New, shared[:], nil, []byte(InfoString))
	key := make([]byte, KeyLength)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	// Clean up
	for i := range shared {
		shared[i] = 0
	}
	for i := range pub {
		pub[i] = 0
	}
	for i := range priv {
		priv[i] = 0
	}

	return NewSecureBytes(key), nil
}

// DecryptKeyShare decrypts an encrypted share using recipient's private key
func DecryptKeyShare(share *EncryptedShare, recipientPrivateKey []byte) (*SecureBytes, error) {
	// Decode sender's public key
	senderPub, err := base64.StdEncoding.DecodeString(share.SenderPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode sender public key: %v", err)
	}

	// Convert recipient's Ed25519 private key to X25519
	recipientX25519Priv, err := ConvertEd25519ToX25519(recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert recipient key: %v", err)
	}
	defer recipientX25519Priv.Wipe()

	// Derive shared secret
	sharedSecret, err := DeriveSharedSecret(recipientX25519Priv.Data(), senderPub)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %v", err)
	}
	defer sharedSecret.Wipe()

	// Decode encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(share.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %v", err)
	}

	if len(encryptedData) < NonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Split nonce and ciphertext
	nonce := encryptedData[:NonceSize]
	ciphertext := encryptedData[NonceSize:]

	// Create cipher
	block, err := aes.NewCipher(sharedSecret.Data())
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Decrypt
	decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	return NewSecureBytes(decrypted), nil
}

// DerivePublicKey derives the Solana public key from a keypair
func DerivePublicKey(keypairData []byte) (string, error) {
	if len(keypairData) != 64 {
		return "", fmt.Errorf("invalid keypair length")
	}

	// Use solana-keygen to derive the public key
	cmd := exec.Command("solana-keygen", "pubkey", "-")
	cmd.Stdin = bytes.NewReader(keypairData)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to derive public key using solana-keygen: %v", err)
	}

	return strings.TrimSpace(string(output)), nil
}

// ValidateKeypair uses solana-keygen to validate the keypair
func ValidateKeypair(pubkey, filepath string) error {
	cmd := exec.Command("solana-keygen", "verify", pubkey, filepath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("keypair validation failed: %v\nOutput: %s", err, string(output))
	}
	return nil
}

func main() {
	encryptedShare := flag.String("share", "encrypted_share.json", "Path to encrypted share file")
	recipientKeypair := flag.String("keypair", "", "Path to recipient's keypair file")
	debug := flag.Bool("debug", false, "Enable debug output")
	flag.Parse()

	if *recipientKeypair == "" {
		fmt.Println("Error: Need path to recipient's keypair file (-keypair)")
		flag.PrintDefaults()
		return
	}

	// Read the encrypted share
	fmt.Println("Reading encrypted share...")
	shareData, err := os.ReadFile(*encryptedShare)
	if err != nil {
		fmt.Printf("Error reading encrypted share: %v\n", err)
		return
	}

	var encShare EncryptedShare
	if err := json.Unmarshal(shareData, &encShare); err != nil {
		fmt.Printf("Error parsing encrypted share: %v\n", err)
		return
	}

	if *debug {
		fmt.Printf("Encrypted share structure:\n")
		fmt.Printf("- SenderPublicKey length: %d bytes\n", len(encShare.SenderPublicKey))
		fmt.Printf("- EncryptedData length: %d bytes\n", len(encShare.EncryptedData))
	}

	// Read recipient's keypair
	fmt.Println("Reading recipient's keypair...")
	recipientKey, err := ReadKeypair(*recipientKeypair)
	if err != nil {
		fmt.Printf("Error reading recipient keypair: %v\n", err)
		return
	}
	defer recipientKey.Wipe()

	if *debug {
		fmt.Printf("Recipient keypair read successfully (length: %d bytes)\n", len(recipientKey.Data()))
	}

	// Decrypt the share
	fmt.Println("Decrypting share...")
	decryptedKey, err := DecryptKeyShare(&encShare, recipientKey.Data()[:32])
	if err != nil {
		fmt.Printf("Error decrypting share: %v\n", err)
		return
	}
	defer decryptedKey.Wipe()

	if *debug {
		fmt.Printf("Decrypted data length: %d bytes\n", len(decryptedKey.Data()))
	}

	// Before deriving public key, validate decrypted data format
	if len(decryptedKey.Data()) != 64 {
		fmt.Printf("Error: Decrypted data is not a valid Solana keypair (length: %d, expected: 64)\n", len(decryptedKey.Data()))
		return
	}

	// Create a temporary file for solana-keygen with proper Solana format
	tempFile, err := os.CreateTemp("", "keypair-*.json")
	if err != nil {
		fmt.Printf("Error creating temporary file: %v\n", err)
		return
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	// Convert the bytes to an array of integers for JSON marshaling
	byteArray := make([]int, 64)
	for i, b := range decryptedKey.Data() {
		byteArray[i] = int(b)
	}

	// Write the keypair in Solana's format
	if err := tempFile.Truncate(0); err != nil {
		fmt.Printf("Error truncating temporary file: %v\n", err)
		return
	}
	if _, err := tempFile.Seek(0, 0); err != nil {
		fmt.Printf("Error seeking temporary file: %v\n", err)
		return
	}

	if err := json.NewEncoder(tempFile).Encode(byteArray); err != nil {
		fmt.Printf("Error writing keypair JSON: %v\n", err)
		return
	}
	tempFile.Close()

	// Derive public key using solana-keygen
	cmd := exec.Command("solana-keygen", "pubkey", tempPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running solana-keygen: %v\n", err)
		fmt.Printf("Command output: %s\n", string(output))
		return
	}

	pubKey := strings.TrimSpace(string(output))
	if *debug {
		fmt.Printf("Derived public key: %s\n", pubKey)
	}

	// Save the final keypair in Solana's format
	outputPath := fmt.Sprintf("%s.json", pubKey)
	outputFile, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer outputFile.Close()

	if err := json.NewEncoder(outputFile).Encode(byteArray); err != nil {
		fmt.Printf("Error writing final keypair: %v\n", err)
		return
	}

	fmt.Printf("Successfully decrypted keypair and saved to %s\n", outputPath)

	// Validate the saved keypair using solana-keygen verify with both pubkey and keypair file
	if err := ValidateKeypair(pubKey, outputPath); err != nil {
		fmt.Printf("Warning: %v\n", err)
	} else {
		fmt.Println("✓ Keypair validated successfully with solana-keygen")
	}
}
