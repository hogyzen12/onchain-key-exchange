package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

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

	// Use HKDF to derive a secure encryption key
	reader := hkdf.New(sha512.New, shared[:], nil, []byte(InfoString))
	key := make([]byte, KeyLength)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	// Clean up the temporary buffers
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

func testDecryption(encryptedSharePath string, keypairPath string) error {
	// Read the encrypted share
	shareData, err := os.ReadFile(encryptedSharePath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted share: %v", err)
	}

	var encShare EncryptedShare
	if err := json.Unmarshal(shareData, &encShare); err != nil {
		return fmt.Errorf("failed to parse encrypted share: %v", err)
	}

	// Read the keypair
	keypair, err := ReadKeypair(keypairPath)
	if err != nil {
		return fmt.Errorf("failed to read keypair: %v", err)
	}
	defer keypair.Wipe()

	// Try to decrypt
	decrypted, err := DecryptKeyShare(&encShare, keypair.Data()[:32])
	if err != nil {
		return fmt.Errorf("decryption failed: %v", err)
	}
	defer decrypted.Wipe()

	// Validate the decrypted data is a valid Solana keypair (64 bytes)
	if len(decrypted.Data()) != 64 {
		return fmt.Errorf("decrypted data is not a valid keypair (got %d bytes, expected 64)", len(decrypted.Data()))
	}

	return nil
}

func main() {
	encryptedShare := flag.String("encrypted", "encrypted_share.json", "Path to encrypted share file")
	correctKeypair := flag.String("correct", "", "Path to correct keypair file")
	wrongKeypair1 := flag.String("wrong1", "", "Path to first wrong keypair file")
	wrongKeypair2 := flag.String("wrong2", "", "Path to second wrong keypair file")
	flag.Parse()

	if *correctKeypair == "" || *wrongKeypair1 == "" || *wrongKeypair2 == "" {
		fmt.Println("Error: Need paths to all three keypairs")
		flag.PrintDefaults()
		return
	}

	fmt.Println("\nRunning decryption tests...")
	fmt.Println("================================")

	// Test 1: Wrong Keypair 1
	fmt.Printf("\nTest 1: Attempting decryption with wrong keypair 1 (%s)\n", *wrongKeypair1)
	err := testDecryption(*encryptedShare, *wrongKeypair1)
	if err != nil {
		fmt.Printf("✓ Test 1 Passed: Decryption correctly failed with wrong keypair 1\n")
		fmt.Printf("  Error: %v\n", err)
	} else {
		fmt.Printf("✗ Test 1 Failed: Decryption unexpectedly succeeded with wrong keypair 1!\n")
	}

	// Test 2: Correct Keypair
	fmt.Printf("\nTest 2: Attempting decryption with correct keypair (%s)\n", *correctKeypair)
	err = testDecryption(*encryptedShare, *correctKeypair)
	if err != nil {
		fmt.Printf("✗ Test 2 Failed: Decryption failed with correct keypair!\n")
		fmt.Printf("  Error: %v\n", err)
	} else {
		fmt.Printf("✓ Test 2 Passed: Successfully decrypted with correct keypair\n")
	}

	// Test 3: Wrong Keypair 2
	fmt.Printf("\nTest 3: Attempting decryption with wrong keypair 2 (%s)\n", *wrongKeypair2)
	err = testDecryption(*encryptedShare, *wrongKeypair2)
	if err != nil {
		fmt.Printf("✓ Test 3 Passed: Decryption correctly failed with wrong keypair 2\n")
		fmt.Printf("  Error: %v\n", err)
	} else {
		fmt.Printf("✗ Test 3 Failed: Decryption unexpectedly succeeded with wrong keypair 2!\n")
	}

	fmt.Println("\n================================")
	fmt.Println("Tests complete!")
}
