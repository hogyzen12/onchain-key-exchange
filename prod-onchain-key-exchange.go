package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Constants for encryption
const (
	KeyLength         = 32 // AES-256
	NonceSize         = 12 // AES-GCM standard nonce size
	InfoString        = "solana-key-share-encryption"
	DefaultOutputFile = "encrypted_share.json"
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

// Base58Decode decodes a base58 string and ensures 32-byte output
func Base58Decode(encoded string) ([]byte, error) {
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	decode := make(map[rune]int)
	for i, r := range alphabet {
		decode[r] = i
	}

	var result []byte
	target := new([32]byte)
	targetLen := uint64(0)

	for _, r := range encoded {
		value, ok := decode[r]
		if !ok {
			return nil, fmt.Errorf("invalid character in base58 string: %c", r)
		}

		val := uint64(value)
		for i := len(result) - 1; i >= 0; i-- {
			val += uint64(result[i]) * 58
			result[i] = byte(val & 0xFF)
			val >>= 8
		}

		for val > 0 {
			result = append([]byte{byte(val & 0xFF)}, result...)
			val >>= 8
		}
		targetLen++
	}

	// Add leading zeros from the encoded string
	for _, r := range encoded {
		if r != '1' {
			break
		}
		result = append([]byte{0x00}, result...)
	}

	// Ensure exactly 32 bytes
	if len(result) > 32 {
		return nil, fmt.Errorf("decoded public key too long: %d bytes", len(result))
	}

	// Pad with zeros if necessary
	copy(target[32-len(result):], result)

	return target[:], nil
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

// ConvertPubKeyToX25519 converts a Solana (Ed25519) public key to X25519
func ConvertPubKeyToX25519(pubKeyBytes []byte) (*SecureBytes, error) {
	// First, create an edwards25519 Point from the public key bytes
	edPoint, err := edwards25519.NewIdentityPoint().SetBytes(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Ed25519 public key: %v", err)
	}

	// Convert to Montgomery form (X25519)
	x25519Bytes := edPoint.BytesMontgomery()
	return NewSecureBytes(x25519Bytes), nil
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

// EncryptKeyForRecipient encrypts a keypair file for a specific recipient's public key
func EncryptKeyForRecipient(keyToShare []byte, senderPrivateKey, recipientPublicKey []byte) (*EncryptedShare, error) {
	// Convert recipient's Ed25519 public key to X25519
	recipientX25519Pub, err := ConvertPubKeyToX25519(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert recipient public key: %v", err)
	}
	defer recipientX25519Pub.Wipe()

	// Derive shared secret
	sharedSecret, err := DeriveSharedSecret(senderPrivateKey, recipientX25519Pub.Data())
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %v", err)
	}
	defer sharedSecret.Wipe()

	// Create AES-GCM cipher
	block, err := aes.NewCipher(sharedSecret.Data())
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt the key
	ciphertext := aesGCM.Seal(nil, nonce, keyToShare, nil)

	// Combine nonce and ciphertext
	encryptedData := append(nonce, ciphertext...)

	// Get sender's public key for verification
	var senderPub [32]byte
	curve25519.ScalarBaseMult(&senderPub, (*[32]byte)(senderPrivateKey))

	return &EncryptedShare{
		SenderPublicKey: base64.StdEncoding.EncodeToString(senderPub[:]),
		EncryptedData:   base64.StdEncoding.EncodeToString(encryptedData),
	}, nil
}

func main() {
	// Command line flags
	shareKeyPath := flag.String("share", "", "Path to keypair file to share")
	recipientPubKey := flag.String("recipient", "", "Recipient's public key address")
	outputPath := flag.String("output", DefaultOutputFile, "Output path for encrypted share")
	flag.Parse()

	if *shareKeyPath == "" || *recipientPubKey == "" {
		fmt.Println("Error: Need keypair to share (-share) and recipient's public key (-recipient)")
		flag.PrintDefaults()
		return
	}

	// Read keypair to share
	keyToShare, err := ReadKeypair(*shareKeyPath)
	if err != nil {
		fmt.Printf("Error reading key to share: %v\n", err)
		return
	}
	defer keyToShare.Wipe()

	// Decode recipient's public key from base58
	recipientPubKeyBytes, err := Base58Decode(*recipientPubKey)
	if err != nil {
		fmt.Printf("Error decoding recipient public key: %v\n", err)
		return
	}

	// Convert sender's Ed25519 private key to X25519
	senderX25519Priv, err := ConvertEd25519ToX25519(keyToShare.Data()[:32])
	if err != nil {
		fmt.Printf("Error converting sender key: %v\n", err)
		return
	}
	defer senderX25519Priv.Wipe()

	// Encrypt the keypair for the recipient
	encryptedShare, err := EncryptKeyForRecipient(
		keyToShare.Data(),
		senderX25519Priv.Data(),
		recipientPubKeyBytes,
	)
	if err != nil {
		fmt.Printf("Error encrypting key: %v\n", err)
		return
	}

	// Save the encrypted share
	shareData, err := json.MarshalIndent(encryptedShare, "", "  ")
	if err != nil {
		fmt.Printf("Error encoding encrypted share: %v\n", err)
		return
	}

	if err := os.WriteFile(*outputPath, shareData, 0600); err != nil {
		fmt.Printf("Error saving encrypted share: %v\n", err)
		return
	}

	fmt.Printf("Successfully encrypted keypair for recipient and saved to %s\n", *outputPath)
}
