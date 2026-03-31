// Package crypto provides AES-256-GCM encryption for relay blocks.
// Each block gets a unique 12-byte random nonce. Key is derived from
// the master key + block ID using HKDF-SHA256 (per-block key derivation).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const KeySize = 32 // AES-256

// Encryptor holds the master key and derives per-block keys.
type Encryptor struct {
	masterKey []byte // 32 bytes
}

func New(masterKey []byte) (*Encryptor, error) {
	if len(masterKey) != KeySize {
		return nil, errors.New("master key must be 32 bytes (AES-256)")
	}
	k := make([]byte, KeySize)
	copy(k, masterKey)
	return &Encryptor{masterKey: k}, nil
}

// deriveKey produces a unique 32-byte key for a specific block using HKDF.
func (e *Encryptor) deriveKey(blockID string) ([]byte, error) {
	h := hkdf.New(sha256.New, e.masterKey, []byte(blockID), []byte("dudenest-relay-v1"))
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt encrypts plaintext for a given blockID. Returns [nonce | ciphertext+tag].
func (e *Encryptor) Encrypt(blockID string, plaintext []byte) ([]byte, error) {
	key, err := e.deriveKey(blockID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil) // nonce prepended
	return ciphertext, nil
}

// Decrypt decrypts data produced by Encrypt. Expects [nonce | ciphertext+tag].
func (e *Encryptor) Decrypt(blockID string, data []byte) ([]byte, error) {
	key, err := e.deriveKey(blockID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DeriveKeyFromPassword derives a 32-byte master key from a password + salt.
// Uses HKDF-SHA256 (user should use Argon2id outside for password stretching).
func DeriveKeyFromPassword(password, salt string) []byte {
	h := hkdf.New(sha256.New, []byte(password), []byte(salt), []byte("dudenest-master-key-v1"))
	key := make([]byte, KeySize)
	io.ReadFull(h, key) //nolint:errcheck
	return key
}
