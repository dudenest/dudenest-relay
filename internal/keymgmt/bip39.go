// Package keymgmt implements BIP39 mnemonic generation and AES-256 key derivation.
// Uses github.com/tyler-smith/go-bip39 for mnemonic generation/validation (MIT license).
// Key derivation: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048 rounds) → 64-byte seed → first 32 bytes = AES-256.
package keymgmt

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
)

const (
	EntropyBits  = 128 // 12 words
	pbkdf2Rounds = 2048
	pbkdf2KeyLen = 64
)

// GenerateMnemonic generates a fresh BIP39 12-word mnemonic using crypto/rand entropy.
func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(EntropyBits)
	if err != nil {
		return "", fmt.Errorf("entropy: %w", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("mnemonic: %w", err)
	}
	return mnemonic, nil
}

// MnemonicToKey derives a 32-byte AES-256 key (hex-encoded) from a BIP39 mnemonic.
// passphrase is typically empty ("") for relay use.
func MnemonicToKey(mnemonic, passphrase string) (string, error) {
	if err := ValidateMnemonic(mnemonic); err != nil {
		return "", err
	}
	seed := pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+passphrase), pbkdf2Rounds, pbkdf2KeyLen, sha512.New)
	return hex.EncodeToString(seed[:32]), nil
}

// ValidateMnemonic checks that all words are valid BIP39 words and count is 12.
func ValidateMnemonic(mnemonic string) error {
	if !bip39.IsMnemonicValid(mnemonic) {
		return fmt.Errorf("invalid BIP39 mnemonic (bad words or checksum)")
	}
	return nil
}
