package relay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const relaySaltLen = 16

func deriveRelayKey(keyBytes, salt []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, keyBytes, salt, []byte("frozt-relay-encryption"))
	derivedKey := make([]byte, 32)
	_, err := io.ReadFull(hkdfReader, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return derivedKey, nil
}

func Encrypt(plaintext string, hexKey string) (string, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", fmt.Errorf("decode encryption key: %w", err)
	}

	salt := make([]byte, relaySaltLen)
	_, err = rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	derivedKey, err := deriveRelayKey(keyBytes, salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	result := make([]byte, 0, relaySaltLen+len(ciphertext))
	result = append(result, salt...)
	result = append(result, ciphertext...)
	return base64.StdEncoding.EncodeToString(result), nil
}

func Decrypt(ciphertextB64 string, hexKey string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("decode base64: %w", err)
	}

	if len(data) < relaySaltLen {
		return "", fmt.Errorf("ciphertext too short for salt")
	}

	salt := data[:relaySaltLen]
	rest := data[relaySaltLen:]

	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", fmt.Errorf("decode encryption key: %w", err)
	}

	derivedKey, err := deriveRelayKey(keyBytes, salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(rest) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce := rest[:nonceSize]
	ciphertext := rest[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}
