package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

func encryptData(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, argon2SaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	result := make([]byte, 0, argon2SaltLen+len(ciphertext))
	result = append(result, salt...)
	result = append(result, ciphertext...)
	return result, nil
}

func decryptData(ciphertext []byte, passphrase string) ([]byte, error) {
	if len(ciphertext) < argon2SaltLen {
		return nil, fmt.Errorf("ciphertext too short for salt")
	}

	salt := ciphertext[:argon2SaltLen]
	rest := ciphertext[argon2SaltLen:]

	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(rest) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := rest[:nonceSize]
	data := rest[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
