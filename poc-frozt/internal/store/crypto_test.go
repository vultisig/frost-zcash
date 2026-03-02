package store

import (
	"bytes"
	"testing"
)

func TestDeriveKey_Deterministic(t *testing.T) {
	salt := []byte("fixed-test-salt!")
	k1 := deriveKey("test-passphrase", salt)
	k2 := deriveKey("test-passphrase", salt)
	if !bytes.Equal(k1, k2) {
		t.Fatal("same passphrase+salt should produce same key")
	}
	if len(k1) != 32 {
		t.Fatalf("key length = %d, want 32", len(k1))
	}
}

func TestDeriveKey_DifferentPassphrases(t *testing.T) {
	salt := []byte("fixed-test-salt!")
	k1 := deriveKey("passphrase-a", salt)
	k2 := deriveKey("passphrase-b", salt)
	if bytes.Equal(k1, k2) {
		t.Fatal("different passphrases should produce different keys")
	}
}

func TestDeriveKey_DifferentSalts(t *testing.T) {
	k1 := deriveKey("same-pass", []byte("salt-aaaaaaaaaaaA"))
	k2 := deriveKey("same-pass", []byte("salt-bbbbbbbbbbB"))
	if bytes.Equal(k1, k2) {
		t.Fatal("different salts should produce different keys")
	}
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	plaintext := []byte("hello frozt keystore")
	passphrase := "my-secret-pass"

	ct, err := encryptData(plaintext, passphrase)
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("ciphertext should not be empty")
	}

	decrypted, err := decryptData(ct, passphrase)
	if err != nil {
		t.Fatalf("decryptData: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptProducesUniqueCiphertexts(t *testing.T) {
	plaintext := []byte("same message")
	passphrase := "same-key"

	ct1, err := encryptData(plaintext, passphrase)
	if err != nil {
		t.Fatalf("encrypt 1: %v", err)
	}
	ct2, err := encryptData(plaintext, passphrase)
	if err != nil {
		t.Fatalf("encrypt 2: %v", err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Fatal("same plaintext should produce different ciphertexts (random salt+nonce)")
	}
}

func TestDecryptWrongPassphrase(t *testing.T) {
	ct, err := encryptData([]byte("secret"), "correct-pass")
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}
	_, err = decryptData(ct, "wrong-pass")
	if err == nil {
		t.Fatal("expected error when decrypting with wrong passphrase")
	}
}

func TestDecryptTooShort(t *testing.T) {
	_, err := decryptData([]byte{1, 2, 3}, "any-pass")
	if err == nil {
		t.Fatal("expected error for ciphertext shorter than salt")
	}
}

func TestEncryptDecryptEmptyPlaintext(t *testing.T) {
	ct, err := encryptData([]byte{}, "pass")
	if err != nil {
		t.Fatalf("encryptData empty: %v", err)
	}
	decrypted, err := decryptData(ct, "pass")
	if err != nil {
		t.Fatalf("decryptData empty: %v", err)
	}
	if len(decrypted) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}
