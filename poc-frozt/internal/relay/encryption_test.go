package relay

import (
	"encoding/hex"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := hex.EncodeToString([]byte("test-encryption-key-32bytes!!!!"))
	plaintext := "hello frozt relay"

	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ciphertext == "" {
		t.Fatal("ciphertext should not be empty")
	}

	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptProducesUniqueCiphertexts(t *testing.T) {
	key := hex.EncodeToString([]byte("test-key-for-uniqueness-check!!"))
	plaintext := "same message"

	ct1, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}

	ct2, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	if ct1 == ct2 {
		t.Fatal("encrypting same plaintext should produce different ciphertexts (random nonce)")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := hex.EncodeToString([]byte("correct-key-32bytes-padded!!!!!"))
	key2 := hex.EncodeToString([]byte("wrong---key-32bytes-padded!!!!!"))

	ct, err := Encrypt("secret", key1)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(ct, key2)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestDecryptInvalidBase64(t *testing.T) {
	key := hex.EncodeToString([]byte("some-key-that-is-32-bytes!!!!!!"))
	_, err := Decrypt("not-valid-base64!!!", key)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestEncryptInvalidHexKey(t *testing.T) {
	_, err := Encrypt("hello", "not-hex")
	if err == nil {
		t.Fatal("expected error for invalid hex key")
	}
}

func TestEncryptDecryptEmptyMessage(t *testing.T) {
	key := hex.EncodeToString([]byte("test-key-for-empty-msg-testing!"))

	ct, err := Encrypt("", key)
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	decrypted, err := Decrypt(ct, key)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if decrypted != "" {
		t.Fatalf("expected empty string, got %q", decrypted)
	}
}

func TestEncryptDecryptLargeMessage(t *testing.T) {
	key := hex.EncodeToString([]byte("test-key-for-large-message!!!!!"))
	msg := make([]byte, 10000)
	for i := range msg {
		msg[i] = byte(i % 256)
	}

	ct, err := Encrypt(string(msg), key)
	if err != nil {
		t.Fatalf("Encrypt large: %v", err)
	}

	decrypted, err := Decrypt(ct, key)
	if err != nil {
		t.Fatalf("Decrypt large: %v", err)
	}
	if decrypted != string(msg) {
		t.Fatal("large message roundtrip failed")
	}
}
