package bip39

import (
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

func MnemonicToSeed(mnemonic string) []byte {
	password := []byte(mnemonic)
	salt := []byte("mnemonic")
	return pbkdf2.Key(password, salt, 2048, 64, sha512.New)
}
