package main

import (
	"fmt"
	"os"

	"github.com/tyler-smith/go-bip39"
)

func main() {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		fmt.Fprintf(os.Stderr, "entropy: %v\n", err)
		os.Exit(1)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mnemonic: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(mnemonic)
}
