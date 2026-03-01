package bip39

import (
	"encoding/hex"
	"testing"
)

func TestMnemonicToSeed_KnownVector(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	seed := MnemonicToSeed(mnemonic)
	if len(seed) != 64 {
		t.Fatalf("seed length = %d, want 64", len(seed))
	}

	want := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	got := hex.EncodeToString(seed)
	if got != want {
		t.Fatalf("seed = %s, want %s", got, want)
	}
}

func TestMnemonicToSeed_Deterministic(t *testing.T) {
	mnemonic := "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
	s1 := MnemonicToSeed(mnemonic)
	s2 := MnemonicToSeed(mnemonic)
	if hex.EncodeToString(s1) != hex.EncodeToString(s2) {
		t.Fatal("same mnemonic should produce same seed")
	}
}

func TestMnemonicToSeed_DifferentMnemonics(t *testing.T) {
	s1 := MnemonicToSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	s2 := MnemonicToSeed("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
	if hex.EncodeToString(s1) == hex.EncodeToString(s2) {
		t.Fatal("different mnemonics should produce different seeds")
	}
}

func TestMnemonicToSeed_EmptyMnemonic(t *testing.T) {
	seed := MnemonicToSeed("")
	if len(seed) != 64 {
		t.Fatalf("seed length = %d, want 64", len(seed))
	}
}
