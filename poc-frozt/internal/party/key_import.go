package party

import (
	"context"
	"fmt"
	"log"

	frozt "github.com/vultisig/frozt-zcash/go-frozt"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/bip39"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/orchestration"
)

func (n *Node) runKeyImport(ctx context.Context) error {
	var config *orchestration.KeyImportConfig

	isCoordinator := orchestration.IsCoordinatorParty(n.Config.PartyID, n.Config.Parties)

	if isCoordinator {
		if n.Config.Mnemonic == "" {
			return fmt.Errorf("coordinator requires MNEMONIC env var")
		}

		seed := bip39.MnemonicToSeed(n.Config.Mnemonic)

		config = &orchestration.KeyImportConfig{
			Seed:         seed,
			AccountIndex: 0,
		}

		log.Printf("[%s] Coordinator: derived seed from mnemonic", n.Config.PartyID)
	} else {
		config = &orchestration.KeyImportConfig{}
	}

	result, err := orchestration.RunKeyImport(
		ctx,
		n.Client,
		n.Config.SessionID,
		n.Config.PartyID,
		n.Config.Identifier,
		n.Config.MaxSigners,
		n.Config.MinSigners,
		config,
		n.Config.Parties,
	)
	if err != nil {
		return fmt.Errorf("key import failed: %w", err)
	}

	err = n.Keystore.SaveKeyPackage(n.Config.SessionID, result.KeyPackage)
	if err != nil {
		return fmt.Errorf("save key package: %w", err)
	}

	err = n.Keystore.SavePubKeyPackage(n.Config.SessionID, result.PubKeyPackage)
	if err != nil {
		return fmt.Errorf("save pub key package: %w", err)
	}

	err = n.Keystore.SaveSaplingExtras(n.Config.SessionID, result.SaplingExtras)
	if err != nil {
		return fmt.Errorf("save sapling extras: %w", err)
	}

	id, err := frozt.KeyPackageIdentifier(result.KeyPackage)
	if err != nil {
		return fmt.Errorf("get key package identifier: %w", err)
	}

	verifyingKey, err := frozt.PubKeyPackageVerifyingKey(result.PubKeyPackage)
	if err != nil {
		return fmt.Errorf("get verifying key: %w", err)
	}

	keys, err := frozt.SaplingDeriveKeys(result.PubKeyPackage, result.SaplingExtras)
	if err != nil {
		return fmt.Errorf("derive z-address: %w", err)
	}

	log.Printf("[%s] Key import complete!", n.Config.PartyID)
	log.Printf("[%s]   Identifier: %d", n.Config.PartyID, id)
	log.Printf("[%s]   Verifying key: %x", n.Config.PartyID, verifyingKey)
	log.Printf("[%s]   Z-address: %s", n.Config.PartyID, keys.Address)

	if n.Config.ExpectedAddress != "" && keys.Address != n.Config.ExpectedAddress {
		return fmt.Errorf("z-address mismatch: got %s, expected %s", keys.Address, n.Config.ExpectedAddress)
	}

	err = n.Client.CompleteTSS(ctx, n.Config.SessionID, n.Config.Parties)
	if err != nil {
		return fmt.Errorf("complete TSS: %w", err)
	}

	return nil
}
