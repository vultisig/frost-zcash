package party

import (
	"context"
	"fmt"
	"log"

	frozt "github.com/vultisig/frozt-zcash/go-frozt"
	"github.com/vultisig/frozt-zcash/go-frozt/orchestration"
)

func (n *Node) runKeygen(ctx context.Context) error {
	result, err := orchestration.RunKeygen(
		ctx,
		n.Client,
		n.Config.SessionID,
		n.Config.PartyID,
		n.Config.Identifier,
		n.Config.MaxSigners,
		n.Config.MinSigners,
		n.Config.Parties,
	)
	if err != nil {
		return fmt.Errorf("keygen failed: %w", err)
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

	zAddr, err := frozt.SaplingDeriveAddress(result.PubKeyPackage, result.SaplingExtras)
	if err != nil {
		return fmt.Errorf("derive z-address: %w", err)
	}

	log.Printf("[%s] Keygen complete!", n.Config.PartyID)
	log.Printf("[%s]   Identifier: %d", n.Config.PartyID, id)
	log.Printf("[%s]   Verifying key: %x", n.Config.PartyID, verifyingKey)
	log.Printf("[%s]   Z-address: %s", n.Config.PartyID, zAddr)

	err = n.Client.CompleteTSS(ctx, n.Config.SessionID, n.Config.Parties)
	if err != nil {
		return fmt.Errorf("complete TSS: %w", err)
	}

	return nil
}
