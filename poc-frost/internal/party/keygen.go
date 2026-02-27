package party

import (
	"context"
	"fmt"
	"log"

	frost "github.com/vultisig/frost-zcash/go-frost"
	"github.com/vultisig/frost-zcash/go-frost/orchestration"
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

	id, err := frost.KeyPackageIdentifier(result.KeyPackage)
	if err != nil {
		return fmt.Errorf("get key package identifier: %w", err)
	}

	verifyingKey, err := frost.PubKeyPackageVerifyingKey(result.PubKeyPackage)
	if err != nil {
		return fmt.Errorf("get verifying key: %w", err)
	}

	zAddr, err := frost.DeriveZAddress(result.PubKeyPackage)
	if err != nil {
		return fmt.Errorf("derive z-address: %w", err)
	}

	tAddr, err := frost.PubKeyToTAddress(result.PubKeyPackage)
	if err != nil {
		return fmt.Errorf("derive t-address: %w", err)
	}

	log.Printf("[%s] Keygen complete!", n.Config.PartyID)
	log.Printf("[%s]   Identifier: %d", n.Config.PartyID, id)
	log.Printf("[%s]   Verifying key: %x", n.Config.PartyID, verifyingKey)
	log.Printf("[%s]   Z-Address: %s", n.Config.PartyID, zAddr)
	log.Printf("[%s]   T-Address: %s", n.Config.PartyID, tAddr)

	err = n.Client.CompleteTSS(ctx, n.Config.SessionID, n.Config.Parties)
	if err != nil {
		return fmt.Errorf("complete TSS: %w", err)
	}

	return nil
}
