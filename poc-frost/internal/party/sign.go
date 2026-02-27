package party

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/vultisig/frost-zcash/go-frost/orchestration"
)

func (n *Node) runSign(ctx context.Context) error {
	keyPackage, err := n.Keystore.LoadKeyPackage(n.Config.SessionID)
	if err != nil {
		return fmt.Errorf("load key package: %w", err)
	}

	pubKeyPackage, err := n.Keystore.LoadPubKeyPackage(n.Config.SessionID)
	if err != nil {
		return fmt.Errorf("load pub key package: %w", err)
	}

	message := []byte(n.Config.SignMessage)
	if len(message) == 0 {
		message = []byte("frost-zcash test message")
	}

	signerParties := n.Config.Signers
	if len(signerParties) == 0 {
		signerParties = n.Config.Parties
	}

	result, err := orchestration.RunSign(
		ctx,
		n.Client,
		n.Config.SessionID,
		n.Config.PartyID,
		n.Config.Identifier,
		keyPackage,
		pubKeyPackage,
		message,
		signerParties,
	)
	if err != nil {
		return fmt.Errorf("sign failed: %w", err)
	}

	log.Printf("[%s] Signing complete!", n.Config.PartyID)
	log.Printf("[%s]   Message: %s", n.Config.PartyID, string(message))
	log.Printf("[%s]   Signature: %s", n.Config.PartyID, hex.EncodeToString(result.Signature))

	err = n.Client.CompleteTSS(ctx, n.Config.SessionID, signerParties)
	if err != nil {
		return fmt.Errorf("complete TSS: %w", err)
	}

	return nil
}
