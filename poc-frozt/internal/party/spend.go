package party

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	frozt "github.com/vultisig/frozt-zcash/go-frozt"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/lightwalletd"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/orchestration"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/relay"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/spend"
)

type sighashMessage struct {
	Sighash string   `json:"sighash"`
	Alphas  []string `json:"alphas"`
}

func (n *Node) runSpend(ctx context.Context) error {
	keyPackage, err := n.Keystore.LoadKeyPackage(n.Config.SessionID)
	if err != nil {
		return fmt.Errorf("load key package: %w", err)
	}

	pubKeyPackage, err := n.Keystore.LoadPubKeyPackage(n.Config.SessionID)
	if err != nil {
		return fmt.Errorf("load pub key package: %w", err)
	}

	saplingExtras, err := n.Keystore.LoadSaplingExtras(n.Config.SessionID)
	if err != nil {
		return fmt.Errorf("load sapling extras: %w", err)
	}

	signerParties := n.Config.Signers
	if len(signerParties) == 0 {
		signerParties = n.Config.Parties
	}

	isCoordinator := orchestration.IsCoordinatorParty(n.Config.PartyID, signerParties)

	var prep *spend.Preparation
	var sighash []byte
	var alphas [][]byte

	if isCoordinator {
		cfg := spend.PrepareConfig{
			LightwalletdEndpoint: n.Config.LightwalletdEndpoint,
			RecipientAddress:     n.Config.RecipientAddress,
			SendAmount:           n.Config.SendAmount,
			Birthday:             n.Config.Birthday,
			PartyID:              n.Config.PartyID,
		}

		prep, err = spend.PrepareTransaction(ctx, cfg, pubKeyPackage, saplingExtras)
		if err != nil {
			return fmt.Errorf("prepare spend: %w", err)
		}
		defer prep.Builder.Close()

		sighash = prep.Sighash
		alphas = prep.Alphas

		alphaStrings := make([]string, len(alphas))
		for i, a := range alphas {
			alphaStrings[i] = base64.StdEncoding.EncodeToString(a)
		}
		msg := sighashMessage{
			Sighash: base64.StdEncoding.EncodeToString(sighash),
			Alphas:  alphaStrings,
		}
		msgBytes, marshalErr := json.Marshal(msg)
		if marshalErr != nil {
			return fmt.Errorf("marshal sighash msg: %w", marshalErr)
		}

		recipients := orchestration.OtherParties(signerParties, n.Config.PartyID)
		sendErr := n.Client.SendMessage(ctx, n.Config.SessionID, "spend-sighash", relay.Message{
			SessionID: n.Config.SessionID,
			From:      n.Config.PartyID,
			To:        recipients,
			Body:      string(msgBytes),
		})
		if sendErr != nil {
			return fmt.Errorf("broadcast sighash: %w", sendErr)
		}

		log.Printf("[%s] Broadcast sighash and %d alphas to signers", n.Config.PartyID, len(alphas))
	} else {
		var shMsg sighashMessage
		waitErr := orchestration.WaitForMessage(ctx, n.Client, n.Config.SessionID, n.Config.PartyID, "spend-sighash", func(body string) error {
			return json.Unmarshal([]byte(body), &shMsg)
		})
		if waitErr != nil {
			return fmt.Errorf("receive sighash: %w", waitErr)
		}

		sighash, err = base64.StdEncoding.DecodeString(shMsg.Sighash)
		if err != nil {
			return fmt.Errorf("decode sighash: %w", err)
		}
		alphas = make([][]byte, len(shMsg.Alphas))
		for i, a := range shMsg.Alphas {
			alphas[i], err = base64.StdEncoding.DecodeString(a)
			if err != nil {
				return fmt.Errorf("decode alpha %d: %w", i, err)
			}
		}

		log.Printf("[%s] Received sighash and %d alphas from coordinator", n.Config.PartyID, len(alphas))
	}

	signatures := make([][]byte, len(alphas))
	for i, alpha := range alphas {
		log.Printf("[%s] Running FROST signing round %d/%d", n.Config.PartyID, i+1, len(alphas))

		signResult, signErr := orchestration.RunSpendSign(
			ctx,
			n.Client,
			n.Config.SessionID,
			n.Config.PartyID,
			n.Config.Identifier,
			keyPackage,
			pubKeyPackage,
			sighash,
			alpha,
			i,
			signerParties,
		)
		if signErr != nil {
			return fmt.Errorf("spend sign round %d failed: %w", i, signErr)
		}

		signatures[i] = signResult.Signature
		log.Printf("[%s] Round %d signature: %s", n.Config.PartyID, i, hex.EncodeToString(signResult.Signature))
	}

	if isCoordinator {
		rawTx, finalizeErr := frozt.TxBuilderComplete(prep.Builder, signatures)
		if finalizeErr != nil {
			return fmt.Errorf("tx finalize: %w", finalizeErr)
		}

		log.Printf("[%s] Transaction finalized (%d bytes)", n.Config.PartyID, len(rawTx))
		log.Printf("[%s]   Raw tx: %s", n.Config.PartyID, hex.EncodeToString(rawTx))

		broadcastCtx, broadcastCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer broadcastCancel()

		scanner, scannerErr := lightwalletd.NewScanner(n.Config.LightwalletdEndpoint)
		if scannerErr != nil {
			return fmt.Errorf("create scanner for broadcast: %w", scannerErr)
		}
		defer scanner.Close()

		broadcastErr := scanner.SendTransaction(broadcastCtx, rawTx)
		if broadcastErr != nil {
			return fmt.Errorf("broadcast transaction: %w", broadcastErr)
		}

		log.Printf("[%s] Transaction broadcast successfully!", n.Config.PartyID)

		for _, note := range prep.SelectedNotes {
			markErr := n.Keystore.MarkNoteSpent(n.Config.SessionID, note.TxHash, note.Index, note.Height)
			if markErr != nil {
				log.Printf("[%s] Warning: failed to mark note as spent: %v", n.Config.PartyID, markErr)
			}
		}

		recipients := orchestration.OtherParties(signerParties, n.Config.PartyID)
		sendErr := n.Client.SendMessage(ctx, n.Config.SessionID, "spend-broadcast-done", relay.Message{
			SessionID: n.Config.SessionID,
			From:      n.Config.PartyID,
			To:        recipients,
			Body:      "done",
		})
		if sendErr != nil {
			return fmt.Errorf("send broadcast-done: %w", sendErr)
		}
	} else {
		waitErr := orchestration.WaitForMessage(ctx, n.Client, n.Config.SessionID, n.Config.PartyID, "spend-broadcast-done", func(body string) error {
			return nil
		})
		if waitErr != nil {
			return fmt.Errorf("wait for broadcast-done: %w", waitErr)
		}
		log.Printf("[%s] Coordinator confirmed broadcast complete", n.Config.PartyID)
	}

	completeErr := n.Client.CompleteTSS(ctx, n.Config.SessionID, signerParties)
	if completeErr != nil {
		return fmt.Errorf("complete TSS: %w", completeErr)
	}

	return nil
}
