package orchestration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	frozt "github.com/vultisig/frozt-zcash/go-frozt"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/relay"
)

type KeyImportConfig struct {
	Seed         []byte
	AccountIndex uint32
}

func RunKeyImport(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, identifier, maxSigners, minSigners uint16, config *KeyImportConfig, allParties []string) (*KeygenResult, error) {
	isCoordinator := IsCoordinatorParty(partyID, allParties)

	var seed []byte
	if isCoordinator {
		seed = config.Seed
	}

	secret1, round1Pkg, expectedVK, saplingExtras, err := frozt.KeyImportPart1(identifier, maxSigners, minSigners, seed, config.AccountIndex)
	if err != nil {
		return nil, fmt.Errorf("key import part1: %w", err)
	}

	msg := RoundMessage{
		SenderID: identifier,
		Data:     base64.StdEncoding.EncodeToString(round1Pkg),
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal round1 msg: %w", err)
	}

	recipients := OtherParties(allParties, partyID)
	err = client.SendMessage(ctx, sessionID, "import-round1", relay.Message{
		SessionID: sessionID,
		From:      partyID,
		To:        recipients,
		Body:      string(msgBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("send round1: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, "import-round1", partyID, 1, len(allParties))
	if err != nil {
		return nil, fmt.Errorf("barrier import-round1: %w", err)
	}

	round1Messages, err := collectMessages(ctx, client, sessionID, partyID, "import-round1", len(allParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect round1: %w", err)
	}

	round1Map, err := buildRoundMap(round1Messages)
	if err != nil {
		return nil, fmt.Errorf("build round1 map: %w", err)
	}
	round1Encoded := frozt.EncodeMap(round1Map)

	secret2, round2Pkgs, err := frozt.DkgPart2(secret1, round1Encoded)
	if err != nil {
		return nil, fmt.Errorf("dkg part2: %w", err)
	}

	round2Map, err := frozt.DecodeMap(round2Pkgs)
	if err != nil {
		return nil, fmt.Errorf("decode round2 packages: %w", err)
	}
	err = sendPerRecipient(ctx, client, sessionID, partyID, "import-round2", identifier, round2Map, allParties)
	if err != nil {
		return nil, fmt.Errorf("send round2: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, "import-round2", partyID, 1, len(allParties))
	if err != nil {
		return nil, fmt.Errorf("barrier import-round2: %w", err)
	}

	round2Messages, err := collectMessages(ctx, client, sessionID, partyID, "import-round2", len(allParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect round2: %w", err)
	}

	round2RecvMap, err := buildRoundMap(round2Messages)
	if err != nil {
		return nil, fmt.Errorf("build round2 map: %w", err)
	}
	round2Encoded := frozt.EncodeMap(round2RecvMap)

	expectedVK, err = exchangeBytes(ctx, client, sessionID, partyID, identifier, "import-expected-vk", expectedVK, allParties)
	if err != nil {
		return nil, fmt.Errorf("exchange expected vk: %w", err)
	}

	keyPackage, pubKeyPackage, err := frozt.KeyImportPart3(secret2, round1Encoded, round2Encoded, expectedVK)
	if err != nil {
		return nil, fmt.Errorf("key import part3: %w", err)
	}

	saplingExtras, err = exchangeBytes(ctx, client, sessionID, partyID, identifier, "import-sapling-extras", saplingExtras, allParties)
	if err != nil {
		return nil, fmt.Errorf("exchange sapling extras: %w", err)
	}

	if len(saplingExtras) != 96 {
		return nil, fmt.Errorf("invalid sapling extras length: got %d, want 96", len(saplingExtras))
	}

	err = verifySaplingExtrasConsistency(ctx, client, sessionID, partyID, identifier, saplingExtras, allParties)
	if err != nil {
		return nil, fmt.Errorf("sapling extras consistency: %w", err)
	}

	return &KeygenResult{
		KeyPackage:    keyPackage,
		PubKeyPackage: pubKeyPackage,
		SaplingExtras: saplingExtras,
	}, nil
}

func exchangeBytes(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, identifier uint16, messageID string, data []byte, allParties []string) ([]byte, error) {
	isCoordinator := IsCoordinatorParty(partyID, allParties)

	if isCoordinator {
		msg := RoundMessage{
			SenderID: identifier,
			Data:     base64.StdEncoding.EncodeToString(data),
		}
		msgBytes, err := json.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("marshal %s: %w", messageID, err)
		}

		recipients := OtherParties(allParties, partyID)
		err = client.SendMessage(ctx, sessionID, messageID, relay.Message{
			SessionID: sessionID,
			From:      partyID,
			To:        recipients,
			Body:      string(msgBytes),
		})
		if err != nil {
			return nil, fmt.Errorf("send %s: %w", messageID, err)
		}

		return data, nil
	}

	messages, err := collectMessages(ctx, client, sessionID, partyID, messageID, 1)
	if err != nil {
		return nil, fmt.Errorf("collect %s: %w", messageID, err)
	}

	received, err := base64.StdEncoding.DecodeString(messages[0].Data)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", messageID, err)
	}

	return received, nil
}
