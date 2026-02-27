package orchestration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	frost "github.com/vultisig/frost-zcash/go-frost"
)

type ReshareResult struct {
	KeyPackage    []byte
	PubKeyPackage []byte
}

func RunReshare(
	ctx context.Context,
	client *RelayClient,
	sessionID, partyID string,
	identifier, maxSigners, minSigners uint16,
	oldKeyPackage []byte,
	oldIdentifiers []uint16,
	expectedVerifyingKey []byte,
	allParties []string,
) (*ReshareResult, error) {
	secret1, round1Pkg, err := frost.ResharePart1(identifier, maxSigners, minSigners, oldKeyPackage, oldIdentifiers)
	if err != nil {
		return nil, fmt.Errorf("reshare part1: %w", err)
	}

	msg := RoundMessage{
		SenderID: identifier,
		Data:     base64.StdEncoding.EncodeToString(round1Pkg),
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal round1 msg: %w", err)
	}

	recipients := otherParties(allParties, partyID)
	err = client.SendMessage(ctx, sessionID, "reshare-round1", Message{
		SessionID: sessionID,
		From:      partyID,
		To:        recipients,
		Body:      string(msgBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("send round1: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, "reshare-round1", partyID, 1, len(allParties))
	if err != nil {
		return nil, fmt.Errorf("barrier reshare-round1: %w", err)
	}

	round1Messages, err := collectMessages(ctx, client, sessionID, partyID, "reshare-round1", len(allParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect round1: %w", err)
	}

	round1Map := buildRoundMap(round1Messages)
	round1Encoded := frost.EncodeMap(round1Map)

	secret2, round2Pkgs, err := frost.DkgPart2(secret1, round1Encoded)
	if err != nil {
		return nil, fmt.Errorf("dkg part2: %w", err)
	}

	round2Map, err := frost.DecodeMap(round2Pkgs)
	if err != nil {
		return nil, fmt.Errorf("decode round2 packages: %w", err)
	}
	err = sendPerRecipient(ctx, client, sessionID, partyID, "reshare-round2", identifier, round2Map, allParties)
	if err != nil {
		return nil, fmt.Errorf("send round2: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, "reshare-round2", partyID, 1, len(allParties))
	if err != nil {
		return nil, fmt.Errorf("barrier reshare-round2: %w", err)
	}

	round2Messages, err := collectMessages(ctx, client, sessionID, partyID, "reshare-round2", len(allParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect round2: %w", err)
	}

	round2RecvMap := buildRoundMap(round2Messages)
	round2Encoded := frost.EncodeMap(round2RecvMap)

	keyPackage, pubKeyPackage, err := frost.ResharePart3(secret2, round1Encoded, round2Encoded, expectedVerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("reshare part3: %w", err)
	}

	return &ReshareResult{
		KeyPackage:    keyPackage,
		PubKeyPackage: pubKeyPackage,
	}, nil
}
