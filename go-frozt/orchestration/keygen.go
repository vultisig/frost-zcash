package orchestration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	frozt "github.com/vultisig/frozt-zcash/go-frozt"
)

const (
	messagePollInterval = 50 * time.Millisecond
)

type KeygenResult struct {
	KeyPackage    []byte
	PubKeyPackage []byte
}

type RoundMessage struct {
	SenderID   uint16 `json:"sender_id"`
	Data       string `json:"data"`
	ReceiverID uint16 `json:"receiver_id,omitempty"`
}

func RunKeygen(ctx context.Context, client *RelayClient, sessionID, partyID string, identifier, maxSigners, minSigners uint16, allParties []string) (*KeygenResult, error) {
	secret1, round1Pkg, err := frozt.DkgPart1(identifier, maxSigners, minSigners)
	if err != nil {
		return nil, fmt.Errorf("dkg part1: %w", err)
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
	err = client.SendMessage(ctx, sessionID, "dkg-round1", Message{
		SessionID: sessionID,
		From:      partyID,
		To:        recipients,
		Body:      string(msgBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("send round1: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, "dkg-round1", partyID, 1, len(allParties))
	if err != nil {
		return nil, fmt.Errorf("barrier dkg-round1: %w", err)
	}

	round1Messages, err := collectMessages(ctx, client, sessionID, partyID, "dkg-round1", len(allParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect round1: %w", err)
	}

	round1Map := buildRoundMap(round1Messages)
	round1Encoded := frozt.EncodeMap(round1Map)

	secret2, round2Pkgs, err := frozt.DkgPart2(secret1, round1Encoded)
	if err != nil {
		return nil, fmt.Errorf("dkg part2: %w", err)
	}

	round2Map, err := frozt.DecodeMap(round2Pkgs)
	if err != nil {
		return nil, fmt.Errorf("decode round2 packages: %w", err)
	}
	err = sendPerRecipient(ctx, client, sessionID, partyID, "dkg-round2", identifier, round2Map, allParties)
	if err != nil {
		return nil, fmt.Errorf("send round2: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, "dkg-round2", partyID, 1, len(allParties))
	if err != nil {
		return nil, fmt.Errorf("barrier dkg-round2: %w", err)
	}

	round2Messages, err := collectMessages(ctx, client, sessionID, partyID, "dkg-round2", len(allParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect round2: %w", err)
	}

	round2RecvMap := buildRoundMap(round2Messages)
	round2Encoded := frozt.EncodeMap(round2RecvMap)

	keyPackage, pubKeyPackage, err := frozt.DkgPart3(secret2, round1Encoded, round2Encoded)
	if err != nil {
		return nil, fmt.Errorf("dkg part3: %w", err)
	}

	return &KeygenResult{
		KeyPackage:    keyPackage,
		PubKeyPackage: pubKeyPackage,
	}, nil
}

func collectMessages(ctx context.Context, client *RelayClient, sessionID, partyID, messageID string, expected int) ([]RoundMessage, error) {
	var collected []RoundMessage
	seen := make(map[uint16]bool)

	for len(collected) < expected {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		msgs, err := client.GetMessages(ctx, sessionID, partyID, messageID)
		if err != nil {
			return nil, err
		}

		for _, m := range msgs {
			var rm RoundMessage
			err = json.Unmarshal([]byte(m.Body), &rm)
			if err != nil {
				return nil, fmt.Errorf("unmarshal round message: %w", err)
			}
			if !seen[rm.SenderID] {
				seen[rm.SenderID] = true
				collected = append(collected, rm)
			}
		}

		if len(collected) < expected {
			time.Sleep(messagePollInterval)
		}
	}

	return collected, nil
}

func buildRoundMap(messages []RoundMessage) []frozt.MapEntry {
	entries := make([]frozt.MapEntry, 0, len(messages))
	for _, m := range messages {
		idBytes, err := frozt.EncodeIdentifier(m.SenderID)
		if err != nil {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(m.Data)
		if err != nil {
			continue
		}
		entries = append(entries, frozt.MapEntry{
			ID:    idBytes,
			Value: data,
		})
	}
	return entries
}

func sendPerRecipient(ctx context.Context, client *RelayClient, sessionID, partyID, messageID string, senderIdentifier uint16, mapEntries []frozt.MapEntry, allParties []string) error {
	partyMap := buildPartyIdentifierMap(allParties)

	for _, entry := range mapEntries {
		recipientID, err := frozt.DecodeIdentifier(entry.ID)
		if err != nil {
			return fmt.Errorf("decode recipient id: %w", err)
		}

		recipientPartyID, ok := partyMap[recipientID]
		if !ok {
			return fmt.Errorf("no party found for identifier %d", recipientID)
		}

		msg := RoundMessage{
			SenderID:   senderIdentifier,
			ReceiverID: recipientID,
			Data:       base64.StdEncoding.EncodeToString(entry.Value),
		}
		msgBytes, err := json.Marshal(msg)
		if err != nil {
			return err
		}

		err = client.SendMessage(ctx, sessionID, messageID, Message{
			SessionID: sessionID,
			From:      partyID,
			To:        []string{recipientPartyID},
			Body:      string(msgBytes),
		})
		if err != nil {
			return fmt.Errorf("send to %s: %w", recipientPartyID, err)
		}
	}

	return nil
}

func otherParties(all []string, self string) []string {
	var others []string
	for _, p := range all {
		if p != self {
			others = append(others, p)
		}
	}
	return others
}

func buildPartyIdentifierMap(parties []string) map[uint16]string {
	sorted := make([]string, len(parties))
	copy(sorted, parties)
	sort.Strings(sorted)

	m := make(map[uint16]string, len(sorted))
	for i, p := range sorted {
		m[uint16(i+1)] = p
	}
	return m
}
