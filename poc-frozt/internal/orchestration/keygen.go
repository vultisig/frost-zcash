package orchestration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	frozt "github.com/vultisig/frozt-zcash/go-frozt"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/relay"
)

type KeygenResult struct {
	KeyPackage    []byte
	PubKeyPackage []byte
	SaplingExtras []byte
}

type RoundMessage struct {
	SenderID   uint16 `json:"sender_id"`
	Data       string `json:"data"`
	ReceiverID uint16 `json:"receiver_id,omitempty"`
}

func RunKeygen(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, identifier, maxSigners, minSigners uint16, allParties []string) (*KeygenResult, error) {
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

	recipients := OtherParties(allParties, partyID)
	err = client.SendMessage(ctx, sessionID, "dkg-round1", relay.Message{
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

	round2RecvMap, err := buildRoundMap(round2Messages)
	if err != nil {
		return nil, fmt.Errorf("build round2 map: %w", err)
	}
	round2Encoded := frozt.EncodeMap(round2RecvMap)

	keyPackage, pubKeyPackage, err := frozt.DkgPart3(secret2, round1Encoded, round2Encoded)
	if err != nil {
		return nil, fmt.Errorf("dkg part3: %w", err)
	}

	saplingExtras, err := exchangeSaplingExtras(ctx, client, sessionID, partyID, identifier, allParties)
	if err != nil {
		return nil, fmt.Errorf("sapling extras: %w", err)
	}

	return &KeygenResult{
		KeyPackage:    keyPackage,
		PubKeyPackage: pubKeyPackage,
		SaplingExtras: saplingExtras,
	}, nil
}

func exchangeSaplingExtras(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, identifier uint16, allParties []string) ([]byte, error) {
	isCoordinator := IsCoordinatorParty(partyID, allParties)

	var extras []byte
	if isCoordinator {
		var err error
		extras, err = frozt.SaplingGenerateExtras()
		if err != nil {
			return nil, fmt.Errorf("generate sapling extras: %w", err)
		}

		msg := RoundMessage{
			SenderID: identifier,
			Data:     base64.StdEncoding.EncodeToString(extras),
		}
		msgBytes, err := json.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("marshal sapling extras: %w", err)
		}

		recipients := OtherParties(allParties, partyID)
		err = client.SendMessage(ctx, sessionID, "sapling-extras", relay.Message{
			SessionID: sessionID,
			From:      partyID,
			To:        recipients,
			Body:      string(msgBytes),
		})
		if err != nil {
			return nil, fmt.Errorf("send sapling extras: %w", err)
		}
	} else {
		messages, err := collectMessages(ctx, client, sessionID, partyID, "sapling-extras", 1)
		if err != nil {
			return nil, fmt.Errorf("collect sapling extras: %w", err)
		}

		extras, err = base64.StdEncoding.DecodeString(messages[0].Data)
		if err != nil {
			return nil, fmt.Errorf("decode sapling extras: %w", err)
		}
	}

	if len(extras) != 96 {
		return nil, fmt.Errorf("invalid sapling extras length: got %d, want 96", len(extras))
	}

	err := verifySaplingExtrasConsistency(ctx, client, sessionID, partyID, identifier, extras, allParties)
	if err != nil {
		return nil, fmt.Errorf("sapling extras consistency: %w", err)
	}

	return extras, nil
}

func verifySaplingExtrasConsistency(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, identifier uint16, extras []byte, allParties []string) error {
	hash := sha256.Sum256(extras)
	myHash := hex.EncodeToString(hash[:])

	msg := RoundMessage{
		SenderID: identifier,
		Data:     myHash,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal hash: %w", err)
	}

	recipients := OtherParties(allParties, partyID)
	err = client.SendMessage(ctx, sessionID, "sapling-extras-hash", relay.Message{
		SessionID: sessionID,
		From:      partyID,
		To:        recipients,
		Body:      string(msgBytes),
	})
	if err != nil {
		return fmt.Errorf("send hash: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, "sapling-extras-hash", partyID, 1, len(allParties))
	if err != nil {
		return fmt.Errorf("barrier: %w", err)
	}

	messages, err := collectMessages(ctx, client, sessionID, partyID, "sapling-extras-hash", len(allParties)-1)
	if err != nil {
		return fmt.Errorf("collect hashes: %w", err)
	}

	for _, m := range messages {
		if m.Data != myHash {
			return fmt.Errorf("party %d has different sapling extras hash", m.SenderID)
		}
	}

	return nil
}

func collectMessages(ctx context.Context, client *relay.RelayClient, sessionID, partyID, messageID string, expected int) ([]RoundMessage, error) {
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
			body, decErr := client.DecryptAndVerify(m)
			if decErr != nil {
				return nil, fmt.Errorf("decrypt round message: %w", decErr)
			}
			var rm RoundMessage
			err = json.Unmarshal([]byte(body), &rm)
			if err != nil {
				return nil, fmt.Errorf("unmarshal round message: %w", err)
			}
			if !seen[rm.SenderID] {
				seen[rm.SenderID] = true
				collected = append(collected, rm)
			}
		}

		if len(collected) < expected {
			time.Sleep(client.MessagePollInterval)
		}
	}

	return collected, nil
}

func buildRoundMap(messages []RoundMessage) ([]frozt.MapEntry, error) {
	entries := make([]frozt.MapEntry, 0, len(messages))
	for _, m := range messages {
		data, err := base64.StdEncoding.DecodeString(m.Data)
		if err != nil {
			return nil, fmt.Errorf("decode base64 from sender %d: %w", m.SenderID, err)
		}
		entries = append(entries, frozt.MapEntry{
			ID:    m.SenderID,
			Value: data,
		})
	}
	return entries, nil
}

func sendPerRecipient(ctx context.Context, client *relay.RelayClient, sessionID, partyID, messageID string, senderIdentifier uint16, mapEntries []frozt.MapEntry, allParties []string) error {
	partyMap := buildPartyIdentifierMap(allParties)

	for _, entry := range mapEntries {
		recipientID := entry.ID

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

		err = client.SendMessage(ctx, sessionID, messageID, relay.Message{
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

func OtherParties(all []string, self string) []string {
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
