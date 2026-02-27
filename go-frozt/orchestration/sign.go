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

type SignResult struct {
	Signature []byte
}

type CommitmentMessage struct {
	SenderID   uint16 `json:"sender_id"`
	Commitment string `json:"commitment"`
}

type SigningPackageMessage struct {
	SigningPackage string `json:"signing_package"`
	Randomizer    string `json:"randomizer"`
}

type SignShareMessage struct {
	SenderID uint16 `json:"sender_id"`
	Share    string `json:"share"`
}

func RunSign(ctx context.Context, client *RelayClient, sessionID, partyID string, identifier uint16, keyPackage, pubKeyPackage, message []byte, signerParties []string) (*SignResult, error) {
	isCoordinator := isCoordinatorParty(partyID, signerParties)

	nonces, commitmentBytes, err := frozt.SignCommit(keyPackage)
	if err != nil {
		return nil, fmt.Errorf("sign commit: %w", err)
	}

	commitMsg := CommitmentMessage{
		SenderID:   identifier,
		Commitment: base64.StdEncoding.EncodeToString(commitmentBytes),
	}
	commitMsgBytes, err := json.Marshal(commitMsg)
	if err != nil {
		return nil, fmt.Errorf("marshal commitment: %w", err)
	}

	recipients := otherParties(signerParties, partyID)
	err = client.SendMessage(ctx, sessionID, "sign-commit", Message{
		SessionID: sessionID,
		From:      partyID,
		To:        recipients,
		Body:      string(commitMsgBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("send commitment: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, "sign-commit", partyID, 1, len(signerParties))
	if err != nil {
		return nil, fmt.Errorf("barrier sign-commit: %w", err)
	}

	commitMessages, err := collectCommitments(ctx, client, sessionID, partyID, len(signerParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect commitments: %w", err)
	}

	allCommitments := append(commitMessages, CommitmentMessage{
		SenderID:   identifier,
		Commitment: base64.StdEncoding.EncodeToString(commitmentBytes),
	})

	commitmentsMap := buildCommitmentsMap(allCommitments)
	commitmentsEncoded := frozt.EncodeMap(commitmentsMap)

	if isCoordinator {
		return runCoordinator(ctx, client, sessionID, partyID, identifier, nonces, keyPackage, pubKeyPackage, message, commitmentsEncoded, signerParties)
	}
	return runSigner(ctx, client, sessionID, partyID, identifier, nonces, keyPackage, message, commitmentsEncoded, pubKeyPackage, signerParties)
}

func runCoordinator(ctx context.Context, client *RelayClient, sessionID, partyID string, identifier uint16, nonces frozt.Handle, keyPackage, pubKeyPackage, message, commitmentsEncoded []byte, signerParties []string) (*SignResult, error) {
	signingPackage, randomizer, err := frozt.SignNewPackage(message, commitmentsEncoded, pubKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("sign new package: %w", err)
	}

	spMsg := SigningPackageMessage{
		SigningPackage: base64.StdEncoding.EncodeToString(signingPackage),
		Randomizer:    base64.StdEncoding.EncodeToString(randomizer),
	}
	spMsgBytes, err := json.Marshal(spMsg)
	if err != nil {
		return nil, fmt.Errorf("marshal signing package: %w", err)
	}

	recipients := otherParties(signerParties, partyID)
	err = client.SendMessage(ctx, sessionID, "sign-package", Message{
		SessionID: sessionID,
		From:      partyID,
		To:        recipients,
		Body:      string(spMsgBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("send signing package: %w", err)
	}

	myShare, err := frozt.Sign(signingPackage, nonces, keyPackage, randomizer)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	shares, err := collectSignShares(ctx, client, sessionID, partyID, len(signerParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect sign shares: %w", err)
	}

	myIDBytes, err := frozt.EncodeIdentifier(identifier)
	if err != nil {
		return nil, fmt.Errorf("encode my id: %w", err)
	}

	allShareEntries := []frozt.MapEntry{{ID: myIDBytes, Value: myShare}}
	for _, s := range shares {
		idBytes, err := frozt.EncodeIdentifier(s.SenderID)
		if err != nil {
			return nil, fmt.Errorf("encode share sender id: %w", err)
		}
		shareData, err := base64.StdEncoding.DecodeString(s.Share)
		if err != nil {
			return nil, fmt.Errorf("decode share data: %w", err)
		}
		allShareEntries = append(allShareEntries, frozt.MapEntry{ID: idBytes, Value: shareData})
	}

	sharesEncoded := frozt.EncodeMap(allShareEntries)
	signature, err := frozt.SignAggregate(signingPackage, sharesEncoded, pubKeyPackage, randomizer)
	if err != nil {
		return nil, fmt.Errorf("sign aggregate: %w", err)
	}

	sigMsg := base64.StdEncoding.EncodeToString(signature)
	err = client.SendMessage(ctx, sessionID, "sign-result", Message{
		SessionID: sessionID,
		From:      partyID,
		To:        otherParties(signerParties, partyID),
		Body:      sigMsg,
	})
	if err != nil {
		return nil, fmt.Errorf("broadcast signature: %w", err)
	}

	return &SignResult{Signature: signature}, nil
}

func runSigner(ctx context.Context, client *RelayClient, sessionID, partyID string, identifier uint16, nonces frozt.Handle, keyPackage, message, commitmentsEncoded, pubKeyPackage []byte, signerParties []string) (*SignResult, error) {
	coordinatorID := getCoordinatorPartyID(signerParties)

	var spMsg SigningPackageMessage
	err := waitForMessage(ctx, client, sessionID, partyID, "sign-package", func(body string) error {
		return json.Unmarshal([]byte(body), &spMsg)
	})
	if err != nil {
		return nil, fmt.Errorf("receive signing package: %w", err)
	}

	signingPackage, err := base64.StdEncoding.DecodeString(spMsg.SigningPackage)
	if err != nil {
		return nil, fmt.Errorf("decode signing package: %w", err)
	}
	randomizer, err := base64.StdEncoding.DecodeString(spMsg.Randomizer)
	if err != nil {
		return nil, fmt.Errorf("decode randomizer: %w", err)
	}

	share, err := frozt.Sign(signingPackage, nonces, keyPackage, randomizer)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	shareMsg := SignShareMessage{
		SenderID: identifier,
		Share:    base64.StdEncoding.EncodeToString(share),
	}
	shareMsgBytes, err := json.Marshal(shareMsg)
	if err != nil {
		return nil, fmt.Errorf("marshal share: %w", err)
	}

	err = client.SendMessage(ctx, sessionID, "sign-share", Message{
		SessionID: sessionID,
		From:      partyID,
		To:        []string{coordinatorID},
		Body:      string(shareMsgBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("send share: %w", err)
	}

	var signature []byte
	err = waitForMessage(ctx, client, sessionID, partyID, "sign-result", func(body string) error {
		sig, decErr := base64.StdEncoding.DecodeString(body)
		if decErr != nil {
			return decErr
		}
		signature = sig
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("receive signature: %w", err)
	}

	return &SignResult{Signature: signature}, nil
}

func collectCommitments(ctx context.Context, client *RelayClient, sessionID, partyID string, expected int) ([]CommitmentMessage, error) {
	var collected []CommitmentMessage
	seen := make(map[uint16]bool)

	for len(collected) < expected {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		msgs, err := client.GetMessages(ctx, sessionID, partyID, "sign-commit")
		if err != nil {
			return nil, err
		}

		for _, m := range msgs {
			var cm CommitmentMessage
			err = json.Unmarshal([]byte(m.Body), &cm)
			if err != nil {
				return nil, fmt.Errorf("unmarshal commitment: %w", err)
			}
			if !seen[cm.SenderID] {
				seen[cm.SenderID] = true
				collected = append(collected, cm)
			}
		}

		if len(collected) < expected {
			time.Sleep(messagePollInterval)
		}
	}

	return collected, nil
}

func collectSignShares(ctx context.Context, client *RelayClient, sessionID, partyID string, expected int) ([]SignShareMessage, error) {
	var collected []SignShareMessage
	seen := make(map[uint16]bool)

	for len(collected) < expected {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		msgs, err := client.GetMessages(ctx, sessionID, partyID, "sign-share")
		if err != nil {
			return nil, err
		}

		for _, m := range msgs {
			var sm SignShareMessage
			err = json.Unmarshal([]byte(m.Body), &sm)
			if err != nil {
				return nil, fmt.Errorf("unmarshal sign share: %w", err)
			}
			if !seen[sm.SenderID] {
				seen[sm.SenderID] = true
				collected = append(collected, sm)
			}
		}

		if len(collected) < expected {
			time.Sleep(messagePollInterval)
		}
	}

	return collected, nil
}

func waitForMessage(ctx context.Context, client *RelayClient, sessionID, partyID, messageID string, parse func(string) error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msgs, err := client.GetMessages(ctx, sessionID, partyID, messageID)
		if err != nil {
			return err
		}

		if len(msgs) > 0 {
			return parse(msgs[0].Body)
		}

		time.Sleep(messagePollInterval)
	}
}

func buildCommitmentsMap(commitments []CommitmentMessage) []frozt.MapEntry {
	entries := make([]frozt.MapEntry, 0, len(commitments))
	for _, c := range commitments {
		idBytes, err := frozt.EncodeIdentifier(c.SenderID)
		if err != nil {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(c.Commitment)
		if err != nil {
			continue
		}
		entries = append(entries, frozt.MapEntry{ID: idBytes, Value: data})
	}
	return entries
}

func isCoordinatorParty(partyID string, parties []string) bool {
	return partyID == getCoordinatorPartyID(parties)
}

func getCoordinatorPartyID(parties []string) string {
	sorted := make([]string, len(parties))
	copy(sorted, parties)
	sort.Strings(sorted)
	return sorted[0]
}
