package orchestration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	frozt "github.com/vultisig/frozt-zcash/go-frozt"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/relay"
)

type SpendSignResult struct {
	Signature []byte
}

func RunSpendSign(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, identifier uint16, keyPackage, pubKeyPackage, sighash, alpha []byte, roundIndex int, signerParties []string) (*SpendSignResult, error) {
	isCoordinator := IsCoordinatorParty(partyID, signerParties)

	commitPhase := fmt.Sprintf("spend-commit-%d", roundIndex)
	packagePhase := fmt.Sprintf("spend-package-%d", roundIndex)
	sharePhase := fmt.Sprintf("spend-share-%d", roundIndex)
	resultPhase := fmt.Sprintf("spend-result-%d", roundIndex)

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

	recipients := OtherParties(signerParties, partyID)
	err = client.SendMessage(ctx, sessionID, commitPhase, relay.Message{
		SessionID: sessionID,
		From:      partyID,
		To:        recipients,
		Body:      string(commitMsgBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("send commitment: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, commitPhase, partyID, 1, len(signerParties))
	if err != nil {
		return nil, fmt.Errorf("barrier %s: %w", commitPhase, err)
	}

	commitMessages, err := collectCommitments(ctx, client, sessionID, partyID, commitPhase, len(signerParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect commitments: %w", err)
	}

	allCommitments := append(commitMessages, CommitmentMessage{
		SenderID:   identifier,
		Commitment: base64.StdEncoding.EncodeToString(commitmentBytes),
	})

	commitmentsMap, err := buildCommitmentsMap(allCommitments)
	if err != nil {
		return nil, fmt.Errorf("build commitments map: %w", err)
	}
	commitmentsEncoded := frozt.EncodeMap(commitmentsMap)

	if isCoordinator {
		return runSpendCoordinator(ctx, client, sessionID, partyID, identifier, nonces, keyPackage, pubKeyPackage, sighash, alpha, commitmentsEncoded, signerParties, packagePhase, sharePhase, resultPhase)
	}
	return runSpendSigner(ctx, client, sessionID, partyID, identifier, nonces, keyPackage, sighash, alpha, commitmentsEncoded, signerParties, packagePhase, sharePhase, resultPhase)
}

func runSpendCoordinator(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, identifier uint16, nonces frozt.NoncesHandle, keyPackage, pubKeyPackage, sighash, alpha, commitmentsEncoded []byte, signerParties []string, packagePhase, sharePhase, resultPhase string) (*SpendSignResult, error) {
	signingPackage, _, err := frozt.SignNewPackage(sighash, commitmentsEncoded, pubKeyPackage)
	if err != nil {
		return nil, fmt.Errorf("sign new package: %w", err)
	}

	spMsg := SigningPackageMessage{
		SigningPackage: base64.StdEncoding.EncodeToString(signingPackage),
		Randomizer:    base64.StdEncoding.EncodeToString(alpha),
	}
	spMsgBytes, err := json.Marshal(spMsg)
	if err != nil {
		return nil, fmt.Errorf("marshal signing package: %w", err)
	}

	recipients := OtherParties(signerParties, partyID)
	err = client.SendMessage(ctx, sessionID, packagePhase, relay.Message{
		SessionID: sessionID,
		From:      partyID,
		To:        recipients,
		Body:      string(spMsgBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("send signing package: %w", err)
	}

	myShare, err := frozt.Sign(signingPackage, nonces, keyPackage, alpha)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	shares, err := collectSignShares(ctx, client, sessionID, partyID, sharePhase, len(signerParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect sign shares: %w", err)
	}

	allShareEntries := []frozt.MapEntry{{ID: identifier, Value: myShare}}
	for _, s := range shares {
		shareData, decErr := base64.StdEncoding.DecodeString(s.Share)
		if decErr != nil {
			return nil, fmt.Errorf("decode share data: %w", decErr)
		}
		allShareEntries = append(allShareEntries, frozt.MapEntry{ID: s.SenderID, Value: shareData})
	}

	sharesEncoded := frozt.EncodeMap(allShareEntries)
	signature, err := frozt.SignAggregate(signingPackage, sharesEncoded, pubKeyPackage, alpha)
	if err != nil {
		return nil, fmt.Errorf("sign aggregate: %w", err)
	}

	sigMsg := base64.StdEncoding.EncodeToString(signature)
	err = client.SendMessage(ctx, sessionID, resultPhase, relay.Message{
		SessionID: sessionID,
		From:      partyID,
		To:        OtherParties(signerParties, partyID),
		Body:      sigMsg,
	})
	if err != nil {
		return nil, fmt.Errorf("broadcast signature: %w", err)
	}

	return &SpendSignResult{Signature: signature}, nil
}

func runSpendSigner(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, identifier uint16, nonces frozt.NoncesHandle, keyPackage, sighash, alpha, commitmentsEncoded []byte, signerParties []string, packagePhase, sharePhase, resultPhase string) (*SpendSignResult, error) {
	coordinatorID := getCoordinatorPartyID(signerParties)

	var spMsg SigningPackageMessage
	err := WaitForMessage(ctx, client, sessionID, partyID, packagePhase, func(body string) error {
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

	err = client.SendMessage(ctx, sessionID, sharePhase, relay.Message{
		SessionID: sessionID,
		From:      partyID,
		To:        []string{coordinatorID},
		Body:      string(shareMsgBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("send share: %w", err)
	}

	var signature []byte
	err = WaitForMessage(ctx, client, sessionID, partyID, resultPhase, func(body string) error {
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

	return &SpendSignResult{Signature: signature}, nil
}
