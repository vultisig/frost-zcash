package party

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/vultisig/frozt-zcash/poc-frozt/internal/relay"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/store"
)

type Config struct {
	RelayURL              string
	PartyID               string
	Identifier            uint16
	SessionID             string
	Parties               []string
	MaxSigners            uint16
	MinSigners            uint16
	Operation             string
	KeystoreDir           string
	KeystorePassphrase    string
	SignMessage            string
	Signers               []string
	EncryptionKeyHex      string
	Mnemonic              string
	ExpectedAddress       string
	LightwalletdEndpoint  string
	RecipientAddress      string
	SendAmount            uint64
	Birthday              uint64
}

type Node struct {
	Config   Config
	Client   *relay.RelayClient
	Keystore *store.Keystore
}

func NewNode(cfg Config) *Node {
	var client *relay.RelayClient
	if cfg.EncryptionKeyHex != "" {
		client = relay.NewRelayClientWithEncryption(cfg.RelayURL, cfg.EncryptionKeyHex)
	} else {
		client = relay.NewRelayClient(cfg.RelayURL)
	}
	var ks *store.Keystore
	if cfg.KeystorePassphrase != "" {
		ks = store.NewKeystoreEncrypted(cfg.KeystoreDir, cfg.KeystorePassphrase)
	} else {
		ks = store.NewKeystore(cfg.KeystoreDir)
	}

	client.PartyID = cfg.PartyID

	return &Node{
		Config:   cfg,
		Client:   client,
		Keystore: ks,
	}
}

func (n *Node) Run(ctx context.Context) error {
	log.Printf("[%s] Starting node (identifier=%d, operation=%s)", n.Config.PartyID, n.Config.Identifier, n.Config.Operation)

	err := n.waitForRelay(ctx)
	if err != nil {
		return fmt.Errorf("wait for relay: %w", err)
	}

	err = n.Client.JoinSession(ctx, n.Config.SessionID, n.Config.Parties)
	if err != nil {
		return fmt.Errorf("join session: %w", err)
	}

	log.Printf("[%s] Joined session %s, waiting for all parties", n.Config.PartyID, n.Config.SessionID)

	err = n.waitForAllParties(ctx)
	if err != nil {
		return fmt.Errorf("wait for parties: %w", err)
	}

	log.Printf("[%s] All parties joined, running %s", n.Config.PartyID, n.Config.Operation)

	switch n.Config.Operation {
	case "keygen":
		return n.runKeygen(ctx)
	case "sign":
		return n.runSign(ctx)
	case "key-import":
		return n.runKeyImport(ctx)
	case "spend":
		return n.runSpend(ctx)
	default:
		return fmt.Errorf("unknown operation: %s", n.Config.Operation)
	}
}

func (n *Node) waitForRelay(ctx context.Context) error {
	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_, err := n.Client.GetSessionParties(ctx, "health-check")
		if err == nil {
			return nil
		}

		log.Printf("[%s] Waiting for relay... (%d/30)", n.Config.PartyID, i+1)
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("relay not available after 30 attempts")
}

func (n *Node) waitForAllParties(ctx context.Context) error {
	expected := len(n.Config.Parties)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		parties, err := n.Client.GetSessionParties(ctx, n.Config.SessionID)
		if err != nil {
			return err
		}

		if len(parties) >= expected {
			sort.Strings(parties)
			log.Printf("[%s] All %d parties joined: %s", n.Config.PartyID, len(parties), strings.Join(parties, ", "))
			return nil
		}

		time.Sleep(500 * time.Millisecond)
	}
}
