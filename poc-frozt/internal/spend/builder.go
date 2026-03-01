package spend

import (
	"context"
	"fmt"
	"log"
	"sort"

	frozt "github.com/vultisig/frozt-zcash/go-frozt"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/lightwalletd"
)

const BaseFee = uint64(5_000)
const GraceActions = uint64(2)

func ComputeFee(nSpends, nOutputs int) uint64 {
	logicalActions := uint64(nSpends)
	if uint64(nOutputs) > logicalActions {
		logicalActions = uint64(nOutputs)
	}
	actions := GraceActions
	if logicalActions > actions {
		actions = logicalActions
	}
	return actions * BaseFee
}

type PrepareConfig struct {
	LightwalletdEndpoint string
	RecipientAddress     string
	SendAmount           uint64
	Birthday             uint64
	PartyID              string
}

type Preparation struct {
	Sighash       []byte
	Alphas        [][]byte
	Builder       frozt.TxBuilderHandle
	SelectedNotes []*lightwalletd.FoundNote
}

func PrepareTransaction(ctx context.Context, cfg PrepareConfig, pubKeyPackage, saplingExtras []byte) (*Preparation, error) {
	if cfg.LightwalletdEndpoint == "" {
		return nil, fmt.Errorf("LIGHTWALLETD_ENDPOINT is required for spend")
	}
	if cfg.RecipientAddress == "" {
		return nil, fmt.Errorf("RECIPIENT_ADDRESS is required for spend")
	}
	if cfg.SendAmount == 0 {
		return nil, fmt.Errorf("SEND_AMOUNT is required for spend")
	}

	keys, err := frozt.SaplingDeriveKeys(pubKeyPackage, saplingExtras)
	if err != nil {
		return nil, fmt.Errorf("derive keys: %w", err)
	}

	scanner, err := lightwalletd.NewScanner(cfg.LightwalletdEndpoint)
	if err != nil {
		return nil, fmt.Errorf("create scanner: %w", err)
	}
	defer scanner.Close()

	latestHeight, err := scanner.GetLatestBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("get latest block: %w", err)
	}

	startHeight := cfg.Birthday
	if startHeight == 0 {
		startHeight = latestHeight - 100_000
	}

	log.Printf("[%s] Scanning blocks %d to %d for notes...", cfg.PartyID, startHeight, latestHeight)

	initialTreeSize := uint64(0)
	if startHeight > 0 {
		initialTreeSize, err = scanner.GetSaplingTreeSize(ctx, startHeight-1)
		if err != nil {
			return nil, fmt.Errorf("get initial tree size: %w", err)
		}
	}

	scanResult, err := scanner.Scan(ctx, keys.Ivk, startHeight, latestHeight, initialTreeSize, func(height, total uint64) {
		log.Printf("[%s]   Scanned %d / %d blocks...", cfg.PartyID, height, total)
	})
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	if len(scanResult.Notes) == 0 {
		return nil, fmt.Errorf("no spendable notes found")
	}

	log.Printf("[%s] Found %d notes, total value: %d zatoshis", cfg.PartyID, len(scanResult.Notes), scanResult.TotalValue)

	var unspent []lightwalletd.FoundNote
	for _, note := range scanResult.Notes {
		noteData, decErr := DecryptFullNote(ctx, scanner, keys.Ivk, &note)
		if decErr != nil {
			log.Printf("[%s] Warning: could not decrypt full note at height %d: %v", cfg.PartyID, note.Height, decErr)
			continue
		}

		nf, nfErr := frozt.SaplingComputeNullifier(pubKeyPackage, saplingExtras, noteData, note.Position, note.Height)
		if nfErr != nil {
			log.Printf("[%s] Warning: could not compute nullifier for note at height %d: %v", cfg.PartyID, note.Height, nfErr)
			continue
		}

		var nfKey [32]byte
		copy(nfKey[:], nf)
		_, spent := scanResult.SpentNullifiers[nfKey]
		if !spent {
			unspent = append(unspent, note)
		}
	}
	filtered := len(scanResult.Notes) - len(unspent)
	if filtered > 0 {
		log.Printf("[%s] Filtered %d spent notes via on-chain nullifiers, %d remain", cfg.PartyID, filtered, len(unspent))
	}
	scanResult.Notes = unspent

	selectedNotes := selectNotes(scanResult.Notes, cfg.SendAmount)
	if selectedNotes == nil {
		return nil, fmt.Errorf("insufficient funds: need %d, have %d", cfg.SendAmount, scanResult.TotalValue)
	}

	var totalInput uint64
	for _, n := range selectedNotes {
		totalInput += n.Value
	}

	fee := ComputeFee(len(selectedNotes), 2)
	if totalInput < cfg.SendAmount+fee {
		return nil, fmt.Errorf("insufficient funds after fee: need %d + %d fee, have %d", cfg.SendAmount, fee, totalInput)
	}
	changeAmount := totalInput - cfg.SendAmount - fee

	log.Printf("[%s] Selected %d notes, total input: %d, send: %d, change: %d, fee: %d",
		cfg.PartyID, len(selectedNotes), totalInput, cfg.SendAmount, changeAmount, fee)

	targetHeight := uint32(latestHeight + 1)

	builder, err := frozt.TxBuilderNew(pubKeyPackage, saplingExtras, targetHeight)
	if err != nil {
		return nil, fmt.Errorf("tx builder new: %w", err)
	}

	alphas := make([][]byte, 0, len(selectedNotes))

	for i, note := range selectedNotes {
		log.Printf("[%s] Adding spend %d: height=%d, value=%d, txhash=%x, index=%d",
			cfg.PartyID, i, note.Height, note.Value, note.TxHash, note.Index)

		noteData, decryptErr := DecryptFullNote(ctx, scanner, keys.Ivk, note)
		if decryptErr != nil {
			builder.Close()
			return nil, fmt.Errorf("decrypt full note %d: %w", i, decryptErr)
		}

		witnessData, witErr := BuildWitness(ctx, scanner, note, latestHeight, cfg.PartyID)
		if witErr != nil {
			builder.Close()
			return nil, fmt.Errorf("build witness %d: %w", i, witErr)
		}

		alpha, addErr := frozt.TxBuilderAddSpend(builder, noteData, witnessData)
		if addErr != nil {
			builder.Close()
			return nil, fmt.Errorf("add spend %d: %w", i, addErr)
		}
		alphas = append(alphas, alpha)
	}

	err = frozt.TxBuilderAddOutput(builder, cfg.RecipientAddress, cfg.SendAmount)
	if err != nil {
		builder.Close()
		return nil, fmt.Errorf("add recipient output: %w", err)
	}

	if changeAmount > 0 {
		err = frozt.TxBuilderAddOutput(builder, keys.Address, changeAmount)
		if err != nil {
			builder.Close()
			return nil, fmt.Errorf("add change output: %w", err)
		}
	}

	sighash, err := frozt.TxBuilderBuild(builder)
	if err != nil {
		builder.Close()
		return nil, fmt.Errorf("tx builder build: %w", err)
	}

	log.Printf("[%s] Transaction built with %d spends, sighash: %x", cfg.PartyID, len(selectedNotes), sighash)

	return &Preparation{
		Sighash:       sighash,
		Alphas:        alphas,
		Builder:       builder,
		SelectedNotes: selectedNotes,
	}, nil
}

func selectNotes(notes []lightwalletd.FoundNote, targetAmount uint64) []*lightwalletd.FoundNote {
	sort.Slice(notes, func(i, j int) bool {
		return notes[i].Value > notes[j].Value
	})

	for i := range notes {
		fee := ComputeFee(1, 2)
		if notes[i].Value >= targetAmount+fee {
			return []*lightwalletd.FoundNote{&notes[i]}
		}
	}

	sort.Slice(notes, func(i, j int) bool {
		return notes[i].Value < notes[j].Value
	})

	var selected []*lightwalletd.FoundNote
	var total uint64
	for i := range notes {
		selected = append(selected, &notes[i])
		total += notes[i].Value
		fee := ComputeFee(len(selected), 2)
		if total >= targetAmount+fee {
			return selected
		}
	}

	return nil
}
