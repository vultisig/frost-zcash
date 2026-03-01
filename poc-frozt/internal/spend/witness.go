package spend

import (
	"context"
	"fmt"
	"log"

	frozt "github.com/vultisig/frozt-zcash/go-frozt"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/lightwalletd"
)

func BuildWitness(ctx context.Context, scanner *lightwalletd.Scanner, note *lightwalletd.FoundNote, chainTip uint64, partyID string) ([]byte, error) {
	treeState, err := scanner.GetTreeState(ctx, note.Height-1)
	if err != nil {
		return nil, fmt.Errorf("get tree state(%d): %w", note.Height-1, err)
	}

	treeHandle, err := frozt.SaplingTreeFromState([]byte(treeState.SaplingTree))
	if err != nil {
		return nil, fmt.Errorf("tree from state: %w", err)
	}
	defer treeHandle.Close()

	noteBlock, err := scanner.ScanBlock(ctx, note.Height)
	if err != nil {
		return nil, fmt.Errorf("scan block %d: %w", note.Height, err)
	}

	var witnessHandle frozt.WitnessHandle

	log.Printf("[%s] Block %d has %d transactions, looking for tx %x", partyID, note.Height, len(noteBlock.Vtx), note.TxHash)
	for txI, tx := range noteBlock.Vtx {
		log.Printf("[%s]   tx[%d] hash=%x outputs=%d", partyID, txI, tx.Hash, len(tx.Outputs))
		for outputIdx, output := range tx.Outputs {
			if len(output.Cmu) != 32 {
				continue
			}

			appendErr := frozt.SaplingTreeAppend(treeHandle, output.Cmu)
			if appendErr != nil {
				return nil, fmt.Errorf("tree append: %w", appendErr)
			}

			if matchesNote(tx.Hash, outputIdx, note) {
				witnessHandle, err = frozt.SaplingTreeWitness(treeHandle)
				if err != nil {
					return nil, fmt.Errorf("create witness: %w", err)
				}
			} else if witnessHandle != 0 {
				appendErr = frozt.SaplingWitnessAppend(witnessHandle, output.Cmu)
				if appendErr != nil {
					return nil, fmt.Errorf("witness append: %w", appendErr)
				}
			}
		}
	}

	if witnessHandle == 0 {
		return nil, fmt.Errorf("note not found in block %d", note.Height)
	}
	defer witnessHandle.Close()

	endHeight := chainTip
	if endHeight > note.Height+100 {
		endHeight = note.Height + 100
	}

	if note.Height+1 <= endHeight {
		log.Printf("[%s] Advancing witness from block %d to %d...", partyID, note.Height+1, endHeight)

		for h := note.Height + 1; h <= endHeight; h++ {
			block, blockErr := scanner.ScanBlock(ctx, h)
			if blockErr != nil {
				return nil, fmt.Errorf("scan block %d for witness: %w", h, blockErr)
			}

			for _, tx := range block.Vtx {
				for _, output := range tx.Outputs {
					if len(output.Cmu) != 32 {
						continue
					}
					appendErr := frozt.SaplingWitnessAppend(witnessHandle, output.Cmu)
					if appendErr != nil {
						return nil, fmt.Errorf("witness append at height %d: %w", h, appendErr)
					}
				}
			}

			if h%10_000 == 0 {
				log.Printf("[%s]   Witness at block %d / %d", partyID, h, endHeight)
			}
		}
	}

	witnessData, err := frozt.SaplingWitnessSerialize(witnessHandle)
	if err != nil {
		return nil, fmt.Errorf("serialize witness: %w", err)
	}

	return witnessData, nil
}

func matchesNote(txHash []byte, outputIndex int, note *lightwalletd.FoundNote) bool {
	if len(txHash) == 0 || len(note.TxHash) == 0 {
		return false
	}
	if outputIndex != note.Index {
		return false
	}
	if len(txHash) != len(note.TxHash) {
		return false
	}
	for i := range txHash {
		if txHash[i] != note.TxHash[i] {
			return false
		}
	}
	return true
}
