package spend

import (
	"context"
	"fmt"

	frozt "github.com/vultisig/frozt-zcash/go-frozt"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/lightwalletd"
)

func DecryptFullNote(ctx context.Context, scanner *lightwalletd.Scanner, ivk []byte, note *lightwalletd.FoundNote) ([]byte, error) {
	rawTx, _, err := scanner.GetTransaction(ctx, note.TxHash)
	if err != nil {
		return nil, fmt.Errorf("get transaction: %w", err)
	}

	saplingOutputs := ParseSaplingOutputsFromRawTx(rawTx)
	if note.Index >= len(saplingOutputs) {
		return nil, fmt.Errorf("note index %d out of range (tx has %d outputs)", note.Index, len(saplingOutputs))
	}

	output := saplingOutputs[note.Index]

	noteData, err := frozt.SaplingDecryptNoteFull(ivk, output.Cmu, output.EphemeralKey, output.EncCiphertext, note.Height)
	if err != nil {
		return nil, fmt.Errorf("decrypt note full: %w", err)
	}

	return noteData, nil
}
