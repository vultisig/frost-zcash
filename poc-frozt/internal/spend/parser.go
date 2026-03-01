package spend

import (
	"encoding/binary"
)

type SaplingOutput struct {
	Cmu           []byte
	EphemeralKey  []byte
	EncCiphertext []byte
}

func ParseSaplingOutputsFromRawTx(rawTx []byte) []SaplingOutput {
	if len(rawTx) < 20 {
		return nil
	}

	offset := 0

	header := binary.LittleEndian.Uint32(rawTx[offset:])
	offset += 4
	if header != 0x80000005 {
		return nil
	}

	offset += 4 // nVersionGroupId
	offset += 4 // nConsensusBranchId
	offset += 4 // nLockTime
	offset += 4 // nExpiryHeight

	txInCount, bytesRead := readCompactSize(rawTx[offset:])
	offset += bytesRead
	for i := 0; i < int(txInCount); i++ {
		offset += 32
		offset += 4
		scriptLen, br := readCompactSize(rawTx[offset:])
		offset += br
		offset += int(scriptLen)
		offset += 4
	}

	txOutCount, bytesRead := readCompactSize(rawTx[offset:])
	offset += bytesRead
	for i := 0; i < int(txOutCount); i++ {
		offset += 8
		scriptLen, br := readCompactSize(rawTx[offset:])
		offset += br
		offset += int(scriptLen)
	}

	// v5 layout (ZIP 225): nSpendsSapling, spend descriptions, nOutputsSapling, output descriptions, valueBalance, anchor, proofs, sigs
	nSpendsSapling, bytesRead := readCompactSize(rawTx[offset:])
	offset += bytesRead

	// v5 spend descriptions: cv(32) + nullifier(32) + rk(32) = 96 each (inline, before nOutputsSapling)
	offset += int(nSpendsSapling) * 96

	nOutputsSapling, bytesRead := readCompactSize(rawTx[offset:])
	offset += bytesRead

	var outputs []SaplingOutput
	for i := 0; i < int(nOutputsSapling); i++ {
		if offset+756 > len(rawTx) {
			break
		}
		cmu := make([]byte, 32)
		copy(cmu, rawTx[offset+32:offset+64])
		epk := make([]byte, 32)
		copy(epk, rawTx[offset+64:offset+96])
		encCt := make([]byte, 580)
		copy(encCt, rawTx[offset+96:offset+676])

		outputs = append(outputs, SaplingOutput{
			Cmu:           cmu,
			EphemeralKey:  epk,
			EncCiphertext: encCt,
		})

		offset += 756
	}

	return outputs
}

func readCompactSize(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	first := data[0]
	if first < 253 {
		return uint64(first), 1
	}
	if first == 253 {
		return uint64(binary.LittleEndian.Uint16(data[1:3])), 3
	}
	if first == 254 {
		return uint64(binary.LittleEndian.Uint32(data[1:5])), 5
	}
	return binary.LittleEndian.Uint64(data[1:9]), 9
}
