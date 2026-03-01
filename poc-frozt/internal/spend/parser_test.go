package spend

import (
	"encoding/binary"
	"testing"
)

func TestReadCompactSize(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantVal  uint64
		wantRead int
	}{
		{"zero", []byte{0}, 0, 1},
		{"small", []byte{42}, 42, 1},
		{"max_single_byte", []byte{252}, 252, 1},
		{"two_byte", func() []byte {
			b := []byte{253, 0, 0}
			binary.LittleEndian.PutUint16(b[1:], 300)
			return b
		}(), 300, 3},
		{"four_byte", func() []byte {
			b := []byte{254, 0, 0, 0, 0}
			binary.LittleEndian.PutUint32(b[1:], 70000)
			return b
		}(), 70000, 5},
		{"eight_byte", func() []byte {
			b := []byte{255, 0, 0, 0, 0, 0, 0, 0, 0}
			binary.LittleEndian.PutUint64(b[1:], 1<<32+1)
			return b
		}(), 1<<32 + 1, 9},
		{"empty", []byte{}, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, n := readCompactSize(tt.data)
			if val != tt.wantVal {
				t.Errorf("readCompactSize value = %d, want %d", val, tt.wantVal)
			}
			if n != tt.wantRead {
				t.Errorf("readCompactSize bytes read = %d, want %d", n, tt.wantRead)
			}
		})
	}
}

func TestParseSaplingOutputs_TooShort(t *testing.T) {
	result := ParseSaplingOutputsFromRawTx([]byte{1, 2, 3})
	if result != nil {
		t.Fatal("expected nil for short input")
	}
}

func TestParseSaplingOutputs_BadHeader(t *testing.T) {
	data := make([]byte, 30)
	binary.LittleEndian.PutUint32(data[0:], 0x12345678)
	result := ParseSaplingOutputsFromRawTx(data)
	if result != nil {
		t.Fatal("expected nil for bad header")
	}
}

func TestParseSaplingOutputs_V5NoOutputs(t *testing.T) {
	var tx []byte

	appendU32 := func(v uint32) {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, v)
		tx = append(tx, b...)
	}

	appendU32(0x80000005) // header (v5)
	appendU32(0x26A7270A) // nVersionGroupId
	appendU32(0xC2D6D0B4) // nConsensusBranchId
	appendU32(0)          // nLockTime
	appendU32(2000100)    // nExpiryHeight

	tx = append(tx, 0) // txInCount = 0
	tx = append(tx, 0) // txOutCount = 0
	tx = append(tx, 0) // nSpendsSapling = 0
	tx = append(tx, 0) // nOutputsSapling = 0

	result := ParseSaplingOutputsFromRawTx(tx)
	if len(result) != 0 {
		t.Fatalf("expected 0 outputs, got %d", len(result))
	}
}

func TestParseSaplingOutputs_V5WithOutputs(t *testing.T) {
	var tx []byte

	appendU32 := func(v uint32) {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, v)
		tx = append(tx, b...)
	}

	appendU32(0x80000005) // header (v5)
	appendU32(0x26A7270A) // nVersionGroupId
	appendU32(0xC2D6D0B4) // nConsensusBranchId
	appendU32(0)          // nLockTime
	appendU32(2000100)    // nExpiryHeight

	tx = append(tx, 0) // txInCount = 0
	tx = append(tx, 0) // txOutCount = 0
	tx = append(tx, 1) // nSpendsSapling = 1
	tx = append(tx, make([]byte, 96)...) // 1 spend description (96 bytes)

	tx = append(tx, 2) // nOutputsSapling = 2

	for i := 0; i < 2; i++ {
		output := make([]byte, 756)
		// cv(32) + cmu(32) + ephemeral_key(32) + enc_ciphertext(580) + out_ciphertext(80) + proof(192)
		// = 948... wait, let me check the parser again

		// The parser reads: offset+32 = cmu, offset+64 = epk, offset+96 = encCt
		// So the first 32 bytes are cv, next 32 are cmu, next 32 are epk, next 580 are enc_ct
		// Total per output: 756 (32+32+32+580+80) -- wait the parser expects 756 total

		// Set recognizable cmu value
		output[32] = byte(i + 1) // first byte of cmu
		// Set recognizable epk value
		output[64] = byte(i + 10) // first byte of epk
		// Set recognizable enc_ct value
		output[96] = byte(i + 20) // first byte of enc_ciphertext

		tx = append(tx, output...)
	}

	result := ParseSaplingOutputsFromRawTx(tx)
	if len(result) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(result))
	}

	if result[0].Cmu[0] != 1 {
		t.Errorf("output 0 cmu[0] = %d, want 1", result[0].Cmu[0])
	}
	if result[0].EphemeralKey[0] != 10 {
		t.Errorf("output 0 epk[0] = %d, want 10", result[0].EphemeralKey[0])
	}
	if result[0].EncCiphertext[0] != 20 {
		t.Errorf("output 0 enc[0] = %d, want 20", result[0].EncCiphertext[0])
	}

	if result[1].Cmu[0] != 2 {
		t.Errorf("output 1 cmu[0] = %d, want 2", result[1].Cmu[0])
	}
}
