package spend

import (
	"testing"

	"github.com/vultisig/frozt-zcash/poc-frozt/internal/lightwalletd"
)

func TestComputeFee(t *testing.T) {
	tests := []struct {
		name     string
		nSpends  int
		nOutputs int
		want     uint64
	}{
		{"1 spend 1 output (grace)", 1, 1, GraceActions * BaseFee},
		{"1 spend 2 outputs (grace)", 1, 2, GraceActions * BaseFee},
		{"2 spends 2 outputs (grace)", 2, 2, GraceActions * BaseFee},
		{"3 spends 2 outputs", 3, 2, 3 * BaseFee},
		{"2 spends 5 outputs", 2, 5, 5 * BaseFee},
		{"10 spends 3 outputs", 10, 3, 10 * BaseFee},
		{"0 spends 0 outputs (grace)", 0, 0, GraceActions * BaseFee},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeFee(tt.nSpends, tt.nOutputs)
			if got != tt.want {
				t.Errorf("ComputeFee(%d, %d) = %d, want %d", tt.nSpends, tt.nOutputs, got, tt.want)
			}
		})
	}
}

func TestSelectNotes_SingleNoteEnough(t *testing.T) {
	notes := []lightwalletd.FoundNote{
		{Value: 100_000, Height: 100},
	}
	target := uint64(50_000)
	selected := selectNotes(notes, target)
	if selected == nil {
		t.Fatal("expected selected notes, got nil")
	}
	if len(selected) != 1 {
		t.Fatalf("expected 1 note, got %d", len(selected))
	}
	if selected[0].Value != 100_000 {
		t.Errorf("expected note value 100000, got %d", selected[0].Value)
	}
}

func TestSelectNotes_InsufficientFunds(t *testing.T) {
	notes := []lightwalletd.FoundNote{
		{Value: 1000, Height: 100},
		{Value: 2000, Height: 200},
	}
	target := uint64(1_000_000)
	selected := selectNotes(notes, target)
	if selected != nil {
		t.Fatal("expected nil for insufficient funds")
	}
}

func TestSelectNotes_MultipleNotesNeeded(t *testing.T) {
	notes := []lightwalletd.FoundNote{
		{Value: 8_000, Height: 100},
		{Value: 10_000, Height: 200},
	}
	target := uint64(5_000)
	selected := selectNotes(notes, target)
	if selected == nil {
		t.Fatal("expected selected notes")
	}
	if len(selected) < 2 {
		t.Fatalf("expected at least 2 notes, got %d", len(selected))
	}
	var total uint64
	for _, n := range selected {
		total += n.Value
	}
	fee := ComputeFee(len(selected), 2)
	if total < target+fee {
		t.Errorf("selected total %d < target %d + fee %d", total, target, fee)
	}
}

func TestSelectNotes_PrefersLargestSingle(t *testing.T) {
	notes := []lightwalletd.FoundNote{
		{Value: 1_000, Height: 100},
		{Value: 50_000, Height: 200},
		{Value: 2_000, Height: 300},
	}
	target := uint64(30_000)
	selected := selectNotes(notes, target)
	if selected == nil {
		t.Fatal("expected selected notes")
	}
	if len(selected) != 1 {
		t.Fatalf("expected 1 note (the large one), got %d", len(selected))
	}
	if selected[0].Value != 50_000 {
		t.Errorf("expected largest note (50000), got %d", selected[0].Value)
	}
}

func TestSelectNotes_EmptyNotes(t *testing.T) {
	selected := selectNotes(nil, 1000)
	if selected != nil {
		t.Fatal("expected nil for empty notes")
	}
}
