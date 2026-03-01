package lightwalletd

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"

	frozt "github.com/vultisig/frozt-zcash/go-frozt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type FoundNote struct {
	Height   uint64
	TxHash   []byte
	Index    int
	Value    uint64
	Position uint64
}

type ScanResult struct {
	Notes           []FoundNote
	TotalValue      uint64
	BlocksScaned    uint64
	SpentNullifiers map[[32]byte]struct{}
}

type Scanner struct {
	conn   *grpc.ClientConn
	client CompactTxStreamerClient
}

func NewScanner(endpoint string) (*Scanner, error) {
	creds := credentials.NewTLS(&tls.Config{})
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("grpc dial %s: %w", endpoint, err)
	}

	client := NewCompactTxStreamerClient(conn)
	return &Scanner{conn: conn, client: client}, nil
}

func (s *Scanner) Close() error {
	return s.conn.Close()
}

func (s *Scanner) GetLatestBlock(ctx context.Context) (uint64, error) {
	block, err := s.client.GetLatestBlock(ctx, &ChainSpec{})
	if err != nil {
		return 0, err
	}
	return block.Height, nil
}

func (s *Scanner) GetLightdInfo(ctx context.Context) (*LightdInfo, error) {
	return s.client.GetLightdInfo(ctx, &Empty{})
}

func (s *Scanner) Scan(ctx context.Context, ivk []byte, startHeight, endHeight, initialTreeSize uint64, progressFn func(height, total uint64)) (*ScanResult, error) {
	stream, err := s.client.GetBlockRange(ctx, &BlockRange{
		Start: &BlockID{Height: startHeight},
		End:   &BlockID{Height: endHeight},
	})
	if err != nil {
		return nil, fmt.Errorf("GetBlockRange: %w", err)
	}

	result := &ScanResult{
		SpentNullifiers: make(map[[32]byte]struct{}),
	}
	totalBlocks := endHeight - startHeight + 1
	commitmentPos := initialTreeSize

	for {
		block, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			return nil, fmt.Errorf("recv block: %w", recvErr)
		}

		result.BlocksScaned++

		for _, tx := range block.Vtx {
			for _, spend := range tx.Spends {
				if len(spend.Nf) == 32 {
					var nf [32]byte
					copy(nf[:], spend.Nf)
					result.SpentNullifiers[nf] = struct{}{}
				}
			}

			for i, output := range tx.Outputs {
				if len(output.Cmu) != 32 {
					commitmentPos++
					continue
				}

				notePos := commitmentPos
				commitmentPos++

				if len(output.EphemeralKey) != 32 || len(output.Ciphertext) != 52 {
					continue
				}

				value, found, decErr := frozt.SaplingTryDecryptCompact(ivk, output.Cmu, output.EphemeralKey, output.Ciphertext, block.Height)
				if decErr != nil {
					return nil, fmt.Errorf("decrypt error at height %d: %w", block.Height, decErr)
				}
				if found {
					result.Notes = append(result.Notes, FoundNote{
						Height:   block.Height,
						TxHash:   tx.Hash,
						Index:    i,
						Value:    value,
						Position: notePos,
					})
					result.TotalValue += value
				}
			}
		}

		if progressFn != nil && result.BlocksScaned%10000 == 0 {
			progressFn(result.BlocksScaned, totalBlocks)
		}
	}

	return result, nil
}

func (s *Scanner) GetSaplingTreeSize(ctx context.Context, height uint64) (uint64, error) {
	state, err := s.GetTreeState(ctx, height)
	if err != nil {
		return 0, fmt.Errorf("get tree state(%d): %w", height, err)
	}

	size, err := frozt.SaplingTreeSize([]byte(state.SaplingTree))
	if err != nil {
		return 0, fmt.Errorf("sapling tree size: %w", err)
	}

	return size, nil
}

func (s *Scanner) ScanBlock(ctx context.Context, height uint64) (*CompactBlock, error) {
	block, err := s.client.GetBlock(ctx, &BlockID{Height: height})
	if err != nil {
		return nil, fmt.Errorf("GetBlock(%d): %w", height, err)
	}
	return block, nil
}

func (s *Scanner) GetTransaction(ctx context.Context, txHash []byte) ([]byte, uint64, error) {
	resp, err := s.client.GetTransaction(ctx, &TxFilter{Hash: txHash})
	if err != nil {
		return nil, 0, fmt.Errorf("GetTransaction: %w", err)
	}
	return resp.Data, resp.Height, nil
}

func (s *Scanner) GetTreeState(ctx context.Context, height uint64) (*TreeState, error) {
	resp, err := s.client.GetTreeState(ctx, &BlockID{Height: height})
	if err != nil {
		return nil, fmt.Errorf("GetTreeState(%d): %w", height, err)
	}
	return resp, nil
}

func (s *Scanner) SendTransaction(ctx context.Context, rawTx []byte) error {
	resp, err := s.client.SendTransaction(ctx, &RawTransaction{Data: rawTx})
	if err != nil {
		return fmt.Errorf("SendTransaction: %w", err)
	}
	if resp.ErrorCode != 0 {
		return fmt.Errorf("SendTransaction rejected: %s (code %d)", resp.ErrorMessage, resp.ErrorCode)
	}
	return nil
}
