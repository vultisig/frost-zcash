package orchestration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	barrierPollInterval = 100 * time.Millisecond
)

func (c *RelayClient) WaitForBarrier(ctx context.Context, sessionID, phase, partyID string, count, expectedParties int) ([]string, error) {
	req := BarrierRequest{
		Phase:   phase,
		Count:   count,
		PartyID: partyID,
	}

	_, err := c.PostBarrier(ctx, sessionID, req)
	if err != nil {
		return nil, fmt.Errorf("post barrier: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, err := c.GetBarrier(ctx, sessionID, phase, count)
		if err != nil {
			return nil, fmt.Errorf("get barrier: %w", err)
		}

		if len(resp.ReadyParties) >= expectedParties {
			return resp.ReadyParties, nil
		}

		time.Sleep(barrierPollInterval)
	}
}

func (c *RelayClient) GetBarrier(ctx context.Context, sessionID, phase string, count int) (*BarrierResponse, error) {
	reqURL := fmt.Sprintf("%s/barrier/%s?phase=%s&count=%d", c.BaseURL, sessionID, phase, count)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("get barrier: status %d", resp.StatusCode)
	}

	var result BarrierResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
