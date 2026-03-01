package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
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

	polls := 0
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, pollErr := c.GetBarrier(ctx, sessionID, phase, count)
		if pollErr != nil {
			return nil, fmt.Errorf("get barrier: %w", pollErr)
		}

		if len(resp.ReadyParties) >= expectedParties {
			return resp.ReadyParties, nil
		}

		polls++
		if polls%c.BarrierRepostCount == 0 {
			_, _ = c.PostBarrier(ctx, sessionID, req)
		}

		time.Sleep(c.BarrierPollInterval)
	}
}

func (c *RelayClient) GetBarrier(ctx context.Context, sessionID, phase string, count int) (*BarrierResponse, error) {
	reqURL := fmt.Sprintf("%s/barrier/%s?phase=%s&count=%d", c.BaseURL, url.PathEscape(sessionID), url.QueryEscape(phase), count)

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
