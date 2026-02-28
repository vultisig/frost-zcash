package orchestration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Message struct {
	SessionID  string   `json:"session_id,omitempty"`
	From       string   `json:"from,omitempty"`
	To         []string `json:"to,omitempty"`
	Body       string   `json:"body,omitempty"`
	Hash       string   `json:"hash"`
	SequenceNo uint64   `json:"sequence_no"`
}

type BarrierRequest struct {
	Phase   string `json:"phase"`
	Count   int    `json:"count"`
	PartyID string `json:"party_id"`
}

type BarrierResponse struct {
	Phase        string          `json:"phase"`
	Count        json.RawMessage `json:"count"`
	ReadyParties []string        `json:"ready_parties"`
}

// WARNING: Messages are not authenticated. A malicious relay or MITM can
// inject, modify, or drop messages. For production use, add message signing
// with each party's identity key and enforce TLS certificate verification.
type RelayClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewRelayClient(baseURL string) *RelayClient {
	return &RelayClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *RelayClient) JoinSession(ctx context.Context, sessionID string, parties []string) error {
	body, err := json.Marshal(parties)
	if err != nil {
		return fmt.Errorf("marshal parties: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/%s", c.BaseURL, url.PathEscape(sessionID)), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("join session: status %d", resp.StatusCode)
	}
	return nil
}

func (c *RelayClient) GetSessionParties(ctx context.Context, sessionID string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/%s", c.BaseURL, url.PathEscape(sessionID)), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("get session: status %d", resp.StatusCode)
	}

	var parties []string
	err = json.NewDecoder(resp.Body).Decode(&parties)
	if err != nil {
		return nil, err
	}
	return parties, nil
}

func (c *RelayClient) SendMessage(ctx context.Context, sessionID, messageID string, msg Message) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	hash := sha256.Sum256([]byte(msg.Body))
	msg.Hash = hex.EncodeToString(hash[:])

	body, err = json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/message/%s", c.BaseURL, url.PathEscape(sessionID)), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if messageID != "" {
		req.Header.Set("message_id", messageID)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("send message: status %d", resp.StatusCode)
	}
	return nil
}

func (c *RelayClient) GetMessages(ctx context.Context, sessionID, participantID, messageID string) ([]Message, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/message/%s/%s", c.BaseURL,
			url.PathEscape(sessionID), url.PathEscape(participantID)), nil)
	if err != nil {
		return nil, err
	}
	if messageID != "" {
		req.Header.Set("message_id", messageID)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get messages: status %d body=%s", resp.StatusCode, string(respBody))
	}

	var msgs []Message
	err = json.NewDecoder(resp.Body).Decode(&msgs)
	if err != nil {
		return nil, err
	}
	return msgs, nil
}

func (c *RelayClient) PostBarrier(ctx context.Context, sessionID string, req BarrierRequest) (*BarrierResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/barrier/%s", c.BaseURL, url.PathEscape(sessionID)), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("post barrier: status %d", resp.StatusCode)
	}

	var result BarrierResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *RelayClient) StartTSS(ctx context.Context, sessionID string, parties []string) error {
	body, err := json.Marshal(parties)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/start/%s", c.BaseURL, url.PathEscape(sessionID)), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("start tss: status %d", resp.StatusCode)
	}
	return nil
}

func (c *RelayClient) CompleteTSS(ctx context.Context, sessionID string, parties []string) error {
	body, err := json.Marshal(parties)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/complete/%s", c.BaseURL, url.PathEscape(sessionID)), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("complete tss: status %d", resp.StatusCode)
	}
	return nil
}
