package relay

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
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

type RelayClient struct {
	BaseURL             string
	HTTPClient          *http.Client
	EncryptionKeyHex    string
	PartyID             string
	MessagePollInterval time.Duration
	BarrierPollInterval time.Duration
	BarrierRepostCount  int

	seqCounter atomic.Uint64
	seenSeqs   map[string]map[uint64]bool
	seenMu     sync.Mutex
}

func NewRelayClient(baseURL string) *RelayClient {
	return &RelayClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		MessagePollInterval: 50 * time.Millisecond,
		BarrierPollInterval: 100 * time.Millisecond,
		BarrierRepostCount:  10,
	}
}

func NewRelayClientWithEncryption(baseURL, encryptionKeyHex string) *RelayClient {
	return &RelayClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		EncryptionKeyHex:    encryptionKeyHex,
		MessagePollInterval: 50 * time.Millisecond,
		BarrierPollInterval: 100 * time.Millisecond,
		BarrierRepostCount:  10,
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
	msg.SequenceNo = c.seqCounter.Add(1)

	if c.EncryptionKeyHex != "" {
		keyBytes, _ := hex.DecodeString(c.EncryptionKeyHex)
		mac := hmac.New(sha256.New, keyBytes)
		mac.Write([]byte(msg.Body))
		msg.Hash = hex.EncodeToString(mac.Sum(nil))
	} else {
		hash := sha256.Sum256([]byte(msg.Body))
		msg.Hash = hex.EncodeToString(hash[:])
	}

	if c.EncryptionKeyHex != "" {
		encrypted, encErr := Encrypt(msg.Body, c.EncryptionKeyHex)
		if encErr != nil {
			return fmt.Errorf("encrypt message: %w", encErr)
		}
		msg.Body = encrypted
	}

	body, err := json.Marshal(msg)
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
	c.setAuthHeader(req, sessionID, c.PartyID)

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
	c.setAuthHeader(req, sessionID, c.PartyID)

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

func (c *RelayClient) setAuthHeader(req *http.Request, sessionID, partyID string) {
	if c.EncryptionKeyHex == "" {
		return
	}
	keyBytes, err := hex.DecodeString(c.EncryptionKeyHex)
	if err != nil {
		return
	}
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write([]byte(sessionID + ":" + partyID))
	token := hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Session-Token", token)
	req.Header.Set("X-Party-ID", partyID)
}

func (c *RelayClient) DecryptBody(body string) (string, error) {
	if c.EncryptionKeyHex == "" {
		return body, nil
	}
	return Decrypt(body, c.EncryptionKeyHex)
}

func (c *RelayClient) DecryptAndVerify(msg Message) (string, error) {
	plaintext, err := c.DecryptBody(msg.Body)
	if err != nil {
		return "", err
	}

	if msg.Hash != "" {
		var expected string
		if c.EncryptionKeyHex != "" {
			keyBytes, _ := hex.DecodeString(c.EncryptionKeyHex)
			mac := hmac.New(sha256.New, keyBytes)
			mac.Write([]byte(plaintext))
			expected = hex.EncodeToString(mac.Sum(nil))
		} else {
			hash := sha256.Sum256([]byte(plaintext))
			expected = hex.EncodeToString(hash[:])
		}
		if expected != msg.Hash {
			return "", fmt.Errorf("message hash mismatch: relay may have tampered with body")
		}
	}

	if msg.SequenceNo > 0 {
		key := msg.SessionID + ":" + msg.From
		c.seenMu.Lock()
		if c.seenSeqs == nil {
			c.seenSeqs = make(map[string]map[uint64]bool)
		}
		seqs, ok := c.seenSeqs[key]
		if !ok {
			seqs = make(map[uint64]bool)
			c.seenSeqs[key] = seqs
		}
		if seqs[msg.SequenceNo] {
			c.seenMu.Unlock()
			return "", fmt.Errorf("replay detected: duplicate sequence %d from %s", msg.SequenceNo, msg.From)
		}
		seqs[msg.SequenceNo] = true
		c.seenMu.Unlock()
	}

	return plaintext, nil
}
