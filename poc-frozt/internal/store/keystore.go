package store

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Keystore struct {
	Dir        string
	Passphrase string
}

func NewKeystore(dir string) *Keystore {
	return &Keystore{Dir: dir}
}

func NewKeystoreEncrypted(dir, passphrase string) *Keystore {
	return &Keystore{Dir: dir, Passphrase: passphrase}
}

func (k *Keystore) SaveKeyPackage(sessionID string, data []byte) error {
	return k.writeFile(sessionID, "key_package.bin", data)
}

func (k *Keystore) SavePubKeyPackage(sessionID string, data []byte) error {
	return k.writeFile(sessionID, "pub_key_package.bin", data)
}

func (k *Keystore) LoadKeyPackage(sessionID string) ([]byte, error) {
	return k.readFile(sessionID, "key_package.bin")
}

func (k *Keystore) LoadPubKeyPackage(sessionID string) ([]byte, error) {
	return k.readFile(sessionID, "pub_key_package.bin")
}

func (k *Keystore) SaveSaplingExtras(sessionID string, data []byte) error {
	return k.writeFile(sessionID, "sapling_extras.bin", data)
}

func (k *Keystore) LoadSaplingExtras(sessionID string) ([]byte, error) {
	return k.readFile(sessionID, "sapling_extras.bin")
}

type SpentNote struct {
	TxHash string `json:"tx_hash"`
	Index  int    `json:"index"`
	Height uint64 `json:"height"`
}

func (k *Keystore) MarkNoteSpent(sessionID string, txHash []byte, index int, height uint64) error {
	spent, _ := k.LoadSpentNotes(sessionID)
	spent = append(spent, SpentNote{
		TxHash: hex.EncodeToString(txHash),
		Index:  index,
		Height: height,
	})
	data, err := json.Marshal(spent)
	if err != nil {
		return fmt.Errorf("marshal spent notes: %w", err)
	}
	return k.writeFile(sessionID, "spent_notes.json", data)
}

func (k *Keystore) LoadSpentNotes(sessionID string) ([]SpentNote, error) {
	data, err := k.readFile(sessionID, "spent_notes.json")
	if err != nil {
		return nil, nil
	}
	var notes []SpentNote
	err = json.Unmarshal(data, &notes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal spent notes: %w", err)
	}
	return notes, nil
}

func (k *Keystore) IsNoteSpent(sessionID string, txHash []byte, index int) bool {
	spent, _ := k.LoadSpentNotes(sessionID)
	txHashHex := hex.EncodeToString(txHash)
	for _, s := range spent {
		if s.TxHash == txHashHex && s.Index == index {
			return true
		}
	}
	return false
}

func (k *Keystore) HasKeys(sessionID string) bool {
	kpPath := filepath.Join(k.Dir, sessionID, "key_package.bin")
	_, err := os.Stat(kpPath)
	return err == nil
}

func (k *Keystore) writeFile(sessionID, filename string, data []byte) error {
	dir := filepath.Join(k.Dir, sessionID)
	err := os.MkdirAll(dir, 0o700)
	if err != nil {
		return fmt.Errorf("create keystore dir: %w", err)
	}

	toWrite := data
	if k.Passphrase != "" {
		encrypted, encErr := encryptData(data, k.Passphrase)
		if encErr != nil {
			return fmt.Errorf("encrypt keystore file: %w", encErr)
		}
		toWrite = encrypted
	}

	path := filepath.Join(dir, filename)
	return os.WriteFile(path, toWrite, 0o600)
}

func (k *Keystore) readFile(sessionID, filename string) ([]byte, error) {
	path := filepath.Join(k.Dir, sessionID, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if k.Passphrase != "" {
		decrypted, decErr := decryptData(data, k.Passphrase)
		if decErr != nil {
			return nil, fmt.Errorf("decrypt keystore file: %w", decErr)
		}
		return decrypted, nil
	}

	return data, nil
}
