package store

import (
	"fmt"
	"os"
	"path/filepath"
)

type Keystore struct {
	Dir string
}

func NewKeystore(dir string) *Keystore {
	return &Keystore{Dir: dir}
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
	path := filepath.Join(dir, filename)
	return os.WriteFile(path, data, 0o600)
}

func (k *Keystore) readFile(sessionID, filename string) ([]byte, error) {
	path := filepath.Join(k.Dir, sessionID, filename)
	return os.ReadFile(path)
}
