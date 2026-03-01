package vault

import (
	"encoding/json"
	"os"
)

type VultShare struct {
	Version       int    `json:"version"`
	Chain         string `json:"chain"`
	Threshold     int    `json:"threshold"`
	TotalParties  int    `json:"total_parties"`
	PartyID       int    `json:"party_id"`
	Birthday      int    `json:"birthday"`
	ZAddress      string `json:"z_address"`
	KeyPackage    string `json:"key_package"`
	PubKeyPackage string `json:"pub_key_package"`
	SaplingExtras string `json:"sapling_extras"`
}

func ExportVultShare(path string, share VultShare) error {
	data, err := json.MarshalIndent(share, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func ImportVultShare(path string) (VultShare, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return VultShare{}, err
	}
	var share VultShare
	err = json.Unmarshal(data, &share)
	return share, err
}
