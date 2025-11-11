package vault

import (
	"encoding/json"
)

// EncryptedData holds the encrypted secret data structure.
type EncryptedData struct {
	Keys []string `json:"keys"`
}

// Marshal serializes the EncryptedData to JSON bytes.
func (s *EncryptedData) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

// Unmarshal deserializes JSON bytes into EncryptedData.
func (s *EncryptedData) Unmarshal(data []byte) error {
	return json.Unmarshal(data, s)
}

// SealStatus represents the response from Vault's seal status endpoint.
type SealStatus struct {
	Type         string `json:"type"`
	Initialized  bool   `json:"initialized"`
	Sealed       bool   `json:"sealed"`
	T            int    `json:"t"`
	N            int    `json:"n"`
	Progress     int    `json:"progress"`
	Nonce        string `json:"nonce"`
	Version      string `json:"version"`
	Migration    bool   `json:"migration"`
	RecoverySeal bool   `json:"recovery_seal"`
	StorageType  string `json:"storage_type"`
	HAEnabled    bool   `json:"ha_enabled"`
	ActiveTime   string `json:"active_time"`
}

// UnsealResponse represents the response from Vault's unseal endpoint.
type UnsealResponse struct {
	Sealed   bool   `json:"sealed"`
	T        int    `json:"t"`
	N        int    `json:"n"`
	Progress int    `json:"progress"`
	Nonce    string `json:"nonce"`
	Version  string `json:"version"`
}
