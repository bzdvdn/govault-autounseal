package secrets

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
