package secrets

import (
	"encoding/json"
)

// SecretData holds the encrypted secret data structure.
type SecretData struct {
	Keys []string `json:"keys"`
}

// Marshal serializes the SecretData to JSON bytes.
func (s *SecretData) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

// Unmarshal deserializes JSON bytes into SecretData.
func (s *SecretData) Unmarshal(data []byte) error {
	return json.Unmarshal(data, s)
}
