package workers

import (
	"encoding/json"
	store "govault-autounseal/src/internal/store"
	"govault-autounseal/src/internal/vault"
	"govault-autounseal/src/pkg/crypter"
	"log"
	"time"
)

// HTTPWorker handles Vault unsealing via HTTP API calls.
type HTTPWorker struct {
	client        *vault.Client
	waitInterval  int
	store         store.SecretStoreInteface
	encryptedKeys string
}

// NewHTTPWorker creates a new HTTPWorker instance for unsealing Vault via HTTP.
func NewHTTPWorker(
	vaultURLs []string,
	waitInterval int,
	store store.SecretStoreInteface,
) *HTTPWorker {
	return &HTTPWorker{
		client:       vault.NewClient(vaultURLs, "", nil),
		waitInterval: waitInterval,
		store:        store,
	}
}

// Start begins the HTTP worker's unsealing loop, continuously checking and unsealing Vault instances.
func (h *HTTPWorker) Start(encryptedKeys string) {
	h.encryptedKeys = encryptedKeys
	for {
		if err := h.store.Load(); err != nil {
			log.Printf("Failed to load store: %v", err)
			time.Sleep(time.Duration(h.waitInterval) * time.Second)
			continue
		}

		secretKey := h.store.SecretKey()
		secretSalt := h.store.SecretSalt()

		crypter := crypter.NewCrypter(secretSalt)
		decryptedKeys, err := crypter.Decrypt(h.encryptedKeys, secretKey)
		if err != nil {
			log.Printf("Failed to decrypt keys: %v", err)
			time.Sleep(time.Duration(h.waitInterval) * time.Second)
			continue
		}

		var encryptKeys vault.EncryptedData
		if err := encryptKeys.Unmarshal([]byte(decryptedKeys)); err != nil {
			// Try to unmarshal as old format (array of strings)
			var unsealKeys []string
			if err2 := json.Unmarshal([]byte(decryptedKeys), &unsealKeys); err2 != nil {
				log.Printf("Failed to parse decrypted keys: %v", err)
				time.Sleep(time.Duration(h.waitInterval) * time.Second)
				continue
			}
			encryptKeys.Keys = unsealKeys
		}

		h.client.Run(encryptKeys.Keys)
		time.Sleep(time.Duration(h.waitInterval) * time.Second)
	}
}
