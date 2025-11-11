package workers

import (
	"govault-autounseal/src/internal/vault"

	"time"
)

// HTTPWorker handles Vault unsealing via HTTP API calls.
type HTTPWorker struct {
	client       *vault.Client
	waitInterval int
}

// NewHTTPWorker creates a new HTTPWorker instance for unsealing Vault via HTTP.
func NewHTTPWorker(
	vaultURLs []string,
	waitInterval int,
) *HTTPWorker {
	return &HTTPWorker{
		client:       vault.NewClient(vaultURLs, "", nil),
		waitInterval: waitInterval,
	}
}

// Start begins the HTTP worker's unsealing loop, continuously checking and unsealing Vault instances.
func (h *HTTPWorker) Start(unsealKeys []string) {
	for {
		h.client.Run(unsealKeys)
		time.Sleep(time.Duration(h.waitInterval) * time.Second)
	}
}
