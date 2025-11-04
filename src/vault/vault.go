package vault

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
)

// Client represents a Vault client for unsealing operations.
type Client struct {
	baseURLs []string
}

// NewClient creates a new Vault client with the given base URLs.
func NewClient(baseURLs []string) *Client {
	return &Client{baseURLs: baseURLs}
}

// CheckSealStatus checks if Vault is sealed by querying the first available URL.
func (c *Client) CheckSealStatus(baseURL string) (*SealStatus, error) {
	url := fmt.Sprintf("%s/v1/sys/seal-status", baseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logrus.Errorf("Failed to create request for %s: %v", url, err)
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("HTTP request failed for %s: %v", url, err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read response body from %s: %v", url, err)
		return nil, err
	}

	logrus.Debugf("Vault seal status response from %s: %s", url, string(body))

	if resp.StatusCode != http.StatusOK {
		logrus.Errorf("HTTP %d from %s: %s", resp.StatusCode, url, string(body))
		return nil, err
	}

	var status SealStatus
	if err := json.Unmarshal(body, &status); err != nil {
		logrus.Errorf("Failed to unmarshal response from %s: %v", url, err)
		return nil, err
	}

	return &status, nil

}

// Unseal attempts to unseal Vault with the given key by trying each URL.
func (c *Client) Unseal(baseURL string, key string) (*UnsealResponse, error) {
	body := map[string]string{"key": key}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal unseal request: %v", err)
	}
	url := fmt.Sprintf("%s/v1/sys/unseal", baseURL)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		logrus.Errorf("Failed to create unseal request for %s: %v", url, err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("HTTP unseal request failed for %s: %v", url, err)
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read unseal response from %s: %v", url, err)
		return nil, err
	}

	logrus.Debugf("Vault unseal response from %s: %s", url, string(respBody))

	if resp.StatusCode != http.StatusOK {
		logrus.Errorf("HTTP %d from %s: %s", resp.StatusCode, url, string(respBody))
		return nil, err
	}

	var unsealResp UnsealResponse
	if err := json.Unmarshal(respBody, &unsealResp); err != nil {
		logrus.Errorf("Failed to unmarshal unseal response from %s: %v", url, err)
		return nil, err
	}
	return &unsealResp, nil
}

// Run performs the auto-unsealing process for all configured Vault instances using the provided unseal keys.
func (c *Client) Run(unsealKeys []string) {
	for _, baseURL := range c.baseURLs {
		logrus.Infof("Checking seal status for Vault at %s", baseURL)
		for {
			resp, err := c.CheckSealStatus(baseURL)
			if err != nil {
				logrus.Errorf("Failed to check seal status for %s: %v", baseURL, err)
				break
			}
			if !resp.Sealed {
				logrus.Infof("Vault at %s is already unsealed", baseURL)
				break
			} else {
				logrus.Infof("Vault at %s is sealed, attempting to unseal", baseURL)
				for _, unsealKey := range unsealKeys {
					logrus.Infof("Attempting to unseal Vault at %s with key", baseURL)
					_, err := c.Unseal(baseURL, unsealKey)
					if err != nil {
						logrus.Errorf("Failed to unseal Vault at %s: %v", baseURL, err)
					} else {
						logrus.Infof("Successfully sent unseal key to Vault at %s", baseURL)
					}
				}
			}
		}
	}
}
