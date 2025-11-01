package workers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

type HTTPWorker struct {
	vaultURLs    []string
	username     *string
	password     *string
	unsealKeys   []string
	waitInterval int
}

func NewHTTPWorker(
	vaultURLs []string,
	username *string,
	password *string,
	unsealKeys []string,
	waitInterval int,
) *HTTPWorker {
	return &HTTPWorker{
		vaultURLs:    vaultURLs,
		username:     username,
		password:     password,
		unsealKeys:   unsealKeys,
		waitInterval: waitInterval,
	}
}

func (h *HTTPWorker) checkVaultSealedStatus(url string) (bool, error) {
	req, err := http.NewRequest("GET", url+"/v1/sys/seal-status", nil)
	if err != nil {
		return false, err
	}

	if h.username != nil && h.password != nil {
		req.SetBasicAuth(*h.username, *h.password)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("Check vault sealed status failed for %s: %v", url, err)
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return false, err
	}

	sealed, ok := response["sealed"].(bool)
	if !ok {
		return false, fmt.Errorf("invalid response format")
	}

	return sealed, nil
}

func (h *HTTPWorker) unsealVault(url, unsealKey string) (map[string]interface{}, error) {
	body := map[string]string{"key": unsealKey}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url+"/v1/sys/unseal", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	if h.username != nil && h.password != nil {
		req.SetBasicAuth(*h.username, *h.password)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("Unseal vault failed for %s: %v", url, err)
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response map[string]interface{}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, err
	}

	return response, nil
}

func (h *HTTPWorker) Start() {
	for {
		for _, url := range h.vaultURLs {
			sealed, err := h.checkVaultSealedStatus(url)
			if err != nil {
				logrus.Error(err)
				continue
			}

			if sealed {
				for _, unsealKey := range h.unsealKeys {
					_, err := h.unsealVault(url, unsealKey)
					if err != nil {
						logrus.Error(err)
					}
				}
			}
		}

		time.Sleep(time.Duration(h.waitInterval) * time.Second)
	}
}
