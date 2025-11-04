package workers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"govault-autounseal/src/crypter"
	"govault-autounseal/src/secrets"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubernetesWorker handles Vault unsealing via Kubernetes API proxy calls.
type KubernetesWorker struct {
	clientset          *kubernetes.Clientset
	config             *rest.Config
	unsealKeys         []string
	vaultNamespace     string
	vaultLabelSelector string
	podScanMaxCounter  int
	podScanDelay       int
	waitInterval       int
	secretName         string
	secretNamespace    string
	crypter            *crypter.Crypter
	secretKey          string
}

// NewKubernetesWorker creates a new KubernetesWorker instance for unsealing Vault via Kubernetes API.
func NewKubernetesWorker(
	vaultNamespace string,
	vaultLabelSelector string,
	podScanMaxCounter int,
	podScanDelay int,
	waitInterval int,
	secretName string,
	secretNamespace string,
	crypter *crypter.Crypter,
	secretKey string,
) *KubernetesWorker {
	config, err := loadKubeConfig()
	if err != nil {
		logrus.Fatalf("Failed to load kube config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logrus.Fatalf("Failed to create clientset: %v", err)
	}

	return &KubernetesWorker{
		clientset:          clientset,
		config:             config,
		vaultNamespace:     vaultNamespace,
		vaultLabelSelector: vaultLabelSelector,
		podScanMaxCounter:  podScanMaxCounter,
		podScanDelay:       podScanDelay,
		waitInterval:       waitInterval,
		secretName:         secretName,
		secretNamespace:    secretNamespace,
		crypter:            crypter,
		secretKey:          secretKey,
	}
}

// loadKubeConfig loads Kubernetes configuration from in-cluster or external kubeconfig file.
func loadKubeConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}

// getVaultPods retrieves the list of Vault pod names based on the configured label selector.
func (k *KubernetesWorker) getVaultPods() ([]string, error) {
	for counter := 1; counter <= k.podScanMaxCounter; counter++ {
		podList, err := k.clientset.CoreV1().Pods(k.vaultNamespace).List(context.TODO(), v1.ListOptions{
			LabelSelector: k.vaultLabelSelector,
		})
		if err != nil {
			return nil, err
		}

		if len(podList.Items) == 0 {
			logrus.Errorf("No Vault pods found. Label Selector: %s", k.vaultLabelSelector)
			return nil, fmt.Errorf("no Vault pods found")
		}

		var podsWithoutIP []string
		for _, pod := range podList.Items {
			if pod.Status.PodIP == "" {
				podsWithoutIP = append(podsWithoutIP, pod.Name)
			}
		}

		if len(podsWithoutIP) > 0 {
			logrus.Warnf("Vault pods have no assigned IP address: %v", podsWithoutIP)
			time.Sleep(time.Duration(k.podScanDelay) * time.Second)
			continue
		}

		var podNames []string
		for _, pod := range podList.Items {
			podNames = append(podNames, pod.Name)
		}
		return podNames, nil
	}
	return nil, fmt.Errorf("max pod scan counter reached")
}

// generateURL generates the Kubernetes API proxy URL for accessing a pod's endpoint.
func (k *KubernetesWorker) generateURL(podName, endpoint string) string {
	return fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s/proxy%s",
		k.config.Host, k.vaultNamespace, podName, endpoint)
}

// checkVaultSealedStatus checks if the Vault pod is sealed.
func (k *KubernetesWorker) checkVaultSealedStatus(podName string) (bool, error) {
	url := k.generateURL(podName, "/v1/sys/seal-status")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("Check vault sealed status failed for %s: %v", podName, err)
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

// unsealVaultPod attempts to unseal the Vault pod with the provided key.
func (k *KubernetesWorker) unsealVaultPod(podName, unsealKey string) (map[string]interface{}, error) {
	url := k.generateURL(podName, "/v1/sys/unseal")
	body := map[string]string{"key": unsealKey}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("Unseal vault failed for %s: %v", podName, err)
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

// loadKeysFromSecret loads and decrypts the unseal keys from the configured Kubernetes secret.
func (k *KubernetesWorker) loadKeysFromSecret() error {
	secret, err := k.clientset.CoreV1().Secrets(k.secretNamespace).Get(context.TODO(), k.secretName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get secret %s/%s: %v", k.secretNamespace, k.secretName, err)
	}

	encryptedKeys, ok := secret.Data["encrypted-keys"]
	if !ok {
		return fmt.Errorf("encrypted-keys key not found in secret %s/%s", k.secretNamespace, k.secretName)
	}

	decryptedKeys, err := k.crypter.Decrypt(string(encryptedKeys), k.secretKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt keys: %v", err)
	}

	var secretData secrets.SecretData
	if err := secretData.Unmarshal([]byte(decryptedKeys)); err != nil {
		// Try to unmarshal as old format (array of strings)
		var unsealKeys []string
		if err2 := json.Unmarshal([]byte(decryptedKeys), &unsealKeys); err2 != nil {
			return fmt.Errorf("failed to parse decrypted keys: %v", err)
		}
		secretData.Keys = unsealKeys
	}

	k.unsealKeys = secretData.Keys
	return nil
}

// Start begins the Kubernetes worker's unsealing loop, continuously checking and unsealing Vault pods.
func (k *KubernetesWorker) Start() {
	// Load keys from secret on startup
	if err := k.loadKeysFromSecret(); err != nil {
		logrus.Fatalf("Failed to load keys from secret: %v", err)
	}

	for {
		podNames, err := k.getVaultPods()
		if err != nil {
			logrus.Error(err)
			time.Sleep(time.Duration(k.waitInterval) * time.Second)
			continue
		}

		for _, podName := range podNames {
			sealed, err := k.checkVaultSealedStatus(podName)
			if err != nil {
				logrus.Error(err)
				continue
			}

			if sealed {
				for _, unsealKey := range k.unsealKeys {
					_, err := k.unsealVaultPod(podName, unsealKey)
					if err != nil {
						logrus.Error(err)
					}
				}
			}
		}

		time.Sleep(time.Duration(k.waitInterval) * time.Second)
	}
}
