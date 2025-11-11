package worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"

	store "govault-autounseal/src/internal/store"
	storePkg "govault-autounseal/src/internal/store"
	"govault-autounseal/src/internal/vault"
	"govault-autounseal/src/pkg/crypter"
	"govault-autounseal/src/pkg/utils"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// KubernetesWorker handles Vault unsealing via direct pod IP connections.
type KubernetesWorker struct {
	clientset          *kubernetes.Clientset
	config             *rest.Config
	unsealKeys         []string
	vaultNamespace     string
	vaultLabelSelector string
	podScanMaxCounter  int
	podScanDelay       int
	waitInterval       int
	store              storePkg.SecretStoreInteface
	EncryptedKeys      string
	vaultPodPort       int
}

// NewKubernetesWorker creates a new KubernetesWorker instance for unsealing Vault via direct pod connections.
func NewKubernetesWorker(
	vaultNamespace string,
	vaultLabelSelector string,
	podScanMaxCounter int,
	podScanDelay int,
	waitInterval int,
	store store.SecretStoreInteface,
	EncryptedKeys string,
	vaultPodPort int,
) *KubernetesWorker {
	config, err := utils.LoadKubeConfig()
	if err != nil {
		logrus.Fatalf("Failed to load kube config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logrus.Fatalf("Failed to create clientset: %v", err)
	}
	logrus.Info("Successfully created Kubernetes clientset")

	return &KubernetesWorker{
		clientset:          clientset,
		config:             config,
		vaultNamespace:     vaultNamespace,
		vaultLabelSelector: vaultLabelSelector,
		podScanMaxCounter:  podScanMaxCounter,
		podScanDelay:       podScanDelay,
		waitInterval:       waitInterval,
		store:              store,
		EncryptedKeys:      EncryptedKeys,
		vaultPodPort:       vaultPodPort,
	}
}

// getVaultPodNames retrieves the list of Vault pod Names based on the configured label selector.
func (k *KubernetesWorker) getVaultPodNames() ([]string, error) {
	for counter := 1; counter <= k.podScanMaxCounter; counter++ {
		logrus.Debugf("Listing pods in namespace %s with label selector %s", k.vaultNamespace, k.vaultLabelSelector)
		podList, err := k.clientset.CoreV1().Pods(k.vaultNamespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: k.vaultLabelSelector,
		})
		if err != nil {
			logrus.Errorf("Failed to list pods: %v", err)
			return nil, err
		}
		logrus.Debugf("Found %d pods", len(podList.Items))

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

// loadKeysFromStore loads and decrypts the unseal keys from the configured store.
func (k *KubernetesWorker) loadKeysFromStore() error {
	if err := k.store.Load(); err != nil {
		return fmt.Errorf("failed to load store: %v", err)
	}

	secretKey := k.store.SecretKey()
	secretSalt := k.store.SecretSalt()

	crypter := crypter.NewCrypter(secretSalt)
	decryptedKeys, err := crypter.Decrypt(k.EncryptedKeys, secretKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt keys: %v", err)
	}

	var encryptKeys vault.EncryptedData
	if err := encryptKeys.Unmarshal([]byte(decryptedKeys)); err != nil {
		// Try to unmarshal as old format (array of strings)
		var unsealKeys []string
		if err2 := json.Unmarshal([]byte(decryptedKeys), &unsealKeys); err2 != nil {
			return fmt.Errorf("failed to parse decrypted keys: %v", err)
		}
		encryptKeys.Keys = unsealKeys
	}

	k.unsealKeys = encryptKeys.Keys
	return nil
}

func (k *KubernetesWorker) generateVaultURLS(podNames []string) []string {
	var vaultURLs []string
	for _, podName := range podNames {
		vaultURLs = append(vaultURLs, fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s/proxy", k.config.Host, k.vaultNamespace, podName))
	}
	return vaultURLs
}

func (k *KubernetesWorker) getTLSConfigFromKubeconfig() (*tls.Config, error) {
	if k.config.CertData != nil && k.config.KeyData != nil {
		cert, err := tls.X509KeyPair(k.config.CertData, k.config.KeyData)
		if err != nil {
			return nil, err
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		if k.config.CAData != nil {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(k.config.CAData)
			tlsConfig.RootCAs = caCertPool
		}

		return tlsConfig, nil
	}

	return &tls.Config{
		InsecureSkipVerify: true,
	}, nil
}

// Start begins the Kubernetes worker's unsealing loop, continuously checking and unsealing Vault pods.
func (k *KubernetesWorker) Start() {
	// Load keys from store on startup
	if err := k.loadKeysFromStore(); err != nil {
		logrus.Fatalf("Failed to load keys from store: %v", err)
	}

	for {
		podNames, err := k.getVaultPodNames()
		if err != nil {
			logrus.Error(err)
			time.Sleep(time.Duration(k.waitInterval) * time.Second)
			continue
		}
		vaultURLs := k.generateVaultURLS(podNames)

		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		tlsConfig, err := k.getTLSConfigFromKubeconfig()
		if err != nil {
			logrus.Errorf("error - %s", err)
		} else {
			httpClient.Transport = &http.Transport{
				TLSClientConfig: tlsConfig,
			}
		}

		vaultClient := vault.NewClient(vaultURLs, k.config.BearerToken, httpClient)
		vaultClient.Run(k.unsealKeys)
		time.Sleep(time.Duration(k.waitInterval) * time.Second)
	}
}
