package workers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"govault-autounseal/src/crypter"
	"govault-autounseal/src/secrets"
	"govault-autounseal/src/vault"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
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
	secretName         string
	secretNamespace    string
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
	secretName string,
	secretNamespace string,
	EncryptedKeys string,
	vaultPodPort int,
) *KubernetesWorker {
	config, err := loadKubeConfig()
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
		secretName:         secretName,
		secretNamespace:    secretNamespace,
		EncryptedKeys:      EncryptedKeys,
		vaultPodPort:       vaultPodPort,
	}
}

// loadKubeConfig loads Kubernetes configuration from in-cluster or external kubeconfig file.
func loadKubeConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		logrus.Warnf("Failed to load in-cluster config: %v", err)
		kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
		logrus.Infof("Trying external kubeconfig: %s", kubeconfig)

		// Load the kubeconfig and get the current context
		clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
			&clientcmd.ConfigOverrides{},
		)

		rawConfig, err := clientConfig.RawConfig()
		if err != nil {
			logrus.Errorf("Failed to load raw kubeconfig: %v", err)
			return nil, err
		}

		currentContext := rawConfig.CurrentContext
		logrus.Infof("Current kubeconfig context: %s", currentContext)

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			logrus.Errorf("Failed to load external kubeconfig: %v", err)
			return nil, err
		}
		logrus.Info("Successfully loaded external kubeconfig")
	} else {
		logrus.Info("Successfully loaded in-cluster config")
	}
	return config, nil
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

// loadKeysFromSecret loads and decrypts the unseal keys from the configured Kubernetes secret.
func (k *KubernetesWorker) loadKeysFromSecret() error {
	secret, err := k.clientset.CoreV1().Secrets(k.secretNamespace).Get(context.TODO(), k.secretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get secret %s/%s: %v", k.secretNamespace, k.secretName, err)
	}

	secretKey, ok := secret.Data["secret-key"]
	if !ok {
		return fmt.Errorf("secret-key key not found in secret %s/%s", k.secretNamespace, k.secretName)
	}
	secretSalt, ok := secret.Data["secret-salt"]
	if !ok {
		return fmt.Errorf("secret-salt key not found in secret %s/%s", k.secretNamespace, k.secretName)
	}
	crypter := crypter.NewCrypter(string(secretSalt))
	decryptedKeys, err := crypter.Decrypt(k.EncryptedKeys, string(secretKey))
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
	// Load keys from secret on startup
	if err := k.loadKeysFromSecret(); err != nil {
		logrus.Fatalf("Failed to load keys from secret: %v", err)
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
