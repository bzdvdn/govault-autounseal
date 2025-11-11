package store

import (
	"context"
	"fmt"
	"govault-autounseal/src/pkg/utils"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type KubeStore struct {
	clientset       *kubernetes.Clientset
	config          *rest.Config
	secretName      string
	secretNamespace string
	secretData      *SecretData
}

func (k *KubeStore) SecretKey() string {
	return k.secretData.SecretKey
}

func (k *KubeStore) SecretSalt() string {
	return k.secretData.SecretSalt
}

func (k *KubeStore) Load() error {
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

	k.secretData = &SecretData{
		SecretKey:  string(secretKey),
		SecretSalt: string(secretSalt),
	}

	return nil
}

func NewKubeStore(secretName, secretNamespace string) (*KubeStore, error) {
	config, err := utils.LoadKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load kube config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}

	logrus.Info("Successfully created Kubernetes clientset")

	store := &KubeStore{
		clientset:       clientset,
		config:          config,
		secretName:      secretName,
		secretNamespace: secretNamespace,
	}

	if err := store.Load(); err != nil {
		return nil, err
	}

	return store, nil
}
