package utils

import (
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// LoadKubeConfig loads Kubernetes configuration from in-cluster or external kubeconfig file.
func LoadKubeConfig() (*rest.Config, error) {
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
