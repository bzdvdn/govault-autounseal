package config

import (
	"fmt"

	storePkg "govault-autounseal/src/internal/store"

	"github.com/spf13/viper"
)

// Config holds the application configuration loaded from YAML file.
type Config struct {
	WaitInterval  int          `yaml:"wait_interval" mapstructure:"wait_interval"`
	EncryptedKeys string       `yaml:"encrypted_keys" mapstructure:"encrypted_keys"`
	Store         *StoreConfig `yaml:"store" mapstructure:"store"`
	KubeConfig    *KubeConfig  `yaml:"kube_config,omitempty" mapstructure:"kube_config"`
	HTTPConfig    *HTTPConfig  `yaml:"http_config,omitempty" mapstructure:"http_config"`
	HTTPServer    *HTTPServer  `yaml:"http_server,omitempty" mapstructure:"http_server"`
}

// HTTPServer holds HTTP server configuration for health checks.
type HTTPServer struct {
	Port int `yaml:"port" mapstructure:"port"`
}

// KubeConfig holds Kubernetes-specific configuration for Vault unsealing.
type KubeConfig struct {
	VaultNamespace     string `yaml:"vault_namespace" mapstructure:"vault_namespace"`
	VaultLabelSelector string `yaml:"vault_label_selector" mapstructure:"vault_label_selector"`
	VaultPodPort       int    `yaml:"vault_pod_port" mapstructure:"vault_pod_port"`
	PodScanMaxCounter  int    `yaml:"pod_scan_max_counter" mapstructure:"pod_scan_max_counter"`
	PodScanDelay       int    `yaml:"pod_scan_delay" mapstructure:"pod_scan_delay"`
	SecretName         string `yaml:"secret_name" mapstructure:"secret_name"`
	SecretNamespace    string `yaml:"secret_namespace" mapstructure:"secret_namespace"`
}

// HTTPConfig holds HTTP-specific configuration for Vault unsealing.
type HTTPConfig struct {
	VaultURLs  []string `yaml:"vault_urls" mapstructure:"vault_urls"`
	SecretKey  string   `yaml:"secret_key" mapstructure:"secret_key"`
	SecretSalt string   `yaml:"secret_salt" mapstructure:"secret_salt"`
}

// LoadConfig loads and parses the configuration from YAML file or environment variables.
func LoadConfig(configPath string) (*Config, error) {
	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// StoreConfig holds configuration for secret store.
type StoreConfig struct {
	Type   string                 `yaml:"type" mapstructure:"type"`
	Config map[string]interface{} `yaml:"config,omitempty" mapstructure:"config"`
}

// CreateStore creates a store interface based on the configuration.
func (c *Config) CreateStore() (storePkg.SecretStoreInteface, error) {
	if c.Store == nil {
		return nil, fmt.Errorf("store configuration is required")
	}

	switch c.Store.Type {
	case "env":
		return storePkg.NewEnvStore()
	case "file":
		path, ok := c.Store.Config["path"].(string)
		if !ok {
			return nil, fmt.Errorf("file store requires 'path' configuration")
		}
		return storePkg.NewFileSecretStore(path)
	case "kube":
		secretName, ok := c.Store.Config["secret_name"].(string)
		if !ok {
			return nil, fmt.Errorf("kube store requires 'secret_name' configuration")
		}
		secretNamespace, ok := c.Store.Config["secret_namespace"].(string)
		if !ok {
			return nil, fmt.Errorf("kube store requires 'secret_namespace' configuration")
		}
		return storePkg.NewKubeStore(secretName, secretNamespace)
	default:
		return nil, fmt.Errorf("unknown store type: %s", c.Store.Type)
	}
}
