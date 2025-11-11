package config

import (
	"github.com/spf13/viper"
)

// Config holds the application configuration loaded from YAML file.
type Config struct {
	WaitInterval  int         `yaml:"wait_interval" mapstructure:"wait_interval"`
	EncryptedKeys string      `yaml:"encrypted_keys" mapstructure:"encrypted_keys"`
	KubeConfig    *KubeConfig `yaml:"kube_config,omitempty" mapstructure:"kube_config"`
	HTTPConfig    *HTTPConfig `yaml:"http_config,omitempty" mapstructure:"http_config"`
	HTTPServer    *HTTPServer `yaml:"http_server,omitempty" mapstructure:"http_server"`
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
