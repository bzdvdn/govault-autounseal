package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"govault-autounseal/src/crypter"
	"govault-autounseal/src/workers"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Config struct {
	WaitInterval int         `yaml:"wait_interval" mapstructure:"wait_interval"`
	SecretKey    string      `yaml:"secret_key" mapstructure:"secret_key"`
	SecretSalt   string      `yaml:"secret_salt" mapstructure:"secret_salt"`
	KubeConfig   *KubeConfig `yaml:"kube_config,omitempty" mapstructure:"kube_config"`
	HTTPConfig   *HTTPConfig `yaml:"http_config,omitempty" mapstructure:"http_config"`
}

type KubeConfig struct {
	VaultNamespace     string `yaml:"vault_namespace" mapstructure:"vault_namespace"`
	VaultLabelSelector string `yaml:"vault_label_selector" mapstructure:"vault_label_selector"`
	PodScanMaxCounter  int    `yaml:"pod_scan_max_counter" mapstructure:"pod_scan_max_counter"`
	PodScanDelay       int    `yaml:"pod_scan_delay" mapstructure:"pod_scan_delay"`
	SecretName         string `yaml:"secret_name" mapstructure:"secret_name"`
	SecretNamespace    string `yaml:"secret_namespace" mapstructure:"secret_namespace"`
}

type HTTPConfig struct {
	VaultURLs []string `yaml:"vault_urls" mapstructure:"vault_urls"`
	Username  *string  `yaml:"username,omitempty" mapstructure:"username"`
	Password  *string  `yaml:"password,omitempty" mapstructure:"password"`
}

func loadConfig(configPath string) (*Config, error) {
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

var rootCmd = &cobra.Command{
	Use:   "govault-autounseal",
	Short: "Vault autounseal tool in Go",
}

var createSecretDataCmd = &cobra.Command{
	Use:   "create_secret_data",
	Short: "Create encrypted secret data from Vault keys",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		base64VaultJsonKeys := args[0]
		configPath, _ := cmd.Flags().GetString("config")

		config, err := loadConfig(configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}

		data, err := base64.StdEncoding.DecodeString(base64VaultJsonKeys)
		if err != nil {
			log.Fatalf("Failed to decode base64: %v", err)
		}

		var vaultData map[string]interface{}
		if err := json.Unmarshal(data, &vaultData); err != nil {
			log.Fatalf("Failed to parse JSON: %v", err)
		}

		keys, ok := vaultData["unseal_keys_b64"].([]interface{})
		if !ok {
			log.Fatalf("Invalid keys format")
		}

		keysStr := make([]string, len(keys))
		for i, k := range keys {
			keysStr[i] = k.(string)
		}

		keysJson, _ := json.Marshal(keysStr)
		crypter := crypter.NewCrypter(config.SecretSalt)
		encrypted, err := crypter.Encrypt(string(keysJson), config.SecretKey)
		if err != nil {
			log.Fatalf("Failed to encrypt: %v", err)
		}
		fmt.Println(encrypted)
	},
}

var decryptSecretDataCmd = &cobra.Command{
	Use:   "decrypt_secret_data",
	Short: "Decrypt secret data",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		configPath, _ := cmd.Flags().GetString("config")

		config, err := loadConfig(configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		crypter := crypter.NewCrypter(config.SecretSalt)
		decrypted, err := crypter.Decrypt(key, config.SecretKey)
		if err != nil {
			log.Fatalf("Failed to decrypt: %v", err)
		}
		fmt.Println(decrypted)
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the autounseal service",
	Run: func(cmd *cobra.Command, args []string) {
		configPath, _ := cmd.Flags().GetString("config")
		encryptedKeys, _ := cmd.Flags().GetString("encrypted-keys")

		config, err := loadConfig(configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}

		crypter := crypter.NewCrypter(config.SecretSalt)
		decryptedKeys, err := crypter.Decrypt(encryptedKeys, config.SecretKey)
		if err != nil {
			log.Fatalf("Failed to decrypt keys: %v", err)
		}

		var unsealKeys []string
		if err := json.Unmarshal([]byte(decryptedKeys), &unsealKeys); err != nil {
			log.Fatalf("Failed to parse decrypted keys: %v", err)
		}

		if config.KubeConfig != nil {
			worker := workers.NewKubernetesWorker(
				config.KubeConfig.VaultNamespace,
				unsealKeys,
				config.KubeConfig.VaultLabelSelector,
				config.KubeConfig.PodScanMaxCounter,
				config.KubeConfig.PodScanDelay,
				config.WaitInterval,
				config.KubeConfig.SecretName,
				config.KubeConfig.SecretNamespace,
				crypter,
			)
			worker.Start()
		} else if config.HTTPConfig != nil {
			worker := workers.NewHTTPWorker(
				config.HTTPConfig.VaultURLs,
				config.HTTPConfig.Username,
				config.HTTPConfig.Password,
				unsealKeys,
				config.WaitInterval,
			)
			worker.Start()
		} else {
			log.Fatalf("No worker configuration found")
		}
	},
}

func init() {
	rootCmd.AddCommand(createSecretDataCmd)
	rootCmd.AddCommand(decryptSecretDataCmd)
	rootCmd.AddCommand(startCmd)

	createSecretDataCmd.Flags().String("config", "", "Path to config file")
	decryptSecretDataCmd.Flags().String("config", "", "Path to config file")
	startCmd.Flags().String("config", "", "Path to config file")
	startCmd.Flags().String("encrypted-keys", "", "Encrypted unseal keys")
	startCmd.MarkFlagRequired("encrypted-keys")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
