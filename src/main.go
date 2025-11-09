package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"govault-autounseal/src/crypter"
	"govault-autounseal/src/secrets"
	"govault-autounseal/src/workers"

	"github.com/spf13/cobra"
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
	PodScanMaxCounter  int    `yaml:"pod_scan_max_counter" mapstructure:"pod_scan_max_counter"`
	PodScanDelay       int    `yaml:"pod_scan_delay" mapstructure:"pod_scan_delay"`
	SecretName         string `yaml:"secret_name" mapstructure:"secret_name"`
	SecretNamespace    string `yaml:"secret_namespace" mapstructure:"secret_namespace"`
	VaultPodPort       int    `yaml:"vault_pod_port" mapstructure:"vault_pod_port"`
}

// HTTPConfig holds HTTP-specific configuration for Vault unsealing.
type HTTPConfig struct {
	VaultURLs  []string `yaml:"vault_urls" mapstructure:"vault_urls"`
	Username   *string  `yaml:"username,omitempty" mapstructure:"username"`
	Password   *string  `yaml:"password,omitempty" mapstructure:"password"`
	SecretKey  string   `yaml:"secret_key" mapstructure:"secret_key"`
	SecretSalt string   `yaml:"secret_salt" mapstructure:"secret_salt"`
}

// loadConfig loads and parses the configuration from YAML file or environment variables.
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

// createSecretDataCmd is the command for creating encrypted secret data from Vault keys.
var createSecretDataCmd = &cobra.Command{
	Use:   "create_secret_data",
	Short: "Create encrypted secret data from Vault keys",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		base64VaultJsonKeys := args[0]
		secretKey, _ := cmd.Flags().GetString("secret-key")
		secretSalt, _ := cmd.Flags().GetString("secret-salt")

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

		secretData := secrets.SecretData{Keys: keysStr}
		keysJson, err := secretData.Marshal()
		if err != nil {
			log.Fatalf("Failed to marshal data: %v", err)
		}
		crypter := crypter.NewCrypter(secretSalt)
		encrypted, err := crypter.Encrypt(string(keysJson), secretKey)
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
		secretKey, _ := cmd.Flags().GetString("secret-key")
		secretSalt, _ := cmd.Flags().GetString("secret-salt")

		crypter := crypter.NewCrypter(secretSalt)
		decrypted, err := crypter.Decrypt(key, secretKey)
		if err != nil {
			log.Fatalf("Failed to decrypt: %v", err)
		}
		var secretData secrets.SecretData
		if err := secretData.Unmarshal([]byte(decrypted)); err != nil {
			// Try to unmarshal as old format (array of strings)
			var keys []string
			if err2 := json.Unmarshal([]byte(decrypted), &keys); err2 != nil {
				log.Fatalf("Failed to unmarshal decrypted data: %v", err)
			}
			secretData.Keys = keys
		}
		keysJson, err := json.Marshal(secretData)
		if err != nil {
			log.Fatalf("Failed to marshal keys: %v", err)
		}
		fmt.Println(string(keysJson))
	},
}

// healthHandler provides a simple health check endpoint.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// startHTTPServer starts the HTTP server for health checks.
func startHTTPServer(port int) {
	http.HandleFunc("/health", healthHandler)
	log.Printf("Starting HTTP server on port %d", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the autounseal service",
	Run: func(cmd *cobra.Command, args []string) {
		configPath, _ := cmd.Flags().GetString("config")

		config, err := loadConfig(configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}

		if config.EncryptedKeys == "" {
			log.Fatalf("encrypted_keys is required for application")
		}
		// Start HTTP server (always enabled, default port 2310)
		port := 2310
		if config.HTTPServer != nil && config.HTTPServer.Port != 0 {
			port = config.HTTPServer.Port
		}
		go startHTTPServer(port)
		if config.KubeConfig != nil {
			vaultPodPort := config.KubeConfig.VaultPodPort
			if vaultPodPort == 0 {
				vaultPodPort = 8200
			}
			worker := workers.NewKubernetesWorker(
				config.KubeConfig.VaultNamespace,
				config.KubeConfig.VaultLabelSelector,
				config.KubeConfig.PodScanMaxCounter,
				config.KubeConfig.PodScanDelay,
				config.WaitInterval,
				config.KubeConfig.SecretName,
				config.KubeConfig.SecretNamespace,
				config.EncryptedKeys,
				vaultPodPort,
			)
			worker.Start()
		} else if config.HTTPConfig != nil {
			crypter := crypter.NewCrypter(config.HTTPConfig.SecretSalt)
			decrypted, err := crypter.Decrypt(config.EncryptedKeys, config.HTTPConfig.SecretKey)
			if err != nil {
				log.Fatalf("Failed to decrypt encrypted keys: %v", err)
			}

			var secretData secrets.SecretData
			if err := secretData.Unmarshal([]byte(decrypted)); err != nil {
				log.Fatalf("Failed to unmarshal decrypted keys: %v", err)
			}

			worker := workers.NewHTTPWorker(
				config.HTTPConfig.VaultURLs,
				config.WaitInterval,
			)
			worker.Start(secretData.Keys)
		} else {
			log.Fatalf("No worker configuration found")
		}
	},
}

func init() {
	rootCmd.AddCommand(createSecretDataCmd)
	rootCmd.AddCommand(decryptSecretDataCmd)
	rootCmd.AddCommand(startCmd)

	createSecretDataCmd.Flags().String("secret-key", "", "Secret key for encryption")
	createSecretDataCmd.Flags().String("secret-salt", "", "Secret salt for encryption")
	createSecretDataCmd.Flags().String("config", "", "Path to config file")
	decryptSecretDataCmd.Flags().String("secret-key", "", "Secret key for decryption")
	decryptSecretDataCmd.Flags().String("secret-salt", "", "Secret salt for decryption")
	decryptSecretDataCmd.Flags().String("config", "", "Path to config file")
	startCmd.Flags().String("config", "", "Path to config file")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
