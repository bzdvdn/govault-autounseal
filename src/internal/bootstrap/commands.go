package bootstrap

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"govault-autounseal/src/internal/config"
	"govault-autounseal/src/internal/http"
	"govault-autounseal/src/internal/vault"
	"govault-autounseal/src/internal/workers"
	"govault-autounseal/src/pkg/crypter"

	"github.com/spf13/cobra"
)

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

		encryptedData := vault.EncryptedData{Keys: keysStr}
		keysJson, err := encryptedData.Marshal()
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
		var encryptedData vault.EncryptedData
		if err := encryptedData.Unmarshal([]byte(decrypted)); err != nil {
			// Try to unmarshal as old format (array of strings)
			var keys []string
			if err2 := json.Unmarshal([]byte(decrypted), &keys); err2 != nil {
				log.Fatalf("Failed to unmarshal decrypted data: %v", err)
			}
			encryptedData.Keys = keys
		}
		keysJson, err := json.Marshal(encryptedData)
		if err != nil {
			log.Fatalf("Failed to marshal keys: %v", err)
		}
		fmt.Println(string(keysJson))
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the autounseal service",
	Run: func(cmd *cobra.Command, args []string) {
		configPath, _ := cmd.Flags().GetString("config")

		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}

		if cfg.EncryptedKeys == "" {
			log.Fatalf("encrypted_keys is required for application")
		}

		store, err := cfg.CreateStore()
		if err != nil {
			log.Fatalf("Failed to create store: %v", err)
		}

		// Start HTTP server (always enabled, default port 2310)
		port := 2310
		if cfg.HTTPServer != nil && cfg.HTTPServer.Port != 0 {
			port = cfg.HTTPServer.Port
		}
		go http.StartHTTPServer(port)
		if cfg.KubeConfig != nil {
			vaultPodPort := cfg.KubeConfig.VaultPodPort
			if vaultPodPort == 0 {
				vaultPodPort = 8200
			}
			worker := workers.NewKubernetesWorker(
				cfg.KubeConfig.VaultNamespace,
				cfg.KubeConfig.VaultLabelSelector,
				cfg.KubeConfig.PodScanMaxCounter,
				cfg.KubeConfig.PodScanDelay,
				cfg.WaitInterval,
				store,
				cfg.EncryptedKeys,
				vaultPodPort,
			)
			worker.Start()
		} else if cfg.HTTPConfig != nil {
			worker := workers.NewHTTPWorker(
				cfg.HTTPConfig.VaultURLs,
				cfg.WaitInterval,
				store,
			)
			worker.Start(cfg.EncryptedKeys)
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

	decryptSecretDataCmd.Flags().String("secret-key", "", "Secret key for decryption")
	decryptSecretDataCmd.Flags().String("secret-salt", "", "Secret salt for decryption")

	startCmd.Flags().String("config", "", "Path to config file")
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
