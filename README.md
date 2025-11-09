## Vault autounseal at Go with integrated password or native unsealer by shamir keys

This is a Go port of the Python Vault autounseal tool. It provides automatic unsealing of HashiCorp Vault instances using Shamir keys, with support for both Kubernetes and HTTP-based deployments.

### Features

- **Automatic Unsealing**: Continuously monitors Vault instances and automatically unseals them when they become sealed using Shamir keys
- **Multi-Backend Support**: Compatible with Kubernetes environments (via API proxy) and standalone HTTP-based Vault deployments
- **Secure Key Management**: Command-line tools for encrypting and decrypting unseal keys using AES encryption with configurable salt
- **Flexible Configuration**: Supports YAML configuration files, environment variables, and command-line flags
- **Health Monitoring**: Built-in HTTP server for health checks and monitoring (default port 2310)
- **Cross-Platform**: Single Go binary that runs on Linux, macOS, and Windows
- **Docker Support**: Ready-to-use Docker image for containerized deployments
- **Minimal Dependencies**: Uses standard Go libraries with minimal external dependencies for better security and performance
- **Kubernetes Integration**: Native support for Kubernetes secrets and pod discovery
- **Error Handling**: Comprehensive error handling and logging for reliable operation

### Installation

#### Option 1: Build from source

1. Clone the repository
2. Run `go build -o govault-autounseal ./src` to compile the binary
3. Copy one of the example configuration files (`kube.example.yaml` or `http.example.yaml`) to `config.yaml` and modify as needed

#### Option 2: Docker

1. Clone the repository
2. Build the Docker image:
    ```bash
    docker build -t govault-autounseal .
    ```
3. Copy the example configuration file (`config.example.yaml`) to `config.yaml` and modify as needed

### Configuration

The application can be configured via:

1. **YAML Configuration File** (`config.yaml`):
    ```yaml
    # Global settings
    wait_interval: 30
    encrypted_keys: "your-encrypted-keys-here"

    # Kubernetes configuration (uncomment and modify for kube mode)
    kube_config:
      vault_namespace: "vault"
      vault_label_selector: "app.kubernetes.io/name=vault"
      pod_scan_max_counter: 5
      pod_scan_delay: 30
      secret_name: "vault-unseal-keys"
      secret_namespace: "vault"
      vault_pod_port: 8200

    # OR for HTTP mode:
    http_config:
       vault_urls:
         - "https://vault.example.com:8200"
       secret_key: "your-secret-key"
       secret_salt: "your-salt-16-chars"

    # HTTP server configuration for health checks (always enabled, default port 2310)
    http_server:
      port: 2310
    ```

2. **Environment Variables**:
      - `VAULT_WAIT_INTERVAL`
      - `VAULT_ENCRYPTED_KEYS`
      - `VAULT_KUBE_NAMESPACE`
      - `VAULT_KUBE_LABEL_SELECTOR`
      - `VAULT_KUBE_POD_SCAN_MAX_COUNTER`
      - `VAULT_KUBE_POD_SCAN_DELAY`
      - `VAULT_KUBE_SECRET_NAME`
      - `VAULT_KUBE_SECRET_NAMESPACE`
      - `VAULT_KUBE_VAULT_POD_PORT`
      - `VAULT_HTTP_URLS`
      - `VAULT_HTTP_SECRET_KEY`
      - `VAULT_HTTP_SECRET_SALT`
      - `VAULT_HTTP_SERVER_PORT`

### Usage

#### Encrypt Unseal Keys

First, encrypt your unseal keys from the Vault init response. Encode the JSON content of keys.json as base64 and pass it as an argument:

```bash
export SECRET_KEY="test-keys-2310"
export SECRET_SALT="a3F8pLzQ9vXbR2mN"
export KEYS_B64=$(base64 -w 0 keys.example.json) && ./govault-autounseal create_secret_data $KEYS_B64 --secret-key $SECRET_KEY --secret-salt $SECRET_SALT > enc-keys
```

This will output an encrypted string containing your unseal keys.

#### Decrypt Keys (for verification)

```bash
export SECRET_KEY="test-keys-2310"
export SECRET_SALT="a3F8pLzQ9vXbR2mN"
export ENC_DATA=$(cat enc-keys) && ./govault-autounseal decrypt_secret_data $ENC_DATA --secret-key $SECRET_KEY --secret-salt $SECRET_SALT
```

#### Health Check

The service includes a built-in HTTP server for health monitoring:

```bash
curl http://localhost:2310/health
```

#### Run the Autounseal Service

##### Using Docker

For Kubernetes mode, create a secret with the encrypted keys, secret key, and secret salt:

```bash
kubectl create secret generic vault-unseal-keys \
  --from-literal=secret-key="your-secret-key" \
  --from-literal=secret-salt="your-salt-16-chars" \
  -n vault
```

Then run the service with Docker:

```bash
docker run -v $(pwd)/config.yaml:/root/config.yaml govault-autounseal start --config /root/config.yaml
```

For HTTP mode, ensure the encrypted keys are specified in the `encrypted_keys` field of your `config.yaml` file, then run the service:

```bash
docker run -v $(pwd)/config.yaml:/root/config.yaml govault-autounseal start --config /root/config.yaml
```

##### Using Binary

For Kubernetes mode, create a secret with the encrypted keys, secret key, and secret salt:

```bash
kubectl create secret generic vault-unseal-keys \
  --from-literal=secret-key="your-secret-key" \
  --from-literal=secret-salt="your-salt-16-chars" \
  -n vault
```

Then run the service:

```bash
./govault-autounseal start --config config.yaml
```

For HTTP mode, ensure the encrypted keys are specified in the `encrypted_keys` field of your `config.yaml` file, then run the service:

```bash
./govault-autounseal start --config config.yaml
```

### Security Notes

- Store encrypted keys securely and limit access to configuration files
- Use strong, randomly generated secret keys and salts (at least 16 characters for salt)
- Ensure proper access controls for the autounseal service and its configuration
- Regularly rotate unseal keys and update encrypted data
- Use HTTPS for Vault communication when possible
- Monitor logs for unauthorized access attempts
- Consider running the service with minimal privileges in production

### Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### License

MIT License