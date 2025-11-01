## Vault autounseal at Go with integrated password or native unsealer by shamir keys

This is a Go port of the Python Vault autounseal tool. It provides automatic unsealing of HashiCorp Vault instances using Shamir keys, with support for both Kubernetes and HTTP-based deployments.

### Features

- **Automatic Unsealing**: Continuously monitors Vault instances and unseals them when they become sealed
- **Multiple Backends**: Supports both Kubernetes (via API proxy) and direct HTTP access
- **Encrypted Key Storage**: Securely stores unseal keys using AES encryption
- **Configuration Flexibility**: Supports YAML configuration files and environment variables

### Installation

#### Option 1: Build from source

1. Clone the repository
2. Run `go build` to compile the binary
3. Copy `config.example.yaml` to `config.yaml` and modify as needed

#### Option 2: Docker

1. Clone the repository
2. Build the Docker image:
   ```bash
   docker build -t govault-autounseal .
   ```
3. Copy `config.example.yaml` to `config.yaml` and modify as needed

### Configuration

The application can be configured via:

1. **YAML Configuration File** (`config.yaml`):
   ```yaml
   wait_interval: 30
   secret_key: "your-secret-key"
   secret_salt: "your-salt-16-chars"
   
   kube_config:
     vault_namespace: "vault"
     vault_label_selector: "app.kubernetes.io/name=vault"
     pod_scan_max_counter: 5
     pod_scan_delay: 30
   
   # OR for HTTP mode:
   http_config:
     vault_urls:
       - "https://vault.example.com:8200"
     username: "admin"  # optional
     password: "password"  # optional
   ```

2. **Environment Variables**:
    - `VAULT_WAIT_INTERVAL`
    - `VAULT_SECRET_KEY`
    - `VAULT_SECRET_SALT`
    - `VAULT_KUBE_ENABLED`
    - `VAULT_KUBE_NAMESPACE`
    - `VAULT_KUBE_LABEL_SELECTOR`
    - `VAULT_KUBE_POD_SCAN_MAX_COUNTER`
    - `VAULT_KUBE_POD_SCAN_DELAY`
    - `VAULT_KUBE_SECRET_NAME`
    - `VAULT_KUBE_SECRET_NAMESPACE`
    - `VAULT_HTTP_ENABLED`
    - `VAULT_HTTP_URLS`
    - `VAULT_HTTP_USERNAME`
    - `VAULT_HTTP_PASSWORD`

### Usage

#### Encrypt Unseal Keys

First, encrypt your unseal keys from the Vault init response. Encode the JSON content of keys.json as base64 and pass it as an argument:

```bash
base64 -w 0 keys.json | ./govault-autounseal create_secret_data --config config.yaml
```

This will output an encrypted string containing your unseal keys.

#### Decrypt Keys (for verification)

```bash
./govault-autounseal decrypt_secret_data "encrypted-string" --config config.yaml
```

#### Run the Autounseal Service

##### Using Docker

For Kubernetes mode, create a secret with the encrypted keys:

```bash
kubectl create secret generic vault-unseal-keys --from-literal=encrypted-keys="your-encrypted-keys" -n vault
```

Then run the service with Docker:

```bash
docker run -v $(pwd)/config.yaml:/root/config.yaml govault-autounseal start --config /root/config.yaml
```

For HTTP mode, set the encrypted keys as an environment variable:

```bash
docker run -e VAULT_ENCRYPTED_KEYS="your-encrypted-keys" -v $(pwd)/config.yaml:/root/config.yaml govault-autounseal start --config /root/config.yaml
```

##### Using Binary

For Kubernetes mode, create a secret with the encrypted keys:

```bash
kubectl create secret generic vault-unseal-keys --from-literal=encrypted-keys="your-encrypted-keys" -n vault
```

Then run the service:

```bash
./govault-autounseal start --config config.yaml
```

For HTTP mode, set the encrypted keys as an environment variable:

```bash
export VAULT_ENCRYPTED_KEYS="your-encrypted-keys"
./govault-autounseal start --config config.yaml
```

### Key Differences from Python Version

- **Language**: Rewritten in Go for better performance and deployment
- **Dependencies**: Uses standard Go libraries where possible, with minimal external dependencies
- **Error Handling**: Improved error handling and logging
- **Configuration**: Simplified configuration loading with viper

### Security Notes

- Store encrypted keys securely
- Use strong secret keys and salts
- Ensure proper access controls for the autounseal service
- Regularly rotate unseal keys and update encrypted data

### License

MIT License