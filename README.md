# Vault Auto-Unseal (Go)

A Go-based tool for automatic unsealing of HashiCorp Vault instances using Shamir keys. Supports both Kubernetes and HTTP-based deployments with flexible secret storage backends.

## Features

- **Automatic Unsealing**: Monitors Vault instances and unseals them when sealed
- **Multiple Storage Backends**: Environment variables, files, or Kubernetes secrets
- **Multi-Backend Support**: Kubernetes (API proxy) and standalone HTTP deployments
- **Secure Key Management**: AES encryption for unseal keys with configurable salt
- **Flexible Configuration**: YAML configs, environment variables, command-line flags
- **Health Monitoring**: Built-in HTTP server (default port 2310)
- **Cross-Platform**: Single binary for Linux, macOS, Windows
- **Docker Support**: Containerized deployment ready
- **Minimal Dependencies**: Standard Go libraries for security and performance

## Installation

### Build from Source

```bash
git clone <repository>
cd govault-autounseal
go build -o govault-autounseal ./src/cmd/cli
```

### Docker

```bash
docker build -t govault-autounseal .
```

## Configuration

The application supports multiple secret storage backends. Choose one store type per configuration.

### Storage Backends

#### Environment Variables (`env`)
Reads secrets from environment variables `VA_SECRET_KEY` and `VA_SECRET_SALT`.

```yaml
store:
  env: {}
```

#### File (`file`)
Reads secrets from YAML or JSON files.

```yaml
store:
  file:
    path: /path/to/secrets.yaml
```

File format:
```yaml
secret_key: "your-key"
secret_salt: "your-salt"
```

#### Kubernetes Secret (`kube`)
Reads secrets from Kubernetes secrets.

```yaml
store:
  kube:
    secret_name: "vault-secrets"
    secret_namespace: "vault"
```

### Complete Configuration Examples

#### Kubernetes Mode with File Store
```yaml
wait_interval: 30
encrypted_keys: "your-encrypted-keys-here"

store:
  file:
    path: /etc/vault/secrets.yaml

kube_config:
  vault_namespace: vault
  vault_label_selector: app=vault
  vault_pod_port: 8200
  pod_scan_max_counter: 10
  pod_scan_delay: 5

http_server:
  port: 2310
```

#### HTTP Mode with Environment Store
```yaml
wait_interval: 30
encrypted_keys: "your-encrypted-keys-here"

store:
  env: {}

http_config:
  vault_urls:
    - "https://vault1.example.com:8200"
    - "https://vault2.example.com:8200"

http_server:
  port: 2310
```

### Environment Variables

- `VA_SECRET_KEY` - Secret key for decryption (env store)
- `VA_SECRET_SALT` - Secret salt for decryption (env store)

## Usage

### Encrypt Unseal Keys

#### Using Binary
```bash
export VA_SECRET_KEY="your-secret-key"
export VA_SECRET_SALT="your-16-char-salt"
export KEYS_B64=$(base64 -w 0 keys.example.json)
./govault-autounseal create_secret_data $KEYS_B64 --secret-key $VA_SECRET_KEY --secret-salt $VA_SECRET_SALT > enc-keys
```

#### Using Docker
```bash
export VA_SECRET_KEY="your-secret-key"
export VA_SECRET_SALT="your-16-char-salt"
export KEYS_B64=$(base64 -w 0 keys.example.json)
docker run --rm -e VA_SECRET_KEY=$VA_SECRET_KEY -e VA_SECRET_SALT=$VA_SECRET_SALT \
  -v $(pwd)/keys.example.json:/tmp/keys.example.json \
  bzdvdn/govault-autounseal create_secret_data $KEYS_B64 \
  --secret-key $VA_SECRET_KEY --secret-salt $VA_SECRET_SALT > enc-keys
```

### Decrypt Keys (Verification)

#### Using Binary
```bash
export VA_SECRET_KEY="your-secret-key"
export VA_SECRET_SALT="your-16-char-salt"
./govault-autounseal decrypt_secret_data $(cat enc-keys) --secret-key $VA_SECRET_KEY --secret-salt $VA_SECRET_SALT
```

#### Using Docker
```bash
export VA_SECRET_KEY="your-secret-key"
export VA_SECRET_SALT="your-16-char-salt"
docker run --rm -e VA_SECRET_KEY=$VA_SECRET_KEY -e VA_SECRET_SALT=$VA_SECRET_SALT \
  bzdvdn/govault-autounseal decrypt_secret_data $(cat enc-keys) \
  --secret-key $VA_SECRET_KEY --secret-salt $VA_SECRET_SALT
```

### Health Check

```bash
curl http://localhost:2310/health
```

### Run the Service

#### Docker
```bash
docker run -v $(pwd)/config.yaml:/root/config.yaml bzdvdn/govault-autounseal start --config /root/config.yaml
```

#### Binary
```bash
./govault-autounseal start --config config.yaml
```

For Kubernetes deployments, ensure secrets are created with the required keys and salts.

## Project Structure

```
src/
├── cmd/cli/           # Main application entry point
├── internal/
│   ├── bootstrap/     # Command initialization
│   ├── config/        # Configuration management
│   ├── http/          # HTTP server for health checks
│   ├── store/         # Secret storage backends
│   ├── vault/         # Vault client and data structures
│   └── workers/       # Unsealing workers (K8s/HTTP)
└── pkg/
    ├── crypter/       # AES encryption utilities
    └── utils/         # Kubernetes utilities
```

## Security Notes

- Store encrypted keys securely and limit access to configuration files
- Use strong, randomly generated secret keys and salts (at least 16 characters)
- Ensure proper access controls for the autounseal service and its configuration
- Regularly rotate unseal keys and update encrypted data
- Use HTTPS for Vault communication when possible
- Monitor logs for unauthorized access attempts
- Consider running the service with minimal privileges in production

## License

MIT License