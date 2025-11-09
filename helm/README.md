# govault-autounseal

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.0.0](https://img.shields.io/badge/AppVersion-1.0.0-informational?style=flat-square)

A Helm chart for govault-autounseal Go application that automatically unseals HashiCorp Vault instances using Shamir keys.

## Description

This Helm chart deploys the govault-autounseal application, which provides automatic unsealing of HashiCorp Vault instances. The application supports two modes:

- **Kubernetes mode**: Discovers Vault pods in a Kubernetes cluster and unseals them via the Kubernetes API
- **HTTP mode**: Connects directly to Vault instances via HTTP/HTTPS endpoints

The application continuously monitors Vault instances and automatically unseals them when they become sealed, using encrypted Shamir keys stored securely.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- HashiCorp Vault instances
- Encrypted unseal keys (generated using the govault-autounseal CLI tool)

## Installing the Chart

### Add the Helm Repository

```bash
# If you have a repository, add it here
helm repo add your-repo https://your-repo-url
helm repo update
```

### Install the Chart

#### For Kubernetes Mode

```bash
# Create encrypted keys first (see below)
export SECRET_KEY="your-secret-key"
export SECRET_SALT="your-salt-16-chars"
export KEYS_B64=$(base64 -w 0 keys.json)
./govault-autounseal create_secret_data $KEYS_B64 --secret-key $SECRET_KEY --secret-salt $SECRET_SALT > encrypted-keys

# Install the chart
helm install govault-autounseal ./helm \
  --set config.encrypted_keys="$(cat encrypted-keys)" \
  --set encryptionSecret.enabled=true \
  --set encryptionSecret.secretKey="$SECRET_KEY" \
  --set encryptionSecret.secretSalt="$SECRET_SALT" \
  --namespace vault
```

#### For HTTP Mode

```bash
# Install the chart
helm install govault-autounseal ./helm \
  --set mode="http" \
  --set config.encrypted_keys="your-encrypted-keys" \
  --set httpConfig.vault_urls[0]="https://vault.example.com:8200" \
  --set httpConfig.secret_key="your-secret-key" \
  --set httpConfig.secret_salt="your-salt-16-chars" \
  --namespace vault
```

## Uninstalling the Chart

To uninstall/delete the `govault-autounseal` deployment:

```bash
helm uninstall govault-autounseal -n vault
```

## Configuration

The following table lists the configurable parameters of the govault-autounseal chart and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `nameOverride` | Override the name of the chart | `""` |
| `fullnameOverride` | Override the full name of the chart | `""` |
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `govault-autounseal` |
| `image.tag` | Image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `config.wait_interval` | Interval between checks (seconds) | `30` |
| `config.encrypted_keys` | Encrypted unseal keys (required) | `""` |
| `config.http_server.port` | Health check server port | `2310` |
| `mode` | Operation mode: "kube" or "http" | `"kube"` |
| `encryptionSecret.enabled` | Enable encryption secret creation | `false` |
| `encryptionSecret.secretKey` | Secret key for encryption | `"your-secret-key"` |
| `encryptionSecret.secretSalt` | Salt for encryption (16 chars) | `"your-salt-16-chars"` |
| `kubeConfig.vault_namespace` | Namespace where Vault pods run | `"vault"` |
| `kubeConfig.vault_label_selector` | Label selector for Vault pods | `"app.kubernetes.io/name=vault"` |
| `kubeConfig.pod_scan_max_counter` | Max pod scan attempts | `5` |
| `kubeConfig.pod_scan_delay` | Delay between pod scans (seconds) | `30` |
| `kubeConfig.secret_name` | Name of the secret containing keys | `"vault-unseal-keys"` |
| `kubeConfig.secret_namespace` | Namespace of the keys secret | `"vault"` |
| `kubeConfig.vault_pod_port` | Port of Vault pods | `8200` |
| `httpConfig.vault_urls` | List of Vault URLs for HTTP mode | `[]` |
| `httpConfig.secret_key` | Secret key for HTTP mode | `"change-this-key"` |
| `httpConfig.secret_salt` | Salt for HTTP mode (16 chars) | `"change-this-salt-16-chars"` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `serviceAccount.name` | Service account name | `""` |
| `rbac.create` | Create RBAC resources | `true` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `2310` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |
| `resources.limits.cpu` | CPU limit | `300m` |
| `resources.limits.memory` | Memory limit | `254Mi` |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity | `{}` |

## Key Generation

Before installing the chart, you need to generate encrypted unseal keys:

1. Obtain your Vault unseal keys from the Vault init response
2. Encode the keys JSON as base64:
   ```bash
   export KEYS_B64=$(base64 -w 0 keys.json)
   ```
3. Generate encrypted keys:
   ```bash
   ./govault-autounseal create_secret_data $KEYS_B64 --secret-key $SECRET_KEY --secret-salt $SECRET_SALT > encrypted-keys
   ```

## Examples

### Kubernetes Mode with External Secret

```yaml
# values.yaml
mode: "kube"
config:
  encrypted_keys: "VFZ2UjZ6dzZybnpEUmtTQ2FncyBsbUl5eDRkaCtCdlpaOWZtWF8tZ1NRQ254YXAzSldPcTdtR0IrTzNqOFNoNk5YclRM-RUZGK2k0RTgzLV8tMnJLWVdPbFJSQmtnOFNNS0VhMExvbHhTdkRjRXJuUU9ieDlVMzJFU2EzVExTNjhuTmhmSVZYdXVBOGwzVkxMSnp1MmtEY3krSHZpMnQwSWNkQmVfRjZXRGRiS3VRVm5fc1E2bVpSb3o2K1NobzRqemRkSEIyQ25PQl8tMmVfLXJlU2VaRHJ6U1BtWVl6SXlNUWVkazJDemUrUHl1aXg0ZXRRY295ZU15ZHZFY2Y4STJlUlVYenY2b3RzMmhoOEFKb3lrYTFZY3h5NnJQZk1Nd1pGK0ZjaXJmR1ZkczlyOUtPUDByejRSa2VXOEJxRXcrY3U2VEJV"  # Replace with your encrypted keys
encryptionSecret:
  enabled: true
  secretKey: "your-actual-secret-key"
  secretSalt: "your-16-char-salt"
kubeConfig:
  vault_namespace: "vault-system"
  vault_label_selector: "app.kubernetes.io/name=vault"
```

### HTTP Mode

```yaml
# values.yaml
mode: "http"
config:
  encrypted_keys: "VFZ2UjZ6dzZybnpEUmtTQ2FncyBsbUl5eDRkaCtCdlpaOWZtWF8tZ1NRQ254YXAzSldPcTdtR0IrTzNqOFNoNk5YclRM-RUZGK2k0RTgzLV8tMnJLWVdPbFJSQmtnOFNNS0VhMExvbHhTdkRjRXJuUU9ieDlVMzJFU2EzVExTNjhuTmhmSVZYdXVBOGwzVkxMSnp1MmtEY3krSHZpMnQwSWNkQmVfRjZXRGRiS3VRVm5fc1E2bVpSb3o2K1NobzRqemRkSEIyQ25PQl8tMmVfLXJlU2VaRHJ6U1BtWVl6SXlNUWVkazJDemUrUHl1aXg0ZXRRY295ZU15ZHZFY2Y4STJlUlVYenY2b3RzMmhoOEFKb3lrYTFZY3h5NnJQZk1Nd1pGK0ZjaXJmR1ZkczlyOUtPUDByejRSa2VXOEJxRXcrY3U2VEJV"  # Replace with your encrypted keys
httpConfig:
  vault_urls:
    - "https://vault-1.example.com:8200"
    - "https://vault-2.example.com:8200"
  secret_key: "your-actual-secret-key"
  secret_salt: "your-16-char-salt"
```

## Health Checks

The application exposes a health check endpoint on port 2310:

```bash
curl http://govault-autounseal-service:2310/health
```

## Security Considerations

- Store encrypted keys securely and limit access to configuration files
- Use strong, randomly generated secret keys and salts (at least 16 characters for salt)
- Ensure proper access controls for the autounseal service and its configuration
- Regularly rotate unseal keys and update encrypted data
- Use HTTPS for Vault communication when possible
- Monitor logs for unauthorized access attempts
- Consider running the service with minimal privileges in production

## Troubleshooting

### Common Issues

1. **Pod fails to start**: Check that `encrypted_keys` is properly set and not empty
2. **RBAC permissions**: Ensure the service account has permissions to access Vault pods and secrets in the specified namespace
3. **Key decryption fails**: Verify that `secret_key` and `secret_salt` match those used for encryption
4. **Vault connection fails**: Check network connectivity and Vault endpoint configuration

### Logs

View application logs:

```bash
kubectl logs -l app.kubernetes.io/name=govault-autounseal -n vault
```

### Debugging

Enable debug logging by setting environment variables or modifying the configuration.

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

MIT License