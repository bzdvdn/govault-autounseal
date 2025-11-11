package secrets

type SecretStoreInteface interface {
	SecretKey() string
	SecretSalt() string
	Load() error
}

type SecretData struct {
	SecretKey  string `json:"secret_key" yaml:"secret_key" mapstructure:"secret_key"`
	SecretSalt string `json:"secret_salt" yaml:"secret_salt" mapstructure:"secret_salt"`
}
