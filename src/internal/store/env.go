package secrets

import (
	"fmt"
	"os"
)

type EnvStore struct {
	secretData *SecretData
}

func (e *EnvStore) SecretKey() string {
	return e.secretData.SecretKey
}

func (e *EnvStore) SecretSalt() string {
	return e.secretData.SecretSalt
}

func (e *EnvStore) Load() error {
	secretKey := os.Getenv("VA_SECRET_KEY")
	if secretKey == "" {
		return fmt.Errorf("VA_SECRET_KEY environment variable is not set")
	}

	secretSalt := os.Getenv("VA_SECRET_SALT")
	if secretSalt == "" {
		return fmt.Errorf("VA_SECRET_SALT environment variable is not set")
	}

	e.secretData = &SecretData{
		SecretKey:  secretKey,
		SecretSalt: secretSalt,
	}

	return nil
}

func NewEnvStore() (*EnvStore, error) {
	store := &EnvStore{}
	if err := store.Load(); err != nil {
		return nil, err
	}
	return store, nil
}
