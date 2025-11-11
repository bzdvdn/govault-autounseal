package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"
)

type FileSecretStore struct {
	FilePath   string `yaml:"file_path" mapstructure:"file_path"`
	secretData *SecretData
}

func (f *FileSecretStore) SecretKey() string {
	return f.secretData.SecretKey
}
func (f *FileSecretStore) SecretSalt() string {
	return f.secretData.SecretSalt
}

func (f *FileSecretStore) Load() error {
	data, err := os.ReadFile(f.FilePath)
	if err != nil {
		return err
	}

	var secretData SecretData
	ext := strings.ToLower(filepath.Ext(f.FilePath))
	if ext == ".yaml" || ext == ".yml" {
		if err := yaml.Unmarshal(data, &secretData); err != nil {
			return err
		}
	} else if ext == ".json" {
		if err := json.Unmarshal(data, &secretData); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("unsupported file extension: %s", ext)
	}

	f.secretData = &secretData
	return nil
}

func NewFileSecretStore(filePath string) (*FileSecretStore, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", filePath)
	}

	store := &FileSecretStore{
		FilePath: filePath,
	}

	if err := store.Load(); err != nil {
		return nil, err
	}

	return store, nil
}
