package crypter

import (
	"testing"
)

func TestNewCrypter(t *testing.T) {
	salt := "abcdefghijklmnop" // 16 bytes
	crypter := NewCrypter(salt)
	if crypter == nil {
		t.Fatal("NewCrypter returned nil")
	}
	if crypter.salt != salt {
		t.Errorf("Expected salt %s, got %s", salt, crypter.salt)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	salt := "abcdefghijklmnop" // 16 bytes
	secret := "test-secret"
	original := "Hello, World!"

	crypter := NewCrypter(salt)

	encrypted, err := crypter.Encrypt(original, secret)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := crypter.Decrypt(encrypted, secret)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted != original {
		t.Errorf("Expected %s, got %s", original, decrypted)
	}
}

func TestEncrypt(t *testing.T) {
	salt := "abcdefghijklmnop" // 16 bytes
	secret := "test-secret"
	original := "test data"

	crypter := NewCrypter(salt)

	encrypted, err := crypter.Encrypt(original, secret)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encrypted == "" {
		t.Error("Encrypted string is empty")
	}

	// Ensure encrypted string is different from original
	if encrypted == original {
		t.Error("Encrypted string is the same as original")
	}
}

func TestDecrypt(t *testing.T) {
	salt := "abcdefghijklmnop" // 16 bytes
	secret := "test-secret"
	original := "test data"

	crypter := NewCrypter(salt)

	encrypted, err := crypter.Encrypt(original, secret)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := crypter.Decrypt(encrypted, secret)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted != original {
		t.Errorf("Expected %s, got %s", original, decrypted)
	}
}

func TestDecryptInvalidBase64(t *testing.T) {
	salt := "abcdefghijklmnop" // 16 bytes
	secret := "test-secret"
	invalidEncrypted := "invalid-base64"

	crypter := NewCrypter(salt)

	_, err := crypter.Decrypt(invalidEncrypted, secret)
	if err == nil {
		t.Error("Expected error for invalid base64")
	}
}

func TestGetAESObj(t *testing.T) {
	salt := "abcdefghijklmnop" // 16 bytes
	secret := "test-secret"

	crypter := NewCrypter(salt)

	aesObj, err := crypter.getAESObj(secret)
	if err != nil {
		t.Fatalf("getAESObj failed: %v", err)
	}

	if aesObj == nil {
		t.Fatal("getAESObj returned nil")
	}

	if aesObj.block == nil {
		t.Error("AES block is nil")
	}

	if len(aesObj.iv) != 16 {
		t.Errorf("Expected IV length 16, got %d", len(aesObj.iv))
	}
}

func TestGetAESObjInvalidSalt(t *testing.T) {
	salt := "short" // less than 16 bytes
	secret := "test-secret"

	crypter := NewCrypter(salt)

	_, err := crypter.getAESObj(secret)
	if err == nil {
		t.Error("Expected error for invalid salt length")
	}
}
