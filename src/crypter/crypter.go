// Package crypter provides encryption and decryption functionality using AES encryption.
package crypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// aesCipher holds the AES block and stream cipher for encryption/decryption operations.
type aesCipher struct {
	block  cipher.Block
	stream cipher.Stream
}

// encrypt encrypts the given data using AES stream cipher.
func (a *aesCipher) encrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))
	a.stream.XORKeyStream(encrypted, data)
	return encrypted
}

// decrypt decrypts the given data using AES stream cipher.
func (a *aesCipher) decrypt(data []byte) []byte {
	decrypted := make([]byte, len(data))
	a.stream.XORKeyStream(decrypted, data)
	return decrypted
}

// Crypter provides AES encryption and decryption functionality.
type Crypter struct {
	salt string
}

// NewCrypter creates a new Crypter instance with the given salt.
func NewCrypter(salt string) *Crypter {
	return &Crypter{salt: salt}
}

// Encrypt encrypts the given string using AES encryption with the provided secret key.
func (c *Crypter) Encrypt(strToEnc, secret string) (string, error) {
	aesObj, err := c.getAESObj(secret)
	if err != nil {
		return "", err
	}

	hxEnc := aesObj.encrypt([]byte(strToEnc))
	strEnc := base64.StdEncoding.EncodeToString(hxEnc)
	return strings.ReplaceAll(strEnc, "/", "-_-"), nil
}

// Decrypt decrypts the given encrypted string using AES decryption with the provided secret key.
func (c *Crypter) Decrypt(encStr, secret string) (string, error) {
	encStr = strings.ReplaceAll(encStr, "-_-", "/")
	aesObj, err := c.getAESObj(secret)
	if err != nil {
		return "", err
	}

	strTmp, err := base64.StdEncoding.DecodeString(encStr)
	if err != nil {
		return "", err
	}

	strDec := aesObj.decrypt(strTmp)
	return string(strDec), nil
}

// getAESObj creates and returns an AES cipher object for the given key.
func (c *Crypter) getAESObj(key string) (*aesCipher, error) {
	hash := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}

	iv := []byte(c.salt)
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV must be %d bytes long", aes.BlockSize)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	return &aesCipher{block: block, stream: stream}, nil
}
