package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

type aesCipher struct {
	block  cipher.Block
	stream cipher.Stream
}

func (a *aesCipher) encrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))
	a.stream.XORKeyStream(encrypted, data)
	return encrypted
}

func (a *aesCipher) decrypt(data []byte) []byte {
	decrypted := make([]byte, len(data))
	a.stream.XORKeyStream(decrypted, data)
	return decrypted
}

type Crypter struct {
	salt string
}

func NewCrypter(salt string) *Crypter {
	return &Crypter{salt: salt}
}

func (c *Crypter) encrypt(strToEnc, secret string) (string, error) {
	aesObj, err := c.getAESObj(secret)
	if err != nil {
		return "", err
	}

	hxEnc := aesObj.encrypt([]byte(strToEnc))
	strEnc := base64.StdEncoding.EncodeToString(hxEnc)
	return strings.ReplaceAll(strEnc, "/", "-_-"), nil
}

func (c *Crypter) decrypt(encStr, secret string) (string, error) {
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
