package aes

import (
	"encoding/hex"
	"strings"

	"github.com/windvalley/gossh/pkg/aes"
	"github.com/windvalley/gossh/pkg/util"
)

const (
	// cipherTextHead for identifying encrypted strings.
	cipherTextHead = "GOSSH-AES256:"
)

// AES256Encode ...
func AES256Encode(plainText, key string) (string, error) {
	keyLen := 32

	cipherText, err := aes.Encode([]byte(plainText), []byte(key), keyLen)
	if err != nil {
		return "", err
	}

	hexCipherText := hex.EncodeToString(cipherText)

	return cipherTextHead + hexCipherText, nil
}

// AES256Decode ...
func AES256Decode(hexCipherText, key string) (string, error) {
	defer func() {
		if err := recover(); err != nil {
			util.CheckErr("decryption failed: wrong vault password")
		}
	}()

	keyLen := 32

	hexCipherText = strings.TrimPrefix(hexCipherText, cipherTextHead)

	cipherText, err := hex.DecodeString(hexCipherText)
	if err != nil {
		return "", err
	}

	return aes.Decode(cipherText, []byte(key), keyLen)
}

// IsAES256CipherText or not.
func IsAES256CipherText(text string) bool {
	return strings.HasPrefix(text, cipherTextHead)
}
