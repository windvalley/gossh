/*
Copyright © 2021 windvalley

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// Encode plain text.
// Param keyLen available values: 16, 24, 32.
//
//	AES-128 uses a 128 bit key (16 bytes),
//	AES-192 uses a 192 bit key (24 bytes),
//	AES-256 uses a 256 bit key (32 bytes).
func Encode(plainText, key []byte, keyLen int) ([]byte, error) {
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, errors.New("invalid key length, available length: 16, 24, 32")
	}

	key = buildKey(key, keyLen)

	plainText = pkcs7Padding(plainText)

	cipherText := make([]byte, aes.BlockSize+len(plainText))

	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	return cipherText, nil
}

// Decode cipher text.
func Decode(cipherText, key []byte, keyLen int) (string, error) {
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return "", errors.New("invalid key length, available length: 16, 24, 32")
	}

	key = buildKey(key, keyLen)

	iv := cipherText[:aes.BlockSize]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plainTextBytes := make([]byte, len(cipherText))
	mode.CryptBlocks(plainTextBytes, cipherText)

	plainTextBytes = pkcs7UnPadding(plainTextBytes)

	return string(plainTextBytes[aes.BlockSize:]), nil
}

func pkcs7Padding(ciphertext []byte) []byte {
	padding := aes.BlockSize - len(ciphertext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(ciphertext, padtext...)
}

func pkcs7UnPadding(plainText []byte) []byte {
	length := len(plainText)
	unpadding := int(plainText[length-1])

	return plainText[:(length - unpadding)]
}

func buildKey(originKey []byte, keyLen int) []byte {
	originKeyLen := len(originKey)
	if originKeyLen >= keyLen {
		return originKey[:keyLen]
	}

	pads := bytes.Repeat([]byte{'0'}, keyLen-originKeyLen)

	originKey = append(originKey, pads...)

	return originKey
}
