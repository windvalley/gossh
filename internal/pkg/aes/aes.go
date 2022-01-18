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
