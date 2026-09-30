package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"strconv"
)

// seal encrypts with AES-256-GCM. Output is nonce || ciphertext.
// aad is authenticated but not encrypted; we bind each secret to its user row.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func open(key, data, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	n := gcm.NonceSize()
	if len(data) < n {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, data[:n], data[n:], aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// userAAD stops someone with DB access from copying user A's encrypted
// secret into user B's row: decryption would fail.
func userAAD(id int64) []byte {
	return []byte("totp:" + strconv.FormatInt(id, 10))
}