package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"strconv"
)

// AES-GCM se encrypt karke user-specific aad ke saath bind kar dete hain.
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

// user-specific aad is liye ke secret ko doosre user ke row me paste nahi ho paaye.
func userAAD(id int64) []byte {
	return []byte("totp:" + strconv.FormatInt(id, 10))
}
