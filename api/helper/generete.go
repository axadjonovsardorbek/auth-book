package helper

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower  = "abcdefghijklmnopqrstuvwxyz"
	digits = "0123456789"
)

func GeneratePassword(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("password length must be positive")
	}

	pool := upper + lower + digits
	password := make([]byte, length)

	for i := 0; i < length; i++ {
		charIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
		if err != nil {
			return "", err
		}
		password[i] = pool[charIndex.Int64()]
	}

	return string(password), nil
}
