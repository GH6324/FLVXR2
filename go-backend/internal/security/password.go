package security

import (
	"crypto/subtle"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func VerifyPassword(storedHash, password string) (valid bool, needsUpgrade bool) {
	storedHash = strings.TrimSpace(storedHash)
	if strings.HasPrefix(storedHash, "$2a$") || strings.HasPrefix(storedHash, "$2b$") || strings.HasPrefix(storedHash, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)) == nil, false
	}
	if len(storedHash) != 32 {
		return false, false
	}
	legacyHash := MD5(password)
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(storedHash)), []byte(legacyHash)) != 1 {
		return false, false
	}
	return true, true
}
