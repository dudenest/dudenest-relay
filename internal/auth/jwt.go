package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	jwtMu     sync.RWMutex
	jwtSecret = []byte(func() string { // initialized from env; updated via SetJWTSecret after ZT bootstrap
		s := os.Getenv("JWT_SECRET")
		if s == "" { return "dev-secret-change-in-prod" }
		return s
	}())
)

// SetJWTSecret updates the JWT signing secret at runtime (called after ZT bootstrap delivers it).
func SetJWTSecret(s string) {
	jwtMu.Lock()
	jwtSecret = []byte(s)
	jwtMu.Unlock()
}

type Claims struct {
	Sub      string `json:"sub"`      // user id
	Email    string `json:"email"`
	Name     string `json:"name,omitempty"`
	Avatar   string `json:"avatar,omitempty"`
	Provider string `json:"provider"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
}

func ValidateJWT(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 { return nil, errors.New("invalid token") }
	msg := parts[0] + "." + parts[1]
	if sign(msg) != parts[2] { return nil, errors.New("invalid signature") }
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil { return nil, err }
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil { return nil, err }
	if time.Now().Unix() > c.Exp { return nil, errors.New("token expired") }
	return &c, nil
}

func sign(msg string) string {
	jwtMu.RLock()
	secret := jwtSecret
	jwtMu.RUnlock()
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
