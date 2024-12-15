// Package authenticator provides TOTP (Time-based One-Time Password) authentication
// implementation compatible with Google Authenticator, Microsoft Authenticator,
// and other standard TOTP applications.
package authenticator

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Algorithm represents the supported hash algorithms
type Algorithm string

const (
	SHA1   Algorithm = "SHA1"
	SHA256 Algorithm = "SHA256"
	SHA512 Algorithm = "SHA512"
)

// Config holds the configuration for TOTP generation
type Config struct {
	// Algorithm to use for TOTP generation
	Algorithm Algorithm
	// Digits is the length of the generated TOTP
	Digits int
	// Period is the time step in seconds
	Period int
	// Secret is the base32 encoded secret key
	Secret string
}

// DefaultConfig returns a Config with standard settings
func DefaultConfig() Config {
	return Config{
		Algorithm: SHA1,
		Digits:    6,
		Period:    30,
	}
}

// Authenticator handles TOTP generation and validation
type Authenticator struct {
	config      Config
	rateLimiter *RateLimiter
	mu          sync.RWMutex
}

// RateLimiter handles rate limiting for validation attempts
type RateLimiter struct {
	attempts map[string][]time.Time
	window   time.Duration
	limit    int
	mu       sync.RWMutex
}

// NewAuthenticator creates a new Authenticator instance
func NewAuthenticator(config Config) (*Authenticator, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return &Authenticator{
		config: config,
		rateLimiter: &RateLimiter{
			attempts: make(map[string][]time.Time),
			window:   5 * time.Minute,
			limit:    5,
		},
	}, nil
}

func validateConfig(config Config) (err error) {
	if config.Algorithm != SHA1 && config.Algorithm != SHA256 && config.Algorithm != SHA512 {
		err = fmt.Errorf("invalid algorithm: %s", config.Algorithm)
	} else if config.Digits < 6 || config.Digits > 8 {
		err = fmt.Errorf("invalid number of digits: %d", config.Digits)
	} else if config.Period < 30 {
		err = fmt.Errorf("invalid period: %d", config.Period)
	}
	return

}

// GenerateSecret generates a new random secret key
func GenerateSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes), nil
}

// GenerateTOTP generates a TOTP token
func (a *Authenticator) GenerateTOTP() (string, error) {
	counter := uint64(time.Now().Unix() / int64(a.config.Period))
	return a.generateTOTPForCounter(counter)
}

func (a *Authenticator) generateTOTPForCounter(counter uint64) (string, error) {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(a.config.Secret)
	if err != nil {
		return "", fmt.Errorf("invalid secret key: %v", err)
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	var h func() hash.Hash
	switch a.config.Algorithm {
	case SHA1:
		h = sha1.New
	case SHA256:
		h = sha256.New
	case SHA512:
		h = sha512.New
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", a.config.Algorithm)
	}

	mac := hmac.New(h, secret)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	mod := int64(1)
	for i := 0; i < a.config.Digits; i++ {
		mod *= 10
	}
	value = value % mod

	return fmt.Sprintf(fmt.Sprintf("%%0%dd", a.config.Digits), value), nil
}

// ValidateTOTP validates a TOTP token
func (a *Authenticator) ValidateTOTP(token string, userId string) (bool, error) {
	// Check rate limiting
	if exceeded, err := a.rateLimiter.CheckLimit(userId); err != nil {
		return false, err
	} else if exceeded {
		return false, fmt.Errorf("rate limit exceeded for user %s", userId)
	}

	counter := uint64(time.Now().Unix() / int64(a.config.Period))

	// Check current and adjacent time windows
	for i := -1; i <= 1; i++ {
		generated, err := a.generateTOTPForCounter(counter + uint64(i))
		if err != nil {
			return false, err
		}
		if generated == token {
			return true, nil
		}
	}

	return false, nil
}

// GenerateQRCode generates a QR code URI for the authenticator app
func (a *Authenticator) GenerateQRCode(accountName, issuer string) string {
	params := url.Values{}
	params.Add("secret", a.config.Secret)
	params.Add("issuer", issuer)
	params.Add("algorithm", string(a.config.Algorithm))
	params.Add("digits", fmt.Sprintf("%d", a.config.Digits))
	params.Add("period", fmt.Sprintf("%d", a.config.Period))

	return fmt.Sprintf("otpauth://totp/%s:%s?%s",
		url.QueryEscape(issuer),
		url.QueryEscape(accountName),
		params.Encode())
}

// FormatSecretKey formats the secret key for manual entry
func (a *Authenticator) FormatSecretKey() string {
	secret := a.config.Secret
	var chunks []string
	for i := 0; i < len(secret); i += 4 {
		end := i + 4
		if end > len(secret) {
			end = len(secret)
		}
		chunks = append(chunks, secret[i:end])
	}
	return strings.Join(chunks, " ")
}

// CheckLimit checks if the rate limit has been exceeded
func (r *RateLimiter) CheckLimit(userId string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	attempts := r.attempts[userId]

	// Clean old attempts
	valid := make([]time.Time, 0)
	for _, t := range attempts {
		if now.Sub(t) < r.window {
			valid = append(valid, t)
		}
	}

	// Add new attempt
	valid = append(valid, now)
	r.attempts[userId] = valid

	return len(valid) > r.limit, nil
}
