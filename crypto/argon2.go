package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"orion-auth-backend/config"
)

var (
	ErrInvalidHash         = errors.New("invalid argon2id hash format")
	ErrIncompatibleVersion = errors.New("incompatible argon2id version")
)

type Argon2Hasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func NewArgon2Hasher(cfg config.Argon2Config) *Argon2Hasher {
	return &Argon2Hasher{
		memory:      cfg.Memory,
		iterations:  cfg.Iterations,
		parallelism: cfg.Parallelism,
		saltLength:  cfg.SaltLength,
		keyLength:   cfg.KeyLength,
	}
}

// Hash generates an Argon2id hash of the given password.
// Returns a string in the format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func (h *Argon2Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, h.iterations, h.memory, h.parallelism, h.keyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memory, h.iterations, h.parallelism, b64Salt, b64Hash)

	return encoded, nil
}

// Verify checks if the given password matches the encoded hash.
func (h *Argon2Hasher) Verify(password, encodedHash string) (bool, error) {
	salt, hash, params, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey([]byte(password), salt, params.iterations, params.memory, params.parallelism, uint32(len(hash)))

	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

func decodeHash(encodedHash string) (salt, hash []byte, params *argon2Params, err error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	params = &argon2Params{}
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.iterations, &params.parallelism)
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	return salt, hash, params, nil
}
