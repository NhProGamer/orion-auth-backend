package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// ErrUnsupportedScheme is returned when a stored hash uses a scheme we cannot
// verify (e.g. Logto "Legacy" JSON digests, or an unknown prefix). Callers
// migrating from a foreign IAM treat such accounts as password-less: the user
// must reset before they can sign in.
var ErrUnsupportedScheme = errors.New("unsupported password hash scheme")

// importedPrefix namespaces unsalted digest hashes carried over from a foreign
// IAM. Argon2 and bcrypt hashes are already self-describing ($argon2i$…,
// $2b$…) and stored verbatim; bare hex digests are not, so we wrap them as
// $imported$<method>$<hex> to keep every stored hash single-column and
// self-dispatching — no separate scheme column, hence no schema migration.
const importedPrefix = "$imported$"

// VerifyIdentify checks password against a stored hash that may originate from
// a foreign IAM. It dispatches on the hash's self-describing prefix:
//
//	$argon2id$…             native, no rehash needed
//	$argon2i$…              foreign Argon2i → rehash
//	$2a$/$2b$/$2y$…         bcrypt → rehash
//	$imported$sha256$<hex>  unsalted digest envelope (see EncodeForeignHash) → rehash
//
// It returns needsRehash=true whenever a successful match came from anything
// other than the native argon2id scheme, so the caller can transparently
// upgrade the stored hash to argon2id on the next successful login.
//
// This is distinct from Verify, which stays strict argon2id and is used for
// OrionAuth-issued secrets (client secrets, MFA recovery codes) that must
// never accept a foreign scheme.
func (h *Argon2Hasher) VerifyIdentify(password, stored string) (ok bool, needsRehash bool, err error) {
	switch {
	case strings.HasPrefix(stored, "$argon2id$"):
		ok, err = h.Verify(password, stored)
		return ok, false, err
	case strings.HasPrefix(stored, "$argon2i$"):
		ok, err = verifyArgon2i(password, stored)
		return ok, true, err
	case strings.HasPrefix(stored, "$2a$"),
		strings.HasPrefix(stored, "$2b$"),
		strings.HasPrefix(stored, "$2y$"):
		err = bcrypt.CompareHashAndPassword([]byte(stored), []byte(password))
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, true, nil
		}
		if err != nil {
			return false, true, err
		}
		return true, true, nil
	case strings.HasPrefix(stored, importedPrefix):
		ok, err = verifyImportedDigest(password, stored)
		return ok, true, err
	default:
		return false, false, ErrUnsupportedScheme
	}
}

// verifyArgon2i mirrors Verify but uses the Argon2i KDF (argon2.Key) instead of
// Argon2id (argon2.IDKey). The PHC envelope is structurally identical, so the
// existing decodeHash handles parsing.
func verifyArgon2i(password, stored string) (bool, error) {
	salt, hash, params, err := decodeHash(stored)
	if err != nil {
		return false, err
	}
	other := argon2.Key([]byte(password), salt, params.iterations, params.memory, params.parallelism, uint32(len(hash)))
	return subtle.ConstantTimeCompare(hash, other) == 1, nil
}

// EncodeForeignHash wraps an unsalted hex digest from a foreign IAM into the
// $imported$<method>$<hex> envelope VerifyIdentify understands. method is the
// lowercase digest name (sha256, sha1, md5); hexDigest is the hex-encoded hash
// of the raw password as the source system stored it.
func EncodeForeignHash(method, hexDigest string) (string, error) {
	method = strings.ToLower(method)
	switch method {
	case "sha256", "sha1", "md5":
	default:
		return "", ErrUnsupportedScheme
	}
	if _, err := hex.DecodeString(hexDigest); err != nil {
		return "", ErrInvalidHash
	}
	return importedPrefix + method + "$" + strings.ToLower(hexDigest), nil
}

func verifyImportedDigest(password, stored string) (bool, error) {
	parts := strings.Split(stored, "$")
	// ["", "imported", method, hex]
	if len(parts) != 4 {
		return false, ErrInvalidHash
	}
	method, want := parts[2], parts[3]

	var got string
	switch method {
	case "sha256":
		sum := sha256.Sum256([]byte(password))
		got = hex.EncodeToString(sum[:])
	case "sha1":
		sum := sha1.Sum([]byte(password))
		got = hex.EncodeToString(sum[:])
	case "md5":
		sum := md5.Sum([]byte(password))
		got = hex.EncodeToString(sum[:])
	default:
		return false, ErrUnsupportedScheme
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(strings.ToLower(want))) == 1, nil
}
