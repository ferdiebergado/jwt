// Package jwt provides a minimal, secure, and RFC 7519–compliant implementation
// of JSON Web Tokens (JWT) using the HS256 (HMAC-SHA256) algorithm.
//
// It focuses on correctness, simplicity, and clarity rather than feature
// breadth. Only symmetric key signing (HMAC) is supported to minimize attack
// surface and external dependencies.
//
// Typical usage involves creating a token with CreateJWT() and verifying it
// with VerifyJWT(). The CreateJWT function automatically sets standard claims
// such as "iat" (issued at) and "exp" (expiration time) if not already provided.
//
// The VerifyJWT function validates the signature, decodes claims, and enforces
// time-based constraints such as expiration ("exp") and not-before ("nbf").
// Optional ClaimValidator interfaces can be used to perform application-specific
// checks such as validating the token’s issuer ("iss") and audience ("aud").
//
// Example usage:
//
//	claims := &jwt.JWTClaims{
//		Iss: "my-app",
//		Sub: "user123",
//		Aud: "my-client",
//	}
//
//	token, err := jwt.CreateJWT(claims, []byte("mysecret"))
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	var parsed jwt.JWTClaims
//	valid, err := jwt.VerifyJWT(token, []byte("mysecret"), &parsed)
//	if err != nil || !valid {
//		log.Fatal("invalid or expired token")
//	}
//
//	fmt.Println("verified claims:", parsed)
//
// This package avoids known JWT vulnerabilities such as the "alg=none" bypass,
// weak key guessing, and type confusion attacks by:
//   - Hardcoding HS256 as the only supported algorithm
//   - Using constant-time signature comparison
//   - Strictly enforcing RFC 7519 time validations
//   - Disallowing tokens with malformed base64 or JSON segments
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	AlgHS256 = "HS256"
	TypJWT   = "JWT"
)

// JWTHeader represents the JOSE header.
type JWTHeader struct {
	Alg string `json:"alg"`           // Algorithm
	Typ string `json:"typ,omitempty"` // Type
}

// JWTClaims represents standard JWT claims (RFC 7519 §4.1).
type JWTClaims struct {
	Iss string   `json:"iss,omitempty"` // Issuer
	Sub string   `json:"sub,omitempty"` // Subject
	Aud []string `json:"aud,omitempty"` // Audience
	Exp *int64   `json:"exp,omitempty"` // Expiration time (Unix)
	Nbf int64    `json:"nbf,omitempty"` // Not before (Unix)
	Iat *int64   `json:"iat,omitempty"` // Issued at (Unix)
	Jti string   `json:"jti,omitempty"` // JWT ID
}

// -----------------------------------------------------------------------------
// CreateJWT
// -----------------------------------------------------------------------------

// CreateJWT generates an RFC-compliant HS256 JWT string with optional defaults.
// It sets iat automatically and exp if zero (using expTTL as validity period).
func CreateJWT(claims *JWTClaims, secretKey []byte, expTTL time.Duration) (string, error) {
	if len(secretKey) < 32 {
		return "", errors.New("secret key should at least be 32 bytes)")
	}

	now := time.Now().Unix()

	// Set defaults
	if claims.Iat == nil {
		claims.Iat = &now
	}
	exp := now + int64(expTTL.Seconds())
	if claims.Exp == nil && expTTL > 0 {
		claims.Exp = &exp
	}

	// 1. Header
	header := JWTHeader{Alg: AlgHS256, Typ: TypJWT}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)

	// 2. Claims
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// 3. Signing Input
	signingInput := encodedHeader + "." + encodedClaims

	// 4. Signature
	mac := hmac.New(sha256.New, secretKey)
	_, _ = mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// 5. Final Token
	return signingInput + "." + encodedSignature, nil
}

// -----------------------------------------------------------------------------
// VerifyHS256
// -----------------------------------------------------------------------------

var (
	ErrMalformed        = errors.New("token malformed")
	ErrAlgUnsupported   = errors.New("unsupported alg")
	ErrInvalidSig       = errors.New("invalid signature")
	ErrExpired          = errors.New("token expired")
	ErrNotYetValid      = errors.New("token not yet valid")
	ErrIssuerMismatch   = errors.New("issuer mismatch")
	ErrAudienceMismatch = errors.New("audience mismatch")
)

type ClaimValidator func(c *JWTClaims) error

// Verify verifies an HS256 JWT’s signature, time claims, and optional validators.
func Verify(token string, secretKey []byte, claims *JWTClaims, leeway int64, validators ...ClaimValidator) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrMalformed
	}

	encHeader, encClaims, encSig := parts[0], parts[1], parts[2]
	signingInput := encHeader + "." + encClaims

	// Decode header
	if err := decodeHeader(encHeader); err != nil {
		return fmt.Errorf("decode header: %w", err)
	}

	// Verify signature
	if err := verifySig(secretKey, signingInput, encSig); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}

	// Decode claims
	if err := decodeClaims(encClaims, claims); err != nil {
		return fmt.Errorf("decode claims: %w", err)
	}

	// Check exp/nbf
	if err := checkTime(claims, leeway); err != nil {
		return err
	}

	// Run validators (iss/aud/custom)
	for _, v := range validators {
		if v != nil {
			if err := v(claims); err != nil {
				return fmt.Errorf("claim validator: %w", err)
			}
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// Example Claim Validators
// -----------------------------------------------------------------------------

// RequireIssuer returns a validator that ensures token issuer matches the expected one.
func RequireIssuer(expected string) ClaimValidator {
	return func(c *JWTClaims) error {
		if c.Iss != expected {
			return fmt.Errorf("issuer mismatch: got %q, want %q: %w", c.Iss, expected, ErrIssuerMismatch)
		}
		return nil
	}
}

// RequireAudience returns a validator that ensures token audience matches the expected one.
func RequireAudience(expected []string) ClaimValidator {
	return func(c *JWTClaims) error {
		if !slices.Equal(c.Aud, expected) {
			return fmt.Errorf("audience mismatch: got %q, want %q: %w", c.Aud, expected, ErrAudienceMismatch)
		}

		return nil
	}
}

func decodeHeader(encHeader string) error {
	hb, err := base64.RawURLEncoding.DecodeString(encHeader)
	if err != nil {
		return fmt.Errorf("decode header: %w", err)
	}

	var hdr JWTHeader
	if err = json.Unmarshal(hb, &hdr); err != nil {
		return fmt.Errorf("unmarshal header: %w", err)
	}

	if hdr.Alg != AlgHS256 {
		return ErrAlgUnsupported
	}

	return nil
}

func verifySig(secretKey []byte, signingInput, encSig string) error {
	mac := hmac.New(sha256.New, secretKey)
	if _, err := mac.Write([]byte(signingInput)); err != nil {
		return fmt.Errorf("mac.Write: %w", err)
	}

	expectedSig := mac.Sum(nil)

	actualSig, err := base64.RawURLEncoding.DecodeString(encSig)
	if err != nil {
		return fmt.Errorf("decode sig: %w", err)
	}

	if !hmac.Equal(expectedSig, actualSig) {
		return ErrInvalidSig
	}

	return nil
}

func decodeClaims(encClaims string, claims *JWTClaims) error {
	cb, err := base64.RawURLEncoding.DecodeString(encClaims)
	if err != nil {
		return fmt.Errorf("decode claims: %w", err)
	}

	if err := json.Unmarshal(cb, claims); err != nil {
		return fmt.Errorf("unmarshal claims: %w", err)
	}

	return nil
}

func checkTime(claims *JWTClaims, leeway int64) error {
	now := time.Now().Unix()

	if *claims.Exp > int64(0) && now > *claims.Exp+leeway {
		return ErrExpired
	}

	if claims.Nbf > 0 && now < claims.Nbf-leeway {
		return ErrNotYetValid
	}

	return nil
}
