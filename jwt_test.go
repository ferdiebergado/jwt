package jwt_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ferdiebergado/jwt"
)

const key = "supersecretlongkeythatshouldbe32bytesmin"

func TestCreateAndVerifySuccess(t *testing.T) {
	t.Parallel()

	claims := &jwt.JWTClaims{
		Iss: "issuer-1",
		Aud: []string{"aud-1"},
		Sub: "user-123",
	}

	token, err := jwt.Create(claims, []byte(key), time.Minute)
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}

	validators := []jwt.ClaimValidator{
		jwt.RequireIssuer(claims.Iss),
		jwt.RequireAudience(claims.Aud),
	}

	var parsed jwt.JWTClaims
	err = jwt.Verify(token, []byte(key), &parsed, 30, validators...)
	if err != nil {
		t.Fatalf("VerifyHS256 should not return an error: %v", err)
	}

	if parsed.Sub != claims.Sub {
		t.Errorf("parsed.Sub = %q, want: %q", parsed.Sub, claims.Sub)
	}

	if parsed.Iat == nil {
		t.Errorf("parsed.Iat = %v, want: non-nil", parsed.Iat)
	}

	if parsed.Exp == nil {
		t.Errorf("parsed.Exp = %v, want: non-nil", parsed.Exp)
	}
}

func TestCreateAndVerifyJWTFails(t *testing.T) {
	t.Parallel()

	now := time.Now().Unix()
	exp := now - 31

	tests := []struct {
		name       string
		modify     func(token *string)
		setup      func(c *jwt.JWTClaims)
		secret     []byte
		validators []jwt.ClaimValidator
		wantErr    error
	}{
		{
			name: "expired token",
			setup: func(c *jwt.JWTClaims) {
				c.Exp = &exp
			},
			secret:  []byte(key),
			wantErr: jwt.ErrExpired,
		},
		{
			name: "not yet valid (nbf in future)",
			setup: func(c *jwt.JWTClaims) {
				c.Nbf = now + 100
			},
			secret:  []byte(key),
			wantErr: jwt.ErrNotYetValid,
		},
		{
			name:   "invalid signature (tampered payload)",
			secret: []byte(key),
			modify: func(token *string) {
				parts := strings.Split(*token, ".")
				parts[1] = "eyJzdWIiOiJ0YW1wZXJlZCJ9" // fake base64 payload
				*token = strings.Join(parts, ".")
			},
			wantErr: jwt.ErrInvalidSig,
		},
		{
			name:   "unsupported alg in header",
			secret: []byte(key),
			modify: func(token *string) {
				// Replace alg:HS256 → alg:RS256 in header
				parts := strings.Split(*token, ".")
				headerJSON := `{"alg":"RS256","typ":"JWT"}`
				parts[0] = base64URLEncode([]byte(headerJSON))
				*token = strings.Join(parts, ".")
			},
			wantErr: jwt.ErrAlgUnsupported,
		},
		{
			name:   "issuer mismatch",
			secret: []byte(key),
			validators: []jwt.ClaimValidator{
				jwt.RequireIssuer("expected-issuer"),
			},
			wantErr: jwt.ErrIssuerMismatch,
		},
		{
			name:   "audience mismatch",
			secret: []byte(key),
			validators: []jwt.ClaimValidator{
				jwt.RequireAudience([]string{"expected-aud"}),
			},
			wantErr: jwt.ErrAudienceMismatch,
		},
		{
			name:    "secret too short",
			secret:  []byte("weak"),
			wantErr: jwt.ErrMalformed,
		},
		{
			name:    "malformed token",
			secret:  []byte(key),
			modify:  func(t *string) { *t = "onlytwo.parts" },
			wantErr: jwt.ErrMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			claims := &jwt.JWTClaims{
				Iss: "issuer-1",
				Aud: []string{"aud-1"},
				Sub: "user-123",
			}
			if tt.setup != nil {
				tt.setup(claims)
			}

			token, err := jwt.Create(claims, tt.secret, time.Minute)
			if err != nil {
				if tt.wantErr != nil {
					return
				}
				t.Fatalf("Create() = %v", err)
			}

			if tt.modify != nil {
				tt.modify(&token)
			}

			var parsed jwt.JWTClaims
			err = jwt.Verify(token, tt.secret, &parsed, 30, tt.validators...)
			if err == nil {
				t.Fatalf("expected error %v, got nil", tt.wantErr)
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("jwt.VerifyHS256(token, tc.secret, &parsed, tc.validators...) = %v, want: %v", err, tt.wantErr)
			}
		})
	}
}

// --- FUZZ TEST ---

// FuzzVerify uses fuzzing to find crashes or unexpected behavior in the Verify function.
func FuzzVerify(f *testing.F) {
	// Define the stable secret key used by all tests
	const stableSecret = "a_very_long_and_stable_secret_key_for_fuzzing_purposes_12345678"

	// 1. Add known valid tokens and deliberately malformed inputs to the corpus
	goodClaims := &jwt.JWTClaims{
		Iss: "fuzz-server",
		Sub: "fuzz-user",
		Aud: []string{"fuzz-client"},
	}
	validToken, err := jwt.Create(goodClaims, []byte(stableSecret), time.Hour)
	if err != nil {
		f.Fatalf("Failed to create seed token: %v", err)
	}

	// Seed corpus with a valid token (expected success)
	f.Add(validToken, stableSecret)

	// Seed corpus with malformed tokens (expected failures: ErrMalformed, ErrInvalidSig, etc.)
	f.Add("abc.def.ghi", stableSecret)                                  // Malformed Base64 parts
	f.Add("..", stableSecret)                                           // Not enough parts
	f.Add(strings.Repeat("a", 1000), stableSecret)                      // Very long string
	f.Add(validToken+"extra", stableSecret)                             // Token with extra segment
	f.Add(validToken, "incorrect_secret")                               // Valid token, wrong secret (should fail sig check)
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.c2ln", stableSecret) // alg=none attempt

	f.Fuzz(func(t *testing.T, token string, secret string) {
		// Prepare inputs for the Verify function
		var claims jwt.JWTClaims
		secretKey := []byte(secret)
		leeway := int64(30) // Use a fixed leeway for the fuzzing run

		// Avoid panics on zero-length secret keys, which is already handled by the CreateJWT mock
		if len(secretKey) < 1 {
			return
		}

		// The goal of fuzzing is *not* to make Verify succeed, but to ensure it
		// does not crash (panic) and returns a controlled, expected error.
		err := jwt.Verify(token, secretKey, &claims, leeway)

		// Check for specific, expected, controlled errors
		if err != nil {
			// Ensure all errors are recognized errors from the package.
			// Fuzzing should not cause unexpected runtime errors (panics).
			switch {
			case errors.Is(err, jwt.ErrMalformed):
			case errors.Is(err, jwt.ErrAlgUnsupported):
			case errors.Is(err, jwt.ErrInvalidSig):
			case strings.Contains(err.Error(), "decode header"): // Base64 decode errors
			case strings.Contains(err.Error(), "unmarshal header"): // JSON unmarshal errors
			case strings.Contains(err.Error(), "decode claims"): // Base64 decode errors
			case strings.Contains(err.Error(), "unmarshal claims"): // JSON unmarshal errors
			case errors.Is(err, jwt.ErrExpired):
			case errors.Is(err, jwt.ErrNotYetValid):
			default:
				// If an error is returned that we haven't categorized, it's worth logging,
				// but the primary fuzz goal is preventing crashes.
				t.Logf("Unexpected error type: %v", err)
			}
			return
		}

		// If verification succeeds, we must ensure the claims are reasonable.
		// This verifies that unexpected input did not lead to a successful bypass.
		if claims.Iss == "" {
			t.Errorf("Verify unexpectedly succeeded with empty issuer for token: %s", token)
		}
		// Add more logical checks here if a token unexpectedly verifies successfully
	})
}

func base64URLEncode(b []byte) string {
	return strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(base64Encode(b)), "=")
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
