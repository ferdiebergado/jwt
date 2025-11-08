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

	token, err := jwt.CreateJWT(claims, []byte(key), time.Minute)
	if err != nil {
		t.Fatalf("CreateJWT() = %v", err)
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

			token, err := jwt.CreateJWT(claims, tt.secret, time.Minute)
			if err != nil {
				if tt.wantErr != nil {
					return
				}
				t.Fatalf("CreateJWT() = %v", err)
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

func base64URLEncode(b []byte) string {
	return strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(base64Encode(b)), "=")
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
