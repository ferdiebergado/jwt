# jwt

[![Test](https://github.com/ferdiebergado/jwt/actions/workflows/go.yml/badge.svg)](https://github.com/ferdiebergado/jwt/actions/workflows/go.yml) [![CodeQL](https://github.com/ferdiebergado/jwt/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/ferdiebergado/jwt/actions/workflows/github-code-scanning/codeql) [![Go Report Card](https://goreportcard.com/badge/github.com/ferdiebergado/jwt)](https://goreportcard.com/report/github.com/ferdiebergado/jwt) [![Go Reference](https://pkg.go.dev/badge/github.com/ferdiebergado/jwt.svg)](https://pkg.go.dev/github.com/ferdiebergado/jwt)

A minimal, **secure**, and **RFC 7519–compliant** `JSON Web Token` implementation for Go.
Supports **HS256 (HMAC-SHA256)** only — no `alg=none` or asymmetric algorithms.

Designed for correctness, simplicity, and long-term maintainability.
No dependencies outside the Go standard library.

**Minimal. Secure. Predictable.**

Everything you need for `HS256 JWTs` — nothing you don’t.

---

## ✨ Features

-   ✅ **HS256 only** — prevents algorithm-confusion attacks
-   ✅ **Constant-time signature verification**
-   ✅ **Automatic `iat` / `exp` handling**
-   ✅ **RFC 7519–compliant time validation** (`exp`, `nbf`, `iat`)
-   ✅ **Optional claim validators** (e.g., `aud`, `iss` checks)
-   ✅ **Pure stdlib**, no third-party dependencies

## ⚙️ Design Philosophy

-   Explicit security: avoids dangerous flexibility like multiple algorithms or `none`.
-   Predictable behavior: strict base64 decoding, JSON handling, and claim checks.
-   Stable core: relies only on Go’s standard library — no external `crypto` packages.

---

## 📦 Installation

```bash
go get github.com/ferdiebergado/jwt
```

## 🚀 Usage

### Creating a JWT

```go
const secretKey = "supersecretlongkeythatshouldbe32bytesmin"

claims := &jwt.JWTClaims{
    Iss: "my-app",
    Sub: "user123",
    Aud: "my-client",
    Exp: time.Now().Add(1 * time.Hour).Unix(),
}

token, err := jwt.Create(claims, []byte(secretKey))
if err != nil {
    log.Fatal(err)
}

fmt.Println("Token:", token)
```

### Verifying a JWT

```go
const leeway = 30 // adjust based on your clock skew in seconds

var parsed jwt.JWTClaims
err = jwt.Verify(token, []byte(secretKey), &parsed, leeway)
if err != nil {
    log.Fatal(err)
}

fmt.Println(parsed.Sub)
```

### Validating Claims

`Verify` accepts any number of `validators` and use it to validate the claims.

A `validator` is just a function that accepts a `JWTClaims` and returns an error.

```go
type ClaimValidator func(c *JWTClaims) error
```

The package has a couple of built-in `validators`:

-   **RequireIssuer** for validating the `issuer` claim
-   **RequireAudience** for validating the `audience` claim

Example:

```go
validators := []jwt.ClaimValidator{
    jwt.RequireIssuer(claims.Iss),
    jwt.RequireAudience(claims.Aud),
}

var parsed jwt.JWTClaims
err = jwt.Verify(token, []byte(secretKey), &parsed, leeway, validators...)
```

## 🧪 Testing

```go
go test ./...
```

## 🔐 Security Notes

-   Only `HS256` is supported (`HMAC-SHA256`).
-   Always use a sufficiently random secret key (≥ 256 bits recommended).
-   Keep keys out of source control and rotate them periodically.
-   Tokens are verified in constant time to prevent timing attacks.
-   Expiration and "not before" checks follow `RFC 7519` strictly.
