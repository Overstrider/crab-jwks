# crab-jwt

A minimal, secure JWT/JWKS library for Rust with RS256 support.

[![Crates.io](https://img.shields.io/crates/v/crab-jwt.svg)](https://crates.io/crates/crab-jwt)
[![Documentation](https://docs.rs/crab-jwt/badge.svg)](https://docs.rs/crab-jwt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **JWT Creation & Verification** - Sign and verify tokens using RS256 (RSA-SHA256)
- **JWKS Support** - Generate and parse JSON Web Key Sets for key distribution
- **Key Management** - Generate RSA key pairs or import from PEM format
- **Builder Pattern** - Fluent API for constructing tokens
- **Minimal Dependencies** - Only essential, audited crates
- **Type Safe** - Leverage Rust's type system for correctness

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
crab-jwt = "0.1"
```

## Quick Start

```rust
use crab_jwt::{Jwt, KeyPair};

// Generate RSA key pair
let keys = KeyPair::generate()?;

// Create a signed JWT
let token = Jwt::builder()
    .subject("user123")
    .issuer("my-app")
    .claim("role", "admin")
    .expiration_in(3600) // 1 hour
    .sign(&keys.private)?;

// Verify and decode the token
let claims = Jwt::verify(&token, &keys.public)?;
assert_eq!(claims.sub, Some("user123".to_string()));
```

## Usage

### Creating Tokens

Use the builder pattern to construct JWT claims:

```rust
use crab_jwt::{Jwt, KeyPair};

let keys = KeyPair::generate()?;

let token = Jwt::builder()
    .subject("user-id-123")           // sub claim
    .issuer("https://auth.example.com") // iss claim
    .audience("https://api.example.com") // aud claim
    .expiration_in(3600)              // exp: now + 1 hour
    .issued_now()                     // iat: current timestamp
    .not_before(1234567890)           // nbf claim
    .jwt_id("unique-token-id")        // jti claim
    .claim("role", "admin")           // custom claim
    .claim("permissions", vec!["read", "write"]) // custom claim
    .sign(&keys.private)?;
```

### Verifying Tokens

```rust
use crab_jwt::{Jwt, KeyPair};

let claims = Jwt::verify(&token, &public_key)?;

// Access standard claims
println!("Subject: {:?}", claims.sub);
println!("Issuer: {:?}", claims.iss);

// Access custom claims
let role: Option<String> = claims.get("role");
```

### Time Validation

Time validation is **opt-in**, giving you full control:

```rust
let claims = Jwt::verify(&token, &public_key)?;

// Check expiration
if claims.is_expired() {
    return Err("Token has expired");
}

// Check both exp and nbf
if !claims.is_valid_time() {
    return Err("Token is not valid at this time");
}
```

### Key Management

**Generate new keys:**

```rust
use crab_jwt::KeyPair;

let keys = KeyPair::generate()?;
```

**Export to PEM:**

```rust
let private_pem = keys.to_private_pem()?;
let public_pem = keys.to_public_pem()?;

// Save to files, environment variables, etc.
```

**Import from PEM:**

```rust
use crab_jwt::{KeyPair, PublicKeyExt};
use crab_jwt::RsaPublicKey;

// Import private key (derives public key automatically)
let keys = KeyPair::from_private_pem(&private_pem)?;

// Import public key only
let public_key = RsaPublicKey::from_pem(&public_pem)?;
```

### JWKS (JSON Web Key Set)

JWKS allows you to publish public keys for token verification:

**Generate JWKS:**

```rust
use crab_jwt::{Jwks, KeyPair};

let keys = KeyPair::generate()?;

// Create JWKS with a key ID
let jwks = Jwks::from_public_key(&keys.public, "key-2024-01")?;

// Serialize to JSON for your /.well-known/jwks.json endpoint
let json = jwks.to_json();
```

**Multiple keys (for key rotation):**

```rust
let mut jwks = Jwks::new();
jwks.add_key(&current_key.public, "key-2024-02")?;
jwks.add_key(&previous_key.public, "key-2024-01")?;
```

**Fetch and use JWKS:**

```rust
use crab_jwt::{Jwt, Jwks};

// Parse JWKS from JSON (e.g., fetched from HTTP)
let jwks = Jwks::from_json(&jwks_json)?;

// Get key by ID (from JWT header's "kid" claim)
let public_key = jwks.get_key("key-2024-01")?;

// Verify token
let claims = Jwt::verify(&token, &public_key)?;
```

## API Reference

### `Jwt`

| Method | Description |
|--------|-------------|
| `Jwt::builder()` | Create a new JWT builder |
| `Jwt::verify(token, key)` | Verify token and return claims |

### `JwtBuilder`

| Method | Description |
|--------|-------------|
| `.subject(sub)` | Set the subject claim |
| `.issuer(iss)` | Set the issuer claim |
| `.audience(aud)` | Set the audience claim |
| `.expiration(timestamp)` | Set expiration (Unix timestamp) |
| `.expiration_in(seconds)` | Set expiration relative to now |
| `.issued_at(timestamp)` | Set issued-at timestamp |
| `.issued_now()` | Set issued-at to current time |
| `.not_before(timestamp)` | Set not-before timestamp |
| `.jwt_id(jti)` | Set unique token ID |
| `.claim(key, value)` | Add custom claim |
| `.sign(private_key)` | Sign and return token string |

### `Claims`

| Method | Description |
|--------|-------------|
| `.is_expired()` | Check if token has expired |
| `.is_valid_time()` | Check exp and nbf validity |
| `.get::<T>(key)` | Get custom claim value |

### `Jwks`

| Method | Description |
|--------|-------------|
| `Jwks::new()` | Create empty JWKS |
| `Jwks::from_public_key(key, kid)` | Create JWKS with one key |
| `Jwks::from_json(json)` | Parse JWKS from JSON |
| `.add_key(key, kid)` | Add a key to the set |
| `.get_key(kid)` | Get key by ID |
| `.first_key()` | Get the first key |
| `.to_json()` | Serialize to JSON |

### `KeyPair`

| Method | Description |
|--------|-------------|
| `KeyPair::generate()` | Generate new 2048-bit RSA key pair |
| `KeyPair::from_private_pem(pem)` | Import from PEM string |
| `.to_private_pem()` | Export private key to PEM |
| `.to_public_pem()` | Export public key to PEM |

## Error Handling

All fallible operations return `Result<T, crab_jwt::Error>`:

```rust
use crab_jwt::Error;

match Jwt::verify(&token, &public_key) {
    Ok(claims) => println!("Valid token for {:?}", claims.sub),
    Err(Error::InvalidSignature) => println!("Signature verification failed"),
    Err(Error::InvalidToken) => println!("Malformed token"),
    Err(Error::UnsupportedAlgorithm(alg)) => println!("Unsupported: {}", alg),
    Err(e) => println!("Error: {}", e),
}
```

## Security

- Uses the audited `rsa` crate for cryptographic operations
- RS256 (RSA-PKCS#1 v1.5 with SHA-256) algorithm
- 2048-bit RSA keys by default
- No unsafe code

## License

MIT License - see [LICENSE](LICENSE) for details.
