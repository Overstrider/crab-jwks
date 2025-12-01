//! # crab-jwt
//!
//! Minimal JWT/JWKS library for Rust with RS256 support.
//!
//! ## Features
//!
//! - Generate and verify JWT tokens with RS256 (RSA-SHA256)
//! - Generate and parse JWKS (JSON Web Key Set)
//! - RSA key generation and PEM import/export
//! - Builder pattern for creating tokens
//! - Manual time validation (optional)
//!
//! ## Quick Start
//!
//! ```rust
//! use crab_jwt::{Jwt, Jwks, KeyPair};
//!
//! // Generate RSA key pair
//! let keys = KeyPair::generate().unwrap();
//!
//! // Create a JWT token
//! let token = Jwt::builder()
//!     .subject("user123")
//!     .issuer("my-app")
//!     .claim("role", "admin")
//!     .expiration_in(3600)  // expires in 1 hour
//!     .sign(&keys.private)
//!     .unwrap();
//!
//! // Verify the token
//! let claims = Jwt::verify(&token, &keys.public).unwrap();
//! assert_eq!(claims.sub, Some("user123".to_string()));
//!
//! // Check if token is expired (optional)
//! if claims.is_expired() {
//!     println!("Token has expired!");
//! }
//!
//! // Generate JWKS for public distribution
//! let jwks = Jwks::from_public_key(&keys.public, "key-1").unwrap();
//! println!("{}", jwks.to_json());
//! ```
//!
//! ## Key Management
//!
//! ```rust
//! use crab_jwt::{KeyPair, PublicKeyExt};
//! use rsa::RsaPublicKey;
//!
//! // Generate new keys
//! let keys = KeyPair::generate().unwrap();
//!
//! // Export to PEM
//! let private_pem = keys.to_private_pem().unwrap();
//! let public_pem = keys.to_public_pem().unwrap();
//!
//! // Import from PEM
//! let imported = KeyPair::from_private_pem(&private_pem).unwrap();
//! let public_key = RsaPublicKey::from_pem(&public_pem).unwrap();
//! ```
//!
//! ## JWKS Usage
//!
//! ```rust
//! use crab_jwt::{Jwt, Jwks, KeyPair};
//!
//! let keys = KeyPair::generate().unwrap();
//!
//! // Create JWKS with multiple keys
//! let mut jwks = Jwks::new();
//! jwks.add_key(&keys.public, "key-1").unwrap();
//!
//! // Serialize to JSON (for HTTP endpoint)
//! let json = jwks.to_json();
//!
//! // Parse JWKS from JSON
//! let parsed = Jwks::from_json(&json).unwrap();
//!
//! // Get key by ID
//! let public_key = parsed.get_key("key-1").unwrap();
//!
//! // Verify token with JWKS key
//! let token = Jwt::builder()
//!     .subject("user")
//!     .sign(&keys.private)
//!     .unwrap();
//!
//! let claims = Jwt::verify(&token, &public_key).unwrap();
//! ```

mod base64;
mod claims;
mod error;
mod jwks;
mod jwt;
mod keys;

pub use claims::Claims;
pub use error::{Error, Result};
pub use jwks::{Jwk, Jwks};
pub use jwt::{Jwt, JwtBuilder};
pub use keys::{KeyPair, PublicKeyExt};

// Re-export rsa types for convenience
pub use rsa::{RsaPrivateKey, RsaPublicKey};
