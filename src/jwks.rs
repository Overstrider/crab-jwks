use rsa::{traits::PublicKeyParts, BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};

use crate::base64;
use crate::error::{Error, Result};

/// JSON Web Key Set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// JSON Web Key (RSA)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (always "RSA")
    pub kty: String,

    /// Public key use ("sig" for signature)
    #[serde(rename = "use")]
    pub use_: String,

    /// Key ID
    pub kid: String,

    /// Algorithm (always "RS256")
    pub alg: String,

    /// RSA modulus (base64url)
    pub n: String,

    /// RSA exponent (base64url)
    pub e: String,
}

impl Jwks {
    /// Create a new empty JWKS
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Create JWKS from a public key
    pub fn from_public_key(key: &RsaPublicKey, kid: impl Into<String>) -> Result<Self> {
        let jwk = Jwk::from_public_key(key, kid)?;
        Ok(Self { keys: vec![jwk] })
    }

    /// Add a key to the JWKS
    pub fn add_key(&mut self, key: &RsaPublicKey, kid: impl Into<String>) -> Result<()> {
        let jwk = Jwk::from_public_key(key, kid)?;
        self.keys.push(jwk);
        Ok(())
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Get a public key by key ID
    pub fn get_key(&self, kid: &str) -> Result<RsaPublicKey> {
        self.keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| Error::KeyNotFound(kid.to_string()))?
            .to_public_key()
    }

    /// Get the first key (useful when there's only one)
    pub fn first_key(&self) -> Result<RsaPublicKey> {
        self.keys
            .first()
            .ok_or_else(|| Error::KeyNotFound("no keys".to_string()))?
            .to_public_key()
    }
}

impl Default for Jwks {
    fn default() -> Self {
        Self::new()
    }
}

impl Jwk {
    /// Create JWK from RSA public key
    pub fn from_public_key(key: &RsaPublicKey, kid: impl Into<String>) -> Result<Self> {
        Ok(Self {
            kty: "RSA".to_string(),
            use_: "sig".to_string(),
            kid: kid.into(),
            alg: "RS256".to_string(),
            n: base64::encode(&key.n().to_bytes_be()),
            e: base64::encode(&key.e().to_bytes_be()),
        })
    }

    /// Convert JWK to RSA public key
    pub fn to_public_key(&self) -> Result<RsaPublicKey> {
        let n_bytes = base64::decode(&self.n)?;
        let e_bytes = base64::decode(&self.e)?;

        let n = BigUint::from_bytes_be(&n_bytes);
        let e = BigUint::from_bytes_be(&e_bytes);

        Ok(RsaPublicKey::new(n, e)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn test_jwks_roundtrip() {
        let keys = KeyPair::generate().unwrap();

        let jwks = Jwks::from_public_key(&keys.public, "test-key").unwrap();
        let json = jwks.to_json();

        let parsed = Jwks::from_json(&json).unwrap();
        let recovered_key = parsed.get_key("test-key").unwrap();

        assert_eq!(keys.public.n(), recovered_key.n());
        assert_eq!(keys.public.e(), recovered_key.e());
    }

    #[test]
    fn test_jwks_multiple_keys() {
        let keys1 = KeyPair::generate().unwrap();
        let keys2 = KeyPair::generate().unwrap();

        let mut jwks = Jwks::new();
        jwks.add_key(&keys1.public, "key-1").unwrap();
        jwks.add_key(&keys2.public, "key-2").unwrap();

        assert_eq!(jwks.keys.len(), 2);

        let key1 = jwks.get_key("key-1").unwrap();
        let key2 = jwks.get_key("key-2").unwrap();

        assert_eq!(keys1.public.n(), key1.n());
        assert_eq!(keys2.public.n(), key2.n());
    }

    #[test]
    fn test_key_not_found() {
        let jwks = Jwks::new();
        let result = jwks.get_key("nonexistent");
        assert!(matches!(result, Err(Error::KeyNotFound(_))));
    }
}
