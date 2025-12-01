use rsa::{
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    sha2::Sha256,
    signature::{SignatureEncoding, Signer, Verifier},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::base64;
use crate::claims::{current_timestamp, Claims};
use crate::error::{Error, Result};

/// JWT header
#[derive(Debug, Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            alg: "RS256".to_string(),
            typ: "JWT".to_string(),
        }
    }
}

/// JWT operations
pub struct Jwt;

impl Jwt {
    /// Create a new JWT builder
    pub fn builder() -> JwtBuilder {
        JwtBuilder::new()
    }

    /// Verify a JWT token and return the claims
    pub fn verify(token: &str, public_key: &RsaPublicKey) -> Result<Claims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidToken);
        }

        let header_bytes = base64::decode(parts[0])?;
        let header: Header = serde_json::from_slice(&header_bytes)?;

        if header.alg != "RS256" {
            return Err(Error::UnsupportedAlgorithm(header.alg));
        }

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature_bytes = base64::decode(parts[2])?;

        let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());
        let signature = Signature::try_from(signature_bytes.as_slice())
            .map_err(|_| Error::InvalidSignature)?;

        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| Error::InvalidSignature)?;

        let payload_bytes = base64::decode(parts[1])?;
        let claims: Claims = serde_json::from_slice(&payload_bytes)?;

        Ok(claims)
    }
}

/// Builder for creating JWT tokens
pub struct JwtBuilder {
    claims: Claims,
}

impl JwtBuilder {
    /// Create a new builder with empty claims
    pub fn new() -> Self {
        Self {
            claims: Claims::new(),
        }
    }

    /// Set the subject claim
    pub fn subject(mut self, sub: impl Into<String>) -> Self {
        self.claims.sub = Some(sub.into());
        self
    }

    /// Set the issuer claim
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.claims.iss = Some(iss.into());
        self
    }

    /// Set the audience claim
    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.claims.aud = Some(aud.into());
        self
    }

    /// Set the expiration time (Unix timestamp)
    pub fn expiration(mut self, exp: u64) -> Self {
        self.claims.exp = Some(exp);
        self
    }

    /// Set expiration to current time + seconds
    pub fn expiration_in(mut self, seconds: u64) -> Self {
        self.claims.exp = Some(current_timestamp() + seconds);
        self
    }

    /// Set the issued at time (Unix timestamp)
    pub fn issued_at(mut self, iat: u64) -> Self {
        self.claims.iat = Some(iat);
        self
    }

    /// Set issued at to current time
    pub fn issued_now(mut self) -> Self {
        self.claims.iat = Some(current_timestamp());
        self
    }

    /// Set the not before time (Unix timestamp)
    pub fn not_before(mut self, nbf: u64) -> Self {
        self.claims.nbf = Some(nbf);
        self
    }

    /// Set the JWT ID
    pub fn jwt_id(mut self, jti: impl Into<String>) -> Self {
        self.claims.jti = Some(jti.into());
        self
    }

    /// Add a custom claim
    pub fn claim(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.claims.custom.insert(key.into(), value.into());
        self
    }

    /// Sign the JWT with a private key and return the token string
    pub fn sign(self, private_key: &RsaPrivateKey) -> Result<String> {
        let header = Header::default();
        let header_json = serde_json::to_string(&header)?;
        let header_b64 = base64::encode(header_json.as_bytes());

        let payload_json = serde_json::to_string(&self.claims)?;
        let payload_b64 = base64::encode(payload_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let signing_key = SigningKey::<Sha256>::new(private_key.clone());
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = base64::encode(&signature.to_bytes());

        Ok(format!("{}.{}", signing_input, signature_b64))
    }
}

impl Default for JwtBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn test_sign_and_verify() {
        let keys = KeyPair::generate().unwrap();

        let token = Jwt::builder()
            .subject("user123")
            .issuer("test")
            .claim("role", "admin")
            .expiration_in(3600)
            .sign(&keys.private)
            .unwrap();

        let claims = Jwt::verify(&token, &keys.public).unwrap();

        assert_eq!(claims.sub, Some("user123".to_string()));
        assert_eq!(claims.iss, Some("test".to_string()));
        assert_eq!(claims.get::<String>("role"), Some("admin".to_string()));
    }

    #[test]
    fn test_invalid_signature() {
        let keys1 = KeyPair::generate().unwrap();
        let keys2 = KeyPair::generate().unwrap();

        let token = Jwt::builder()
            .subject("user123")
            .sign(&keys1.private)
            .unwrap();

        let result = Jwt::verify(&token, &keys2.public);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_invalid_token_format() {
        let keys = KeyPair::generate().unwrap();

        let result = Jwt::verify("invalid.token", &keys.public);
        assert!(matches!(result, Err(Error::InvalidToken)));
    }
}
