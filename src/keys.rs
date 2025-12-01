use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    RsaPrivateKey, RsaPublicKey,
};

use crate::error::Result;

/// RSA key pair for signing and verifying JWTs
pub struct KeyPair {
    pub private: RsaPrivateKey,
    pub public: RsaPublicKey,
}

impl KeyPair {
    /// Generate a new RSA 2048-bit key pair
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048)?;
        let public = RsaPublicKey::from(&private);
        Ok(Self { private, public })
    }

    /// Import key pair from a private key PEM string
    pub fn from_private_pem(pem: &str) -> Result<Self> {
        let private = RsaPrivateKey::from_pkcs8_pem(pem)?;
        let public = RsaPublicKey::from(&private);
        Ok(Self { private, public })
    }

    /// Export private key to PEM format
    pub fn to_private_pem(&self) -> Result<String> {
        Ok(self.private.to_pkcs8_pem(LineEnding::LF)?.to_string())
    }

    /// Export public key to PEM format
    pub fn to_public_pem(&self) -> Result<String> {
        Ok(self.public.to_public_key_pem(LineEnding::LF)?)
    }
}

/// Extension trait for importing public keys from PEM
pub trait PublicKeyExt {
    fn from_pem(pem: &str) -> Result<RsaPublicKey>;
}

impl PublicKeyExt for RsaPublicKey {
    fn from_pem(pem: &str) -> Result<RsaPublicKey> {
        Ok(RsaPublicKey::from_public_key_pem(pem)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_export() {
        let keys = KeyPair::generate().unwrap();
        let private_pem = keys.to_private_pem().unwrap();
        let public_pem = keys.to_public_pem().unwrap();

        assert!(private_pem.contains("BEGIN PRIVATE KEY"));
        assert!(public_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn test_import_roundtrip() {
        let keys = KeyPair::generate().unwrap();
        let private_pem = keys.to_private_pem().unwrap();

        let imported = KeyPair::from_private_pem(&private_pem).unwrap();
        assert_eq!(
            keys.public.to_public_key_pem(LineEnding::LF).unwrap(),
            imported.public.to_public_key_pem(LineEnding::LF).unwrap()
        );
    }
}
