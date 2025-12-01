use std::fmt;

/// Errors that can occur when working with JWT/JWKS
#[derive(Debug)]
pub enum Error {
    /// Token format is invalid (not 3 parts separated by dots)
    InvalidToken,
    /// Token signature verification failed
    InvalidSignature,
    /// Base64 decoding failed
    InvalidBase64,
    /// JSON parsing failed
    InvalidJson(String),
    /// RSA operation failed
    Rsa(rsa::Error),
    /// PKCS8 encoding/decoding error
    Pkcs8(rsa::pkcs8::Error),
    /// SPKI encoding/decoding error
    Spki(rsa::pkcs8::spki::Error),
    /// Unsupported algorithm
    UnsupportedAlgorithm(String),
    /// Key not found in JWKS
    KeyNotFound(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidToken => write!(f, "invalid token format"),
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::InvalidBase64 => write!(f, "invalid base64 encoding"),
            Error::InvalidJson(msg) => write!(f, "invalid JSON: {}", msg),
            Error::Rsa(e) => write!(f, "RSA error: {}", e),
            Error::Pkcs8(e) => write!(f, "PKCS8 error: {}", e),
            Error::Spki(e) => write!(f, "SPKI error: {}", e),
            Error::UnsupportedAlgorithm(alg) => write!(f, "unsupported algorithm: {}", alg),
            Error::KeyNotFound(kid) => write!(f, "key not found: {}", kid),
        }
    }
}

impl std::error::Error for Error {}

impl From<rsa::Error> for Error {
    fn from(e: rsa::Error) -> Self {
        Error::Rsa(e)
    }
}

impl From<rsa::pkcs8::Error> for Error {
    fn from(e: rsa::pkcs8::Error) -> Self {
        Error::Pkcs8(e)
    }
}

impl From<rsa::pkcs8::spki::Error> for Error {
    fn from(e: rsa::pkcs8::spki::Error) -> Self {
        Error::Spki(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::InvalidJson(e.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(_: base64::DecodeError) -> Self {
        Error::InvalidBase64
    }
}

pub type Result<T> = std::result::Result<T, Error>;
