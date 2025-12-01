use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Standard JWT claims with support for custom claims
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (who the token refers to)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Issuer (who created the token)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Audience (who the token is intended for)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// Expiration time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,

    /// Issued at (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,

    /// Not before (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,

    /// JWT ID (unique identifier)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, Value>,
}

impl Claims {
    /// Create empty claims
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if the token has expired based on `exp` claim
    pub fn is_expired(&self) -> bool {
        match self.exp {
            Some(exp) => current_timestamp() > exp,
            None => false,
        }
    }

    /// Check if the token is valid based on time claims (`exp` and `nbf`)
    pub fn is_valid_time(&self) -> bool {
        let now = current_timestamp();

        if let Some(exp) = self.exp {
            if now > exp {
                return false;
            }
        }

        if let Some(nbf) = self.nbf {
            if now < nbf {
                return false;
            }
        }

        true
    }

    /// Get a custom claim value
    pub fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.custom
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }
}

/// Get current Unix timestamp
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_expired() {
        let mut claims = Claims::new();
        assert!(!claims.is_expired());

        claims.exp = Some(0);
        assert!(claims.is_expired());

        claims.exp = Some(current_timestamp() + 3600);
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_is_valid_time() {
        let mut claims = Claims::new();
        assert!(claims.is_valid_time());

        claims.exp = Some(0);
        assert!(!claims.is_valid_time());

        claims.exp = Some(current_timestamp() + 3600);
        claims.nbf = Some(current_timestamp() + 3600);
        assert!(!claims.is_valid_time());

        claims.nbf = Some(current_timestamp() - 3600);
        assert!(claims.is_valid_time());
    }

    #[test]
    fn test_custom_claims() {
        let mut claims = Claims::new();
        claims
            .custom
            .insert("role".to_string(), Value::String("admin".to_string()));

        let role: Option<String> = claims.get("role");
        assert_eq!(role, Some("admin".to_string()));
    }
}
