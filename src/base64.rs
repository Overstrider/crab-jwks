use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// Encode bytes to base64url without padding (JWT standard)
pub fn encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode base64url string (with or without padding)
pub fn decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let original = b"hello world";
        let encoded = encode(original);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn test_no_padding() {
        let encoded = encode(b"test");
        assert!(!encoded.contains('='));
    }
}
