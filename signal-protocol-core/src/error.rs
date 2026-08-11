//! Error handling for Signal Protocol core

#[derive(Clone, Debug)]
pub enum SignalError {
    KeyGeneration(String),
    SignatureVerification(String),
    KeyExchange(String),
    Encryption(String),
    Decryption(String),
    KeyDerivation(String),
    Serialization(String),
    InvalidInput(String),
}

impl std::fmt::Display for SignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignalError::KeyGeneration(s) => write!(f, "Key generation failed: {}", s),
            SignalError::SignatureVerification(s) => {
                write!(f, "Signature verification failed: {}", s)
            }
            SignalError::KeyExchange(s) => write!(f, "Key exchange failed: {}", s),
            SignalError::Encryption(s) => write!(f, "Encryption failed: {}", s),
            SignalError::Decryption(s) => write!(f, "Decryption failed: {}", s),
            SignalError::KeyDerivation(s) => write!(f, "Key derivation failed: {}", s),
            SignalError::Serialization(s) => write!(f, "Serialization failed: {}", s),
            SignalError::InvalidInput(s) => write!(f, "Invalid input: {}", s),
        }
    }
}

impl std::error::Error for SignalError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_all_variants() {
        let cases = [
            (
                SignalError::KeyGeneration("k".into()),
                "Key generation failed: k",
            ),
            (
                SignalError::SignatureVerification("s".into()),
                "Signature verification failed: s",
            ),
            (SignalError::KeyExchange("x".into()), "Key exchange failed: x"),
            (SignalError::Encryption("e".into()), "Encryption failed: e"),
            (SignalError::Decryption("d".into()), "Decryption failed: d"),
            (
                SignalError::KeyDerivation("h".into()),
                "Key derivation failed: h",
            ),
            (
                SignalError::Serialization("z".into()),
                "Serialization failed: z",
            ),
            (SignalError::InvalidInput("i".into()), "Invalid input: i"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
            let _: &dyn std::error::Error = &err;
        }
    }
}
