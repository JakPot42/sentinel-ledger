//! Signing records with Ed25519. docs/SPEC.md section 7.6.
//!
//! The private key is a file holding 64 hexadecimal characters: the 32-byte seed of
//! RFC 8032. It lives outside the journal's directory. The matching public key is in the
//! machine's configuration file, where the gate and the verifier read it.

use std::fs;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};

/// Read the private key. On Unix the file must not be readable by anyone but its owner.
pub fn load_key(path: &Path) -> Result<SigningKey, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).map_err(|e| format!("key file {}: {e}", path.display()))?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "key file {} is readable by other users (mode {:o}); it must be readable by its owner only",
                path.display(),
                mode & 0o777
            ));
        }
    }
    let text = fs::read_to_string(path).map_err(|e| format!("key file {}: {e}", path.display()))?;
    let bytes = hex::decode(text.trim()).map_err(|_| "the key file is not hexadecimal".to_string())?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| "the key file does not hold 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Make a new key, write it to a file that must not exist yet, and return the public key.
pub fn generate(path: &Path) -> Result<String, String> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("no random numbers from the operating system: {e}"))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| format!("key file {}: {e}", path.display()))?;
    writeln!(file, "{}", hex::encode(seed)).map_err(|e| format!("key file {}: {e}", path.display()))?;
    Ok(public_hex(&SigningKey::from_bytes(&seed)))
}

pub fn public_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

/// The signature over `text`, as 128 hexadecimal characters.
pub fn sign(key: &SigningKey, text: &str) -> String {
    hex::encode(key.sign(text.as_bytes()).to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 section 7.1, test 1: the empty message.
    #[test]
    fn rfc_8032_test_vector_1() {
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap().try_into().unwrap();
        let key = SigningKey::from_bytes(&seed);
        assert_eq!(public_hex(&key), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert_eq!(
            sign(&key, ""),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn a_generated_key_loads_and_an_existing_file_is_not_overwritten() {
        let path = std::env::temp_dir().join(format!("sl-key-test-{}.key", std::process::id()));
        let _ = fs::remove_file(&path);
        let public = generate(&path).unwrap();
        assert_eq!(public_hex(&load_key(&path).unwrap()), public);
        assert!(generate(&path).is_err());
        let _ = fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("sl-key-open-{}.key", std::process::id()));
        let _ = fs::remove_file(&path);
        generate(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_key(&path).unwrap_err().contains("readable by other users"));
        let _ = fs::remove_file(&path);
    }
}
