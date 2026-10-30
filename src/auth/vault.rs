//! Encrypts each secret on its own before it goes into the database. The key
//! is in a file next to the database, so a copy of the database alone gives
//! nothing away.

use std::fs;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::error::{Result, WebdavError};

const KEY_FILE: &str = "vault.key";
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

pub struct Vault {
    key: [u8; KEY_BYTES],
}

pub struct Sealed {
    pub nonce: Vec<u8>,
    pub text: Vec<u8>,
}

fn failed(what: &str, file: &Path, why: impl std::fmt::Display) -> WebdavError {
    WebdavError::new(format!("cannot {what} {}: {why}", file.display()))
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|e| WebdavError::new(format!("no random numbers from the system: {e}")))?;
    Ok(bytes)
}

fn write_private(file: &Path, content: &[u8]) -> Result<()> {
    fs::write(file, content).map_err(|e| failed("write", file, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(file, fs::Permissions::from_mode(0o600))
            .map_err(|e| failed("protect", file, e))?;
    }
    Ok(())
}

impl Vault {
    /// Opens the vault in `data`, with a new key on first use.
    pub fn open(data: &Path) -> Result<Self> {
        fs::create_dir_all(data).map_err(|e| failed("create", data, e))?;
        let file = data.join(KEY_FILE);
        let key = match fs::read(&file) {
            Ok(stored) => stored
                .try_into()
                .map_err(|_| failed("use", &file, "it is not a vault key"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = random::<KEY_BYTES>()?;
                write_private(&file, &key)?;
                key
            }
            Err(e) => return Err(failed("read", &file, e)),
        };
        Ok(Self { key })
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.key))
    }

    /// `owner` is sealed in with the secret, so a row copied to another owner
    /// does not open.
    pub fn seal(&self, owner: &str, secret: &str) -> Result<Sealed> {
        let nonce = random::<NONCE_BYTES>()?;
        let plain = Payload {
            msg: secret.as_bytes(),
            aad: owner.as_bytes(),
        };
        let text = self
            .cipher()
            .encrypt(Nonce::from_slice(&nonce), plain)
            .map_err(|_| WebdavError::new("cannot encrypt a secret"))?;
        Ok(Sealed {
            nonce: nonce.to_vec(),
            text,
        })
    }

    pub fn open_secret(&self, owner: &str, sealed: &Sealed) -> Result<String> {
        let damaged = || WebdavError::new("a stored secret is damaged or from another server");
        if sealed.nonce.len() != NONCE_BYTES {
            return Err(damaged());
        }
        let payload = Payload {
            msg: &sealed.text,
            aad: owner.as_bytes(),
        };
        let plain = self
            .cipher()
            .decrypt(Nonce::from_slice(&sealed.nonce), payload)
            .map_err(|_| damaged())?;
        String::from_utf8(plain).map_err(|_| damaged())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn folder(name: &str) -> PathBuf {
        let folder =
            std::env::temp_dir().join(format!("webdav-vault-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&folder);
        folder
    }

    #[test]
    fn a_secret_opens_with_its_owner_and_survives_a_restart() {
        let folder = folder("restart");
        let sealed = Vault::open(&folder)
            .expect("vault")
            .seal("mine", "a link")
            .expect("seal");
        let reopened = Vault::open(&folder).expect("vault");
        assert_eq!(
            reopened.open_secret("mine", &sealed).expect("open"),
            "a link"
        );
        assert!(reopened.open_secret("theirs", &sealed).is_err());
        fs::remove_dir_all(folder).expect("clean up");
    }

    #[test]
    fn another_key_or_a_changed_row_does_not_open() {
        let folder = folder("tampered");
        let vault = Vault::open(&folder).expect("vault");
        let sealed = vault.seal("mine", "a link").expect("seal");
        let changed = Sealed {
            nonce: vec![0; NONCE_BYTES],
            text: sealed.text.clone(),
        };
        assert!(vault.open_secret("mine", &changed).is_err());

        fs::remove_file(folder.join(KEY_FILE)).expect("remove key");
        let other = Vault::open(&folder).expect("vault with a new key");
        assert!(other.open_secret("mine", &sealed).is_err());
        fs::remove_dir_all(folder).expect("clean up");
    }

    #[test]
    fn the_secret_is_not_readable_when_sealed() {
        let folder = folder("readable");
        let sealed = Vault::open(&folder)
            .expect("vault")
            .seal("mine", "a link")
            .expect("seal");
        assert!(!String::from_utf8_lossy(&sealed.text).contains("a link"));
        fs::remove_dir_all(folder).expect("clean up");
    }
}
