//! Encryption and the keys that undo it.
//!
//! Every value is encrypted with `age` to its env's X25519 recipient. Nothing here is home-made
//! cryptography: `age` does the encrypting, and this file only decides where each env's identity
//! (its private key) is kept.
//!
//! - **macOS Keychain** (the default on a Mac): a generic password, service `shtum.<vault id>`,
//!   account `<env>`. The Keychain's own access control applies on top: another program asking
//!   for the item, `security find-generic-password` included, gets a system prompt.
//! - **Files** (`SHTUM_KEYRING=file`, and the only choice off macOS): `$SHTUM_HOME/identities/<env>.key`,
//!   mode 0600, outside the vault directory so pushing the vault never pushes a key.

use crate::vault::{Vault, make_private_dir, write_atomic};
use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::str::FromStr;
use zeroize::Zeroizing;

pub enum Keyring {
    #[cfg(target_os = "macos")]
    Keychain {
        service: String,
    },
    File {
        dir: PathBuf,
    },
}

impl Keyring {
    pub fn for_vault(v: &Vault) -> Keyring {
        let wants_file = std::env::var("SHTUM_KEYRING").is_ok_and(|k| k == "file");
        #[cfg(target_os = "macos")]
        if !wants_file {
            return Keyring::Keychain {
                service: format!("shtum.{}", v.config.id),
            };
        }
        let _ = wants_file;
        Keyring::File {
            dir: v.home.join("identities"),
        }
    }

    pub fn is_file(&self) -> bool {
        matches!(self, Keyring::File { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            #[cfg(target_os = "macos")]
            Keyring::Keychain { service } => format!("macOS Keychain (service {service})"),
            Keyring::File { dir } => format!("files in {}", dir.display()),
        }
    }

    pub fn store(&self, env: &str, identity: &str) -> Result<()> {
        match self {
            #[cfg(target_os = "macos")]
            Keyring::Keychain { service } => security_framework::passwords::set_generic_password(
                service,
                env,
                identity.as_bytes(),
            )
            .with_context(|| format!("saving the {env} key to the Keychain")),
            Keyring::File { dir } => {
                make_private_dir(dir)?;
                write_atomic(&dir.join(format!("{env}.key")), identity.as_bytes(), 0o600)
            }
        }
    }

    pub fn load(&self, env: &str) -> Result<Zeroizing<String>> {
        let bytes = match self {
            #[cfg(target_os = "macos")]
            Keyring::Keychain { service } => {
                security_framework::passwords::get_generic_password(service, env).with_context(
                    || format!("reading the {env} key from the Keychain (service {service})"),
                )?
            }
            Keyring::File { dir } => std::fs::read(dir.join(format!("{env}.key")))
                .with_context(|| format!("no key for {env} in {}", dir.display()))?,
        };
        let text = String::from_utf8(bytes).context("the stored key is not text")?;
        Ok(Zeroizing::new(text.trim().to_string()))
    }
}

/// A new identity, as the text form age writes (`AGE-SECRET-KEY-1…`), and its recipient.
pub fn generate() -> (Zeroizing<String>, String) {
    let id = age::x25519::Identity::generate();
    let recipient = id.to_public().to_string();
    (
        Zeroizing::new(id.to_string().expose_secret().to_string()),
        recipient,
    )
}

pub fn encrypt(recipient: &str, value: &[u8]) -> Result<String> {
    let r = age::x25519::Recipient::from_str(recipient)
        .map_err(|e| anyhow::anyhow!("bad recipient in shtum.toml: {e}"))?;
    age::encrypt_and_armor(&r, value).context("encrypting")
}

pub fn decrypt(identity: &str, armored: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let id = age::x25519::Identity::from_str(identity)
        .map_err(|e| anyhow::anyhow!("bad stored key: {e}"))?;
    let plain = age::decrypt(&id, armored)
        .context("decrypting — the stored key does not open this value")?;
    Ok(Zeroizing::new(plain))
}

/// A short salted hash, so two copies of a value can be compared without showing either.
pub fn fingerprint(salt: &str, value: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update([0u8]);
    h.update(value);
    hex::encode(h.finalize())[..12].to_string()
}

/// The identity for an env, after asking the person if the env is protected — every time.
pub fn unlock(v: &Vault, ring: &Keyring, env: &str, why: &str) -> Result<Zeroizing<String>> {
    v.recipient(env)?;
    if v.is_protected(env) {
        crate::presence::confirm(&format!("shtum: {why} ({env})"), ring.is_file())?;
    }
    ring.load(env)
}

pub fn open_with(v: &Vault, identity: &str, name: &str, env: &str) -> Result<Zeroizing<Vec<u8>>> {
    let armored = v.read_value(name, env)?;
    let plain = decrypt(identity, &armored)?;
    if plain.is_empty() {
        bail!("{name} in {env} is empty");
    }
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_round_trips_and_only_its_own_key_opens_it() {
        let (id, rcpt) = generate();
        let (other, _) = generate();
        let ct = encrypt(&rcpt, b"re_live_123").unwrap();
        assert!(ct.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
        assert!(!ct.contains("re_live_123"));
        assert_eq!(&decrypt(&id, ct.as_bytes()).unwrap()[..], b"re_live_123");
        assert!(decrypt(&other, ct.as_bytes()).is_err());
    }

    #[test]
    fn fingerprints_depend_on_the_salt() {
        assert_eq!(fingerprint("a", b"x"), fingerprint("a", b"x"));
        assert_ne!(fingerprint("a", b"x"), fingerprint("b", b"x"));
        assert_eq!(fingerprint("a", b"x").len(), 12);
    }
}
