//! The vault on disk: its config, each secret's metadata, and its encrypted value.
//!
//! Layout under `$SHTUM_HOME` (default `~/.shtum`):
//!
//! ```text
//! vault/                     safe to keep in a private git repo
//!   shtum.toml                id, salt, which envs are protected, each env's public recipient
//!   secrets/<env>/<NAME>.toml  metadata — plaintext, agents read and edit it
//!   secrets/<env>/<NAME>.age   the value, age-encrypted to that env's recipient
//!   docs/<name>.md           free-form notes about providers, runbooks, limits
//! identities/                only with SHTUM_KEYRING=file (tests, Linux); never in the vault
//! ```
//!
//! Nothing in `vault/` can decrypt anything. The identities that can live in the macOS
//! Keychain, so the directory can be backed up, diffed and pushed without exposing a value.

use anyhow::{Context, Result, bail};
use chrono::{Local, NaiveDate};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("SHTUM_HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(h);
    }
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join(".shtum")
}

pub fn today() -> NaiveDate {
    Local::now().date_naive()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    pub id: String,
    pub salt: String,
    /// Envs whose values need the person present (Touch ID or password) to decrypt.
    #[serde(default)]
    pub protected: Vec<String>,
    /// Whether `shtum hook` refuses agents reading `.env` files directly.
    #[serde(default = "yes")]
    pub guard_dotenv: bool,
    /// Each env's age public key. Encrypting needs only this, so adding or rotating a
    /// value never needs the identity — or the person — even for a protected env.
    #[serde(default)]
    pub recipients: BTreeMap<String, String>,
}

fn yes() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Change {
    pub date: NaiveDate,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Everything about a secret except its value. Agents may read and edit all of it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Meta {
    pub name: String,
    pub env: String,
    /// A group to keep related secrets together, such as `stripe`. Only for listing: a folder
    /// changes no name, path or env, so two folders never hold the same secret twice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub used_by: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_every_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rotated: Option<NaiveDate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<NaiveDate>,
    pub created: NaiveDate,
    /// A salted hash prefix of the value, so two copies can be compared without either
    /// being shown. Not a check for a low-entropy secret such as a short password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Fields an agent invents (`shtum meta X region=eu`), kept as strings.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
    /// Every value this secret has held, by fingerprint, newest last.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<Change>,
}

#[derive(Debug, PartialEq)]
pub enum Due {
    Overdue(i64),
    Soon(i64),
    Fine(i64),
    NoPolicy,
}

impl Meta {
    pub fn new(name: &str, env: &str) -> Meta {
        Meta {
            name: name.into(),
            env: env.into(),
            folder: None,
            provider: None,
            description: None,
            dashboard: None,
            owner: None,
            used_by: vec![],
            plan: None,
            limits: None,
            rotate_every_days: None,
            last_rotated: None,
            expires: None,
            created: today(),
            fingerprint: None,
            notes: None,
            extra: BTreeMap::new(),
            history: vec![],
        }
    }

    /// When this secret next needs attention: a rotation falling due or an expiry,
    /// whichever comes first.
    pub fn next_due(&self) -> Option<NaiveDate> {
        let rotation = self
            .rotate_every_days
            .map(|d| self.last_rotated.unwrap_or(self.created) + chrono::Duration::days(d as i64));
        match (rotation, self.expires) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub fn due(&self, on: NaiveDate, within_days: i64) -> Due {
        match self.next_due() {
            None => Due::NoPolicy,
            Some(d) => {
                let left = (d - on).num_days();
                if left < 0 {
                    Due::Overdue(-left)
                } else if left <= within_days {
                    Due::Soon(left)
                } else {
                    Due::Fine(left)
                }
            }
        }
    }

    /// Set one field from text, as `shtum meta` and the MCP server do. Fields the vault
    /// maintains itself refuse, so an agent cannot rewrite a secret's history.
    pub fn set_field(&mut self, key: &str, value: &str) -> Result<()> {
        let text = || (!value.trim().is_empty()).then(|| value.trim().to_string());
        let date = || -> Result<Option<NaiveDate>> {
            if value.trim().is_empty() {
                return Ok(None);
            }
            NaiveDate::parse_from_str(value.trim(), "%Y-%m-%d")
                .map(Some)
                .with_context(|| format!("{key} must be a date like 2026-12-31"))
        };
        match key {
            "provider" => self.provider = text(),
            "description" => self.description = text(),
            "dashboard" => self.dashboard = text(),
            "owner" => self.owner = text(),
            "plan" => self.plan = text(),
            "limits" => self.limits = text(),
            "notes" => self.notes = text(),
            "folder" => {
                let f = value.trim();
                if !f.is_empty() && !valid_folder(f) {
                    bail!("{f:?} is not a valid folder — lowercase letters, digits and dashes");
                }
                self.folder = text();
            }
            "used_by" => {
                self.used_by = value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            "rotate_every_days" | "rotate_every" => {
                let v = value.trim().trim_end_matches('d');
                self.rotate_every_days = if v.is_empty() {
                    None
                } else {
                    Some(
                        v.parse()
                            .context("rotate_every_days must be a number of days, like 90")?,
                    )
                }
            }
            "last_rotated" => self.last_rotated = date()?,
            "expires" => self.expires = date()?,
            "name" | "env" | "created" | "fingerprint" | "history" | "extra" => {
                bail!("{key} is maintained by shtum and cannot be set")
            }
            other => {
                if !valid_field(other) {
                    bail!("a custom field name is lowercase letters, digits and underscores");
                }
                if value.trim().is_empty() {
                    self.extra.remove(other);
                } else {
                    self.extra.insert(other.into(), value.trim().into());
                }
            }
        }
        Ok(())
    }
}

/// A secret's name is the environment variable it becomes, which is also what keeps it
/// from naming a path.
pub fn valid_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_')
        && s.len() <= 128
        && c.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

pub fn valid_env(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch.is_ascii_lowercase())
        && s.len() <= 32
        && c.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

/// A folder is a label for grouping, never part of a path.
pub fn valid_folder(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch.is_ascii_lowercase() || ch.is_ascii_digit())
        && s.len() <= 32
        && c.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

pub fn valid_doc(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch.is_ascii_lowercase() || ch.is_ascii_digit())
        && s.len() <= 64
        && !s.contains("..")
        && c.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || "-_.".contains(ch))
}

fn valid_field(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 48
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

pub struct Vault {
    pub home: PathBuf,
    pub config: Config,
}

impl Vault {
    pub fn root(home: &Path) -> PathBuf {
        home.join("vault")
    }

    pub fn exists(home: &Path) -> bool {
        Self::root(home).join("shtum.toml").is_file()
    }

    pub fn open() -> Result<Vault> {
        Self::open_at(&home())
    }

    pub fn open_at(home: &Path) -> Result<Vault> {
        let path = Self::root(home).join("shtum.toml");
        let text = fs::read_to_string(&path)
            .with_context(|| format!("no vault at {} — run `shtum init`", home.display()))?;
        let config =
            toml::from_str(&text).with_context(|| format!("reading {}", path.display()))?;
        Ok(Vault {
            home: home.to_path_buf(),
            config,
        })
    }

    pub fn create(home: &Path) -> Result<Vault> {
        if Self::exists(home) {
            bail!("a vault already exists at {}", home.display());
        }
        let config = Config {
            id: random_hex(8)?,
            salt: random_hex(16)?,
            protected: vec![],
            guard_dotenv: true,
            recipients: BTreeMap::new(),
        };
        let v = Vault {
            home: home.to_path_buf(),
            config,
        };
        make_private_dir(&v.home)?;
        make_private_dir(&v.vault_dir())?;
        make_private_dir(&v.vault_dir().join("secrets"))?;
        make_private_dir(&v.vault_dir().join("docs"))?;
        v.save_config()?;
        Ok(v)
    }

    pub fn vault_dir(&self) -> PathBuf {
        Self::root(&self.home)
    }

    pub fn save_config(&self) -> Result<()> {
        let text = toml::to_string_pretty(&self.config)?;
        write_atomic(&self.vault_dir().join("shtum.toml"), text.as_bytes(), 0o644)
    }

    pub fn is_protected(&self, env: &str) -> bool {
        self.config.protected.iter().any(|e| e == env)
    }

    pub fn envs(&self) -> Vec<String> {
        self.config.recipients.keys().cloned().collect()
    }

    pub fn recipient(&self, env: &str) -> Result<&str> {
        self.config
            .recipients
            .get(env)
            .map(String::as_str)
            .with_context(|| {
                format!(
                    "no env named {env:?} — `shtum env add {env}` creates one (envs: {})",
                    self.envs().join(", ")
                )
            })
    }

    fn env_dir(&self, env: &str) -> PathBuf {
        self.vault_dir().join("secrets").join(env)
    }

    fn meta_path(&self, name: &str, env: &str) -> PathBuf {
        self.env_dir(env).join(format!("{name}.toml"))
    }

    pub fn value_path(&self, name: &str, env: &str) -> PathBuf {
        self.env_dir(env).join(format!("{name}.age"))
    }

    pub fn check(name: &str, env: &str) -> Result<()> {
        if !valid_name(name) {
            bail!(
                "{name:?} is not a valid name — use an environment variable name like RESEND_API_KEY"
            );
        }
        if !valid_env(env) {
            bail!("{env:?} is not a valid env — lowercase letters, digits and dashes");
        }
        Ok(())
    }

    pub fn has(&self, name: &str, env: &str) -> bool {
        valid_name(name) && valid_env(env) && self.meta_path(name, env).is_file()
    }

    /// Whether a value is stored. A secret declared with `shtum add` has a record and no value
    /// until `shtum set` fills it.
    pub fn has_value(&self, name: &str, env: &str) -> bool {
        valid_name(name) && valid_env(env) && self.value_path(name, env).is_file()
    }

    pub fn load(&self, name: &str, env: &str) -> Result<Meta> {
        Self::check(name, env)?;
        let path = self.meta_path(name, env);
        let text =
            fs::read_to_string(&path).with_context(|| format!("no secret {name} in {env}"))?;
        toml::from_str(&text).with_context(|| format!("reading {}", path.display()))
    }

    pub fn save(&self, meta: &Meta) -> Result<()> {
        Self::check(&meta.name, &meta.env)?;
        make_private_dir(&self.env_dir(&meta.env))?;
        let text = toml::to_string_pretty(meta)?;
        write_atomic(
            &self.meta_path(&meta.name, &meta.env),
            text.as_bytes(),
            0o644,
        )
    }

    pub fn write_value(&self, name: &str, env: &str, armored: &str) -> Result<()> {
        Self::check(name, env)?;
        make_private_dir(&self.env_dir(env))?;
        write_atomic(&self.value_path(name, env), armored.as_bytes(), 0o600)
    }

    pub fn read_value(&self, name: &str, env: &str) -> Result<Vec<u8>> {
        Self::check(name, env)?;
        fs::read(self.value_path(name, env))
            .with_context(|| format!("{name} in {env} has no value stored"))
    }

    pub fn remove(&self, name: &str, env: &str) -> Result<()> {
        Self::check(name, env)?;
        let _ = fs::remove_file(self.value_path(name, env));
        fs::remove_file(self.meta_path(name, env))
            .with_context(|| format!("no secret {name} in {env}"))
    }

    /// Every secret, optionally in one env, sorted by env then name.
    pub fn list(&self, env: Option<&str>) -> Result<Vec<Meta>> {
        let mut out = vec![];
        let envs: Vec<String> = match env {
            Some(e) => vec![e.to_string()],
            None => self.envs(),
        };
        for e in envs {
            let dir = self.env_dir(&e);
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            let mut names: Vec<String> = entries
                .flatten()
                .filter_map(|d| {
                    d.file_name()
                        .to_str()?
                        .strip_suffix(".toml")
                        .map(String::from)
                })
                .filter(|n| valid_name(n))
                .collect();
            names.sort();
            for n in names {
                out.push(self.load(&n, &e)?);
            }
        }
        Ok(out)
    }

    /// The envs a name exists in, for commands that were not told which one.
    pub fn envs_of(&self, name: &str) -> Vec<String> {
        self.envs()
            .into_iter()
            .filter(|e| self.has(name, e))
            .collect()
    }

    pub fn doc_path(&self, name: &str) -> Result<PathBuf> {
        if !valid_doc(name) {
            bail!("{name:?} is not a valid doc name — lowercase letters, digits, dashes and dots");
        }
        Ok(self.vault_dir().join("docs").join(format!("{name}.md")))
    }

    pub fn docs(&self) -> Result<Vec<String>> {
        let mut names: Vec<String> = fs::read_dir(self.vault_dir().join("docs"))?
            .flatten()
            .filter_map(|d| {
                d.file_name()
                    .to_str()?
                    .strip_suffix(".md")
                    .map(String::from)
            })
            .filter(|n| valid_doc(n))
            .collect();
        names.sort();
        Ok(names)
    }

    pub fn write_doc(&self, name: &str, text: &str) -> Result<()> {
        write_atomic(&self.doc_path(name)?, text.as_bytes(), 0o644)
    }
}

pub fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| anyhow::anyhow!("no randomness available: {e}"))?;
    Ok(hex::encode(buf))
}

pub fn make_private_dir(p: &Path) -> Result<()> {
    fs::create_dir_all(p).with_context(|| format!("creating {}", p.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write beside the target and rename over it, so a crash leaves the old file or the new
/// one and never half of either. The mode is set before any byte is written.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().context("path has no parent")?;
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("shtum"),
        std::process::id()
    ));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let _ = fs::remove_file(&tmp);
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn names_cannot_name_a_path() {
        assert!(valid_name("RESEND_API_KEY"));
        assert!(valid_name("_x1"));
        for bad in ["", "1A", "A-B", "../X", "A/B", "A.B", "A B"] {
            assert!(!valid_name(bad), "{bad}");
        }
        assert!(valid_env("prod") && valid_env("dev-2"));
        for bad in ["", "Prod", "../p", "p/q", "-p"] {
            assert!(!valid_env(bad), "{bad}");
        }
        assert!(valid_folder("stripe") && valid_folder("ai-2"));
        for bad in ["", "Stripe", "../x", "a/b", "a.b", "-x", "a b"] {
            assert!(!valid_folder(bad), "{bad}");
        }
        assert!(valid_doc("resend") && valid_doc("stripe.limits"));
        for bad in ["", "../x", "a/b", "..", "a..b", "A"] {
            assert!(!valid_doc(bad), "{bad}");
        }
    }

    #[test]
    fn due_takes_the_earlier_of_rotation_and_expiry() {
        let mut m = Meta::new("K", "prod");
        m.created = d("2026-01-01");
        assert_eq!(m.due(d("2026-10-04"), 14), Due::NoPolicy);
        m.rotate_every_days = Some(90);
        assert_eq!(m.next_due(), Some(d("2026-04-01")));
        assert!(matches!(m.due(d("2026-10-04"), 14), Due::Overdue(_)));
        m.last_rotated = Some(d("2026-09-30"));
        assert_eq!(m.due(d("2026-10-04"), 14), Due::Fine(86));
        m.expires = Some(d("2026-10-10"));
        assert_eq!(m.due(d("2026-10-04"), 14), Due::Soon(6));
    }

    #[test]
    fn set_field_refuses_what_shtum_maintains() {
        let mut m = Meta::new("K", "dev");
        m.set_field("rotate_every", "90d").unwrap();
        assert_eq!(m.rotate_every_days, Some(90));
        m.set_field("used_by", "my-api, my-web").unwrap();
        assert_eq!(m.used_by, vec!["my-api", "my-web"]);
        m.set_field("region", "eu").unwrap();
        assert_eq!(m.extra["region"], "eu");
        assert!(m.set_field("fingerprint", "x").is_err());
        assert!(m.set_field("history", "x").is_err());
        assert!(m.set_field("expires", "soon").is_err());
        m.set_field("provider", "").unwrap();
        assert_eq!(m.provider, None);
        m.set_field("folder", "stripe").unwrap();
        assert_eq!(m.folder.as_deref(), Some("stripe"));
        assert!(m.set_field("folder", "../etc").is_err());
        m.set_field("folder", "").unwrap();
        assert_eq!(m.folder, None);
    }

    #[test]
    fn meta_round_trips_through_toml() {
        let mut m = Meta::new("K", "dev");
        m.provider = Some("Resend".into());
        m.extra.insert("region".into(), "eu".into());
        m.history.push(Change {
            date: today(),
            fingerprint: "abc".into(),
            note: None,
        });
        let text = toml::to_string_pretty(&m).unwrap();
        let back: Meta = toml::from_str(&text).unwrap();
        assert_eq!(m, back);
    }
}
