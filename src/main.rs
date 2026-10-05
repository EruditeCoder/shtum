//! shtum — API keys and what is known about them, for people and the agents working with them.
//!
//! The rule everything here serves: **an agent never sees a value.** Whatever an agent reads is
//! sent to a model and saved in a transcript on disk, so values leave shtum only into a program's
//! environment (`shtum run`) or a deploy target (`shtum fly sync`), and the one command that prints
//! a value (`shtum reveal`) needs a terminal and the person's Touch ID.

mod crypto;
mod dotenv;
mod hook;
mod mcp;
mod ops;
mod presence;
mod redact;
mod run;
mod vault;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use crypto::Keyring;
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use vault::{Change, Meta, Vault, today};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "shtum",
    version,
    about = "API keys and what is known about them — values agents never see"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a vault with a dev env and a protected prod env.
    Init,
    /// Where the vault is, where its keys are kept, and what is in it.
    Status,
    /// Manage envs: add, ls, protect, unprotect.
    #[command(subcommand)]
    Env(EnvCmd),
    /// Declare a secret with no value yet: its record, folder and metadata. `shtum set` fills it.
    Add {
        name: String,
        #[arg(long)]
        env: String,
        /// Group it with related secrets, e.g. stripe.
        #[arg(long)]
        folder: Option<String>,
        /// field=value pairs, as for `shtum meta`.
        fields: Vec<String>,
    },
    /// Store a value, read from a hidden prompt or from stdin. Replacing one records a rotation.
    Set {
        name: String,
        #[arg(long)]
        env: String,
        /// A note for the rotation history, e.g. "rotated after the leak drill".
        #[arg(long)]
        note: Option<String>,
        /// Put it in a folder, e.g. stripe.
        #[arg(long)]
        folder: Option<String>,
    },
    /// Move every key in a .env file into an env, printing names only.
    Import {
        file: PathBuf,
        #[arg(long)]
        env: String,
        /// Replace values that already exist and differ.
        #[arg(long)]
        overwrite: bool,
        /// Only these names (comma-separated).
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// Leave these names out (comma-separated), e.g. PORT,NODE_ENV.
        #[arg(long, value_delimiter = ',')]
        skip: Vec<String>,
    },
    /// Every secret, its provider, rotation status and users.
    Ls {
        #[arg(long)]
        env: Option<String>,
        /// Only this folder.
        #[arg(long)]
        folder: Option<String>,
    },
    /// Everything known about a secret except its value.
    Show {
        name: String,
        #[arg(long)]
        env: Option<String>,
    },
    /// Read or set metadata: shtum meta NAME --env prod provider=Resend rotate_every_days=90
    Meta {
        name: String,
        #[arg(long)]
        env: String,
        /// field=value pairs; an empty value clears the field.
        fields: Vec<String>,
    },
    /// Delete a secret and its record.
    Rm {
        name: String,
        #[arg(long)]
        env: String,
    },
    /// What is overdue or due for rotation or expiry.
    Due {
        #[arg(long, default_value_t = 14)]
        within: i64,
    },
    /// Run a command with secrets in its environment. Output is masked unless it is your terminal.
    Run {
        /// Defaults to the env in the nearest .shtum.toml.
        #[arg(long)]
        env: Option<String>,
        /// Only these names (comma-separated). Defaults to .shtum.toml's list, else the whole env.
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Deploy targets.
    #[command(subcommand)]
    Fly(FlyCmd),
    /// Print one value. A person at a terminal only, after Touch ID.
    Reveal {
        name: String,
        #[arg(long)]
        env: String,
    },
    /// Print an env's private key, to keep a copy somewhere safe. A person only, after Touch ID.
    BackupKey {
        #[arg(long)]
        env: String,
    },
    /// Free-form notes: ls, show NAME, write NAME (from stdin).
    #[command(subcommand)]
    Doc(DocCmd),
    /// The Claude Code PreToolUse hook (reads a tool call on stdin).
    Hook,
    /// Print the settings that install the hook and the MCP server.
    Setup,
    /// The MCP server, over stdio.
    Mcp,
}

#[derive(Subcommand)]
enum EnvCmd {
    Add {
        name: String,
        #[arg(long)]
        protected: bool,
    },
    Ls,
    Protect {
        name: String,
    },
    Unprotect {
        name: String,
    },
}

#[derive(Subcommand)]
enum FlyCmd {
    /// Push an env's secrets to a Fly app with `fly secrets import`.
    Sync {
        #[arg(long)]
        env: String,
        #[arg(long)]
        app: String,
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// Set them without restarting machines.
        #[arg(long)]
        stage: bool,
    },
}

#[derive(Subcommand)]
enum DocCmd {
    Ls,
    Show { name: String },
    Write { name: String },
}

fn main() {
    let cli = Cli::parse();
    if matches!(cli.cmd, Cmd::Hook) {
        hook::main();
        return;
    }
    match dispatch(cli.cmd) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("shtum: {e:#}");
            std::process::exit(1);
        }
    }
}

fn dispatch(cmd: Cmd) -> Result<i32> {
    match cmd {
        Cmd::Init => init(),
        Cmd::Status => status(),
        Cmd::Env(c) => env_cmd(c),
        Cmd::Add {
            name,
            env,
            folder,
            fields,
        } => add(&name, &env, folder.as_deref(), &fields),
        Cmd::Set {
            name,
            env,
            note,
            folder,
        } => set(&name, &env, note, folder.as_deref()),
        Cmd::Import {
            file,
            env,
            overwrite,
            only,
            skip,
        } => import(&file, &env, overwrite, &only, &skip),
        Cmd::Ls { env, folder } => {
            print!(
                "{}",
                ops::list_text(&Vault::open()?, env.as_deref(), folder.as_deref())?
            );
            Ok(0)
        }
        Cmd::Show { name, env } => {
            print!(
                "{}",
                ops::show_text(&Vault::open()?, &name, env.as_deref())?
            );
            Ok(0)
        }
        Cmd::Meta { name, env, fields } => meta(&name, &env, &fields),
        Cmd::Rm { name, env } => rm(&name, &env),
        Cmd::Due { within } => {
            print!("{}", ops::due_text(&Vault::open()?, within)?);
            Ok(0)
        }
        Cmd::Run { env, only, command } => run_cmd(env, only, &command),
        Cmd::Fly(FlyCmd::Sync {
            env,
            app,
            only,
            stage,
        }) => fly_sync(&env, &app, &only, stage),
        Cmd::Reveal { name, env } => reveal(&name, &env),
        Cmd::BackupKey { env } => backup_key(&env),
        Cmd::Doc(c) => doc(c),
        Cmd::Hook => unreachable!(),
        Cmd::Setup => setup(),
        Cmd::Mcp => mcp::serve().map(|_| 0),
    }
}

fn init() -> Result<i32> {
    let home = vault::home();
    let mut v = Vault::create(&home)?;
    let ring = Keyring::for_vault(&v);
    for (env, protected) in [("dev", false), ("prod", true)] {
        add_env(&mut v, &ring, env, protected)?;
    }
    println!("Created a vault at {}", v.vault_dir().display());
    println!("Keys are kept in {}.", ring.describe());
    println!(
        "Envs: dev, and prod (protected — using a prod value needs Touch ID or your password)."
    );
    println!();
    println!("Next:");
    println!("  shtum import path/to/.env --env dev     move existing keys in (prints names only)");
    println!(
        "  shtum backup-key --env prod             keep a copy of each env's key somewhere safe;"
    );
    println!(
        "                                          without it, losing this Mac loses the values"
    );
    println!(
        "  shtum setup                             install the hook and MCP server for agents"
    );
    Ok(0)
}

fn add_env(v: &mut Vault, ring: &Keyring, env: &str, protected: bool) -> Result<()> {
    if !vault::valid_env(env) {
        bail!("{env:?} is not a valid env — lowercase letters, digits and dashes");
    }
    if v.config.recipients.contains_key(env) {
        bail!("env {env} already exists");
    }
    let (identity, recipient) = crypto::generate();
    ring.store(env, &identity)?;
    v.config.recipients.insert(env.into(), recipient);
    if protected && !v.is_protected(env) {
        v.config.protected.push(env.into());
    }
    v.save_config()
}

fn status() -> Result<i32> {
    let home = vault::home();
    if !Vault::exists(&home) {
        println!("No vault at {}. `shtum init` creates one.", home.display());
        return Ok(0);
    }
    let v = Vault::open_at(&home)?;
    let ring = Keyring::for_vault(&v);
    println!("vault     {}", v.vault_dir().display());
    println!("keys      {}", ring.describe());
    for env in v.envs() {
        let n = v.list(Some(&env))?.len();
        let p = if v.is_protected(&env) {
            "protected"
        } else {
            ""
        };
        println!("env       {env:<8} {n:>3} secrets  {p}");
    }
    println!(
        "dotenv guard {}",
        if v.config.guard_dotenv { "on" } else { "off" }
    );
    if let Some((path, p)) = project()? {
        println!(
            "project   {} (env {}, {})",
            path.display(),
            p.env.as_deref().unwrap_or("-"),
            if p.only.is_empty() {
                "all names".to_string()
            } else {
                p.only.join(",")
            }
        );
    }
    Ok(0)
}

fn env_cmd(c: EnvCmd) -> Result<i32> {
    let mut v = Vault::open()?;
    let ring = Keyring::for_vault(&v);
    match c {
        EnvCmd::Add { name, protected } => {
            add_env(&mut v, &ring, &name, protected)?;
            println!(
                "Added env {name}{}.",
                if protected { " (protected)" } else { "" }
            );
        }
        EnvCmd::Ls => {
            for e in v.envs() {
                println!(
                    "{e}{}",
                    if v.is_protected(&e) {
                        "  protected"
                    } else {
                        ""
                    }
                );
            }
        }
        EnvCmd::Protect { name } => {
            v.recipient(&name)?;
            if !v.is_protected(&name) {
                v.config.protected.push(name.clone());
                v.save_config()?;
            }
            println!("{name} is protected.");
        }
        EnvCmd::Unprotect { name } => {
            v.recipient(&name)?;
            presence::confirm(&format!("shtum: stop protecting {name}"), ring.is_file())?;
            v.config.protected.retain(|e| e != &name);
            v.save_config()?;
            println!("{name} is no longer protected.");
        }
    }
    Ok(0)
}

/// Read a value without echoing it: a hidden prompt at a terminal, stdin otherwise.
fn read_value(name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let value = if std::io::stdin().is_terminal() {
        Zeroizing::new(
            rpassword::prompt_password(format!("Value for {name} (hidden): "))?.into_bytes(),
        )
    } else {
        let mut buf = Zeroizing::new(vec![]);
        std::io::stdin().read_to_end(&mut buf)?;
        if buf.ends_with(b"\n") {
            buf.pop();
            if buf.ends_with(b"\r") {
                buf.pop();
            }
        }
        buf
    };
    if value.is_empty() {
        bail!("empty value — nothing stored");
    }
    Ok(value)
}

/// Write one value and its record. Returns what happened, for the caller to report.
fn store(
    v: &Vault,
    name: &str,
    env: &str,
    value: &[u8],
    note: Option<String>,
    overwrite: bool,
) -> Result<&'static str> {
    Vault::check(name, env)?;
    let fp = crypto::fingerprint(&v.config.salt, value);
    let existing = if v.has(name, env) {
        Some(v.load(name, env)?)
    } else {
        None
    };
    let mut m = match existing {
        Some(m) if m.fingerprint.as_deref() == Some(fp.as_str()) => return Ok("unchanged"),
        // declared with `shtum add` and never filled: this is its first value, not a rotation
        Some(m) if m.fingerprint.is_none() && !v.has_value(name, env) => m,
        Some(_) if !overwrite => return Ok("differs — kept the stored value (use --overwrite)"),
        Some(m) => m,
        None => Meta::new(name, env),
    };
    let rotated = m.fingerprint.is_some();
    v.write_value(name, env, &crypto::encrypt(v.recipient(env)?, value)?)?;
    m.fingerprint = Some(fp.clone());
    m.history.push(Change {
        date: today(),
        fingerprint: fp,
        note,
    });
    if rotated {
        m.last_rotated = Some(today());
    }
    v.save(&m)?;
    Ok(if rotated { "rotated" } else { "added" })
}

fn guard_protected_write(v: &Vault, ring: &Keyring, env: &str, what: &str) -> Result<()> {
    if v.is_protected(env) {
        presence::confirm(&format!("shtum: {what} ({env})"), ring.is_file())?;
    }
    Ok(())
}

fn set(name: &str, env: &str, note: Option<String>, folder: Option<&str>) -> Result<i32> {
    let v = Vault::open()?;
    Vault::check(name, env)?;
    v.recipient(env)?;
    if let Some(f) = folder {
        Meta::new(name, env).set_field("folder", f)?;
    }
    let value = read_value(name)?;
    guard_protected_write(&v, &Keyring::for_vault(&v), env, &format!("store {name}"))?;
    let what = store(&v, name, env, &value, note, true)?;
    if let Some(f) = folder {
        ops::update(&v, name, env, &[("folder".into(), f.into())])?;
    }
    println!("{name} in {env}: {what}.");
    if what == "added" {
        println!(
            "Describe it: shtum meta {name} --env {env} provider=… dashboard=… rotate_every_days=90"
        );
    }
    Ok(0)
}

/// Declare a secret without a value: the record an agent or a person can describe now, filled
/// later by `shtum set` at a terminal. Takes no value, so nothing here can carry one.
fn add(name: &str, env: &str, folder: Option<&str>, fields: &[String]) -> Result<i32> {
    let v = Vault::open()?;
    let m = ops::declare(&v, name, env, folder, &field_pairs(fields)?)?;
    println!(
        "Declared {name} in {env}{}, no value yet.",
        m.folder
            .as_deref()
            .map(|f| format!(" (folder {f})"))
            .unwrap_or_default()
    );
    println!("Fill it at your terminal: shtum set {name} --env {env}");
    Ok(0)
}

fn field_pairs(fields: &[String]) -> Result<Vec<(String, String)>> {
    fields
        .iter()
        .map(|f| {
            f.split_once('=')
                .map(|(k, val)| (k.trim().to_string(), val.to_string()))
                .with_context(|| format!("{f:?} should be field=value"))
        })
        .collect()
}

fn import(
    file: &Path,
    env: &str,
    overwrite: bool,
    only: &[String],
    skip: &[String],
) -> Result<i32> {
    let v = Vault::open()?;
    v.recipient(env)?;
    let text = Zeroizing::new(
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?,
    );
    let pairs = dotenv::parse(&text)?;
    guard_protected_write(
        &v,
        &Keyring::for_vault(&v),
        env,
        &format!("import {}", file.display()),
    )?;
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for (name, value) in pairs {
        let value = Zeroizing::new(value);
        if (!only.is_empty() && !only.contains(&name)) || skip.contains(&name) {
            continue;
        }
        let what = if value.is_empty() {
            "empty — skipped"
        } else {
            store(
                &v,
                &name,
                env,
                value.as_bytes(),
                Some(format!("imported from {}", file.display())),
                overwrite,
            )?
        };
        println!("{name:<36} {what}");
        *counts
            .entry(what.split(' ').next().unwrap_or(what))
            .or_default() += 1;
    }
    let summary: Vec<String> = counts.iter().map(|(k, n)| format!("{n} {k}")).collect();
    println!("\n{} in {env}: {}.", file.display(), summary.join(", "));
    println!(
        "The file still holds the values. Once your programs run under `shtum run`, delete it."
    );
    Ok(0)
}

fn meta(name: &str, env: &str, fields: &[String]) -> Result<i32> {
    let v = Vault::open()?;
    if fields.is_empty() {
        print!("{}", ops::show_text(&v, name, Some(env))?);
        return Ok(0);
    }
    let m = ops::update(&v, name, env, &field_pairs(fields)?)?;
    println!("Updated {} in {}.", m.name, m.env);
    Ok(0)
}

fn rm(name: &str, env: &str) -> Result<i32> {
    let v = Vault::open()?;
    v.load(name, env)?;
    guard_protected_write(&v, &Keyring::for_vault(&v), env, &format!("delete {name}"))?;
    v.remove(name, env)?;
    println!("Removed {name} from {env}.");
    Ok(0)
}

#[derive(serde::Deserialize, Default)]
struct Project {
    env: Option<String>,
    #[serde(default)]
    only: Vec<String>,
}

/// The nearest `.shtum.toml` above the working directory: which env and names a project runs with.
fn project() -> Result<Option<(PathBuf, Project)>> {
    let mut dir = std::env::current_dir()?;
    loop {
        let p = dir.join(".shtum.toml");
        if p.is_file() {
            let text = std::fs::read_to_string(&p)?;
            let proj: Project =
                toml::from_str(&text).with_context(|| format!("reading {}", p.display()))?;
            return Ok(Some((p, proj)));
        }
        if !dir.pop() {
            return Ok(None);
        }
    }
}

/// Decrypt the secrets a command asked for, asking the person once if the env is protected.
fn gather(v: &Vault, env: &str, only: &[String], why: &str) -> Result<Vec<(String, run::Value)>> {
    let names: Vec<String> = if only.is_empty() {
        let (filled, declared): (Vec<String>, Vec<String>) = v
            .list(Some(env))?
            .into_iter()
            .map(|m| m.name)
            .partition(|n| v.has_value(n, env));
        if !declared.is_empty() {
            eprintln!(
                "shtum: {} in {env} declared without a value, left out: {}",
                declared.len(),
                declared.join(", ")
            );
        }
        filled
    } else {
        for n in only {
            if !v.has(n, env) {
                bail!("no secret {n} in {env}");
            }
            if !v.has_value(n, env) {
                bail!(
                    "{n} in {env} has no value yet — fill it at your terminal: shtum set {n} --env {env}"
                );
            }
        }
        only.to_vec()
    };
    if names.is_empty() {
        return Ok(vec![]);
    }
    let ring = Keyring::for_vault(v);
    let identity = crypto::unlock(v, &ring, env, why)?;
    names
        .into_iter()
        .map(|n| {
            let val = crypto::open_with(v, &identity, &n, env)?;
            Ok((n, val))
        })
        .collect()
}

fn run_cmd(env: Option<String>, only: Vec<String>, command: &[String]) -> Result<i32> {
    let v = Vault::open()?;
    let proj = project()?.map(|(_, p)| p).unwrap_or_default();
    let env = env
        .or(proj.env)
        .context("which env? pass --env, or put env = \"dev\" in a .shtum.toml")?;
    let only = if only.is_empty() { proj.only } else { only };
    let vars = gather(
        &v,
        &env,
        &only,
        &format!("run {}", command.first().map_or("", String::as_str)),
    )?;
    if !run::at_a_terminal() {
        eprintln!("shtum: {} secrets from {env}; output masked", vars.len());
    }
    run::run(run::Job {
        program: command,
        vars: &vars,
        stdin: None,
        mask: &vars,
    })
}

fn fly_sync(env: &str, app: &str, only: &[String], stage: bool) -> Result<i32> {
    let v = Vault::open()?;
    let vars = gather(&v, env, only, &format!("push secrets to Fly app {app}"))?;
    if vars.is_empty() {
        bail!("nothing to push: {env} has no secrets");
    }
    let mut body = Zeroizing::new(Vec::new());
    for (n, val) in &vars {
        if val.contains(&b'\n') {
            bail!(
                "{n} spans several lines; set it with `fly secrets set` by hand (Fly's import format is line-based)"
            );
        }
        body.extend_from_slice(n.as_bytes());
        body.push(b'=');
        body.extend_from_slice(val);
        body.push(b'\n');
    }
    let mut program = vec![
        "fly".to_string(),
        "secrets".into(),
        "import".into(),
        "-a".into(),
        app.into(),
    ];
    if stage {
        program.push("--stage".into());
    }
    eprintln!(
        "shtum: pushing {} secrets from {env} to Fly app {app}",
        vars.len()
    );
    let code = run::run(run::Job {
        program: &program,
        vars: &[],
        stdin: Some(body),
        mask: &vars,
    })?;
    if code == 0 {
        let tag = format!("fly:{app}");
        for (n, _) in &vars {
            let mut m = v.load(n, env)?;
            if !m.used_by.contains(&tag) {
                m.used_by.push(tag.clone());
                v.save(&m)?;
            }
        }
    }
    Ok(code)
}

/// Only a person at a terminal can pass this: an agent's shell has none.
fn at_a_person() -> Result<()> {
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        bail!(
            "this prints a value, so it only runs at a terminal — to give a program the value, use `shtum run`"
        );
    }
    Ok(())
}

fn reveal(name: &str, env: &str) -> Result<i32> {
    at_a_person()?;
    let v = Vault::open()?;
    let ring = Keyring::for_vault(&v);
    presence::confirm(&format!("shtum: show {name} ({env})"), ring.is_file())?;
    let identity = ring.load(env)?;
    let value = crypto::open_with(&v, &identity, name, env)?;
    println!("{}", String::from_utf8_lossy(&value));
    Ok(0)
}

fn backup_key(env: &str) -> Result<i32> {
    at_a_person()?;
    let v = Vault::open()?;
    v.recipient(env)?;
    let ring = Keyring::for_vault(&v);
    presence::confirm(
        &format!("shtum: show the {env} private key"),
        ring.is_file(),
    )?;
    let identity = ring.load(env)?;
    println!("The private key for {env}. Anyone with it and the vault can read every {env} value.");
    println!("Keep it in a password manager or on paper, never in the vault or a repository.\n");
    println!("{}", identity.as_str());
    Ok(0)
}

fn doc(c: DocCmd) -> Result<i32> {
    let v = Vault::open()?;
    match c {
        DocCmd::Ls => {
            for d in v.docs()? {
                println!("{d}");
            }
        }
        DocCmd::Show { name } => print!(
            "{}",
            std::fs::read_to_string(v.doc_path(&name)?).context("no such doc")?
        ),
        DocCmd::Write { name } => {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text)?;
            v.write_doc(&name, &text)?;
            println!("Wrote doc {name}.");
        }
    }
    Ok(0)
}

fn setup() -> Result<i32> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let exe = exe.to_string_lossy();
    println!("shtum cannot edit Claude Code's settings for you. Paste these:\n");
    println!("1. The hook (refuses agents reading .env files, identities and revealed values):\n");
    println!(
        "jq --arg cmd '{exe} hook' '.hooks.PreToolUse = ((.hooks.PreToolUse // []) | map(select(.hooks[0].command != $cmd)) + [{{\"matcher\": \"Bash|Read|Grep|Glob|NotebookRead\", \"hooks\": [{{\"type\": \"command\", \"command\": $cmd}}]}}])' ~/.claude/settings.json > /tmp/claude-settings.json && mv /tmp/claude-settings.json ~/.claude/settings.json\n"
    );
    println!("2. The MCP server (metadata and docs only, never values):\n");
    println!("claude mcp add --scope user shtum -- {exe} mcp\n");
    println!("Both take effect for sessions started afterwards.");
    Ok(0)
}
