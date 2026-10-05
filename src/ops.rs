//! What the CLI and the MCP server both say, so the two cannot drift. Nothing here ever
//! touches a value.

use crate::vault::{Due, Meta, Vault, today};
use anyhow::Result;
use std::fmt::Write;

pub fn due_label(m: &Meta, within: i64) -> String {
    match m.due(today(), within) {
        Due::Overdue(d) => format!("OVERDUE {d}d"),
        Due::Soon(d) => format!("due in {d}d"),
        Due::Fine(d) => format!("ok ({d}d)"),
        Due::NoPolicy => "no rotation policy".into(),
    }
}

/// Rotation status, or that the secret was declared and has no value yet.
pub fn status_label(v: &Vault, m: &Meta, within: i64) -> String {
    if v.has_value(&m.name, &m.env) {
        due_label(m, within)
    } else {
        "no value yet".into()
    }
}

/// Every secret, grouped by folder (secrets in no folder first), optionally one env or one folder.
pub fn list_text(v: &Vault, env: Option<&str>, folder: Option<&str>) -> Result<String> {
    let mut all = v.list(env)?;
    if let Some(f) = folder {
        all.retain(|m| m.folder.as_deref() == Some(f));
        if all.is_empty() {
            return Ok(format!("No secrets in folder {f}.\n"));
        }
    }
    if all.is_empty() {
        return Ok("No secrets yet. `shtum set NAME --env dev` or `shtum import .env --env dev` adds some.\n".into());
    }
    all.sort_by(|a, b| (&a.folder, &a.env, &a.name).cmp(&(&b.folder, &b.env, &b.name)));
    let foldered = all.iter().any(|m| m.folder.is_some());
    let w = all.iter().map(|m| m.name.len()).max().unwrap_or(4).max(4);
    let mut out = String::new();
    let mut current: Option<Option<&str>> = None;
    for m in &all {
        if foldered && current != Some(m.folder.as_deref()) {
            current = Some(m.folder.as_deref());
            if !out.is_empty() {
                out.push('\n');
            }
            let _ = writeln!(
                out,
                "{}",
                m.folder
                    .as_deref()
                    .map_or("(no folder)".to_string(), |f| format!("{f}/"))
            );
        }
        let protected = if v.is_protected(&m.env) { "*" } else { " " };
        let _ = writeln!(
            out,
            "{:<6}{protected} {:<w$}  {:<14} {:<22} {}",
            m.env,
            m.name,
            m.provider.as_deref().unwrap_or("-"),
            status_label(v, m, 14),
            m.used_by.join(","),
        );
    }
    let _ = writeln!(
        out,
        "\n* protected: values need Touch ID or your password to use."
    );
    Ok(out)
}

pub fn show_text(v: &Vault, name: &str, env: Option<&str>) -> Result<String> {
    let envs = match env {
        Some(e) => vec![e.to_string()],
        None => v.envs_of(name),
    };
    if envs.is_empty() {
        anyhow::bail!("no secret named {name}");
    }
    let mut out = String::new();
    for e in envs {
        let m = v.load(name, &e)?;
        let _ = writeln!(
            out,
            "# {} in {}{}",
            m.name,
            m.env,
            if v.is_protected(&e) {
                " (protected)"
            } else {
                ""
            }
        );
        if v.has_value(&m.name, &e) {
            let _ = writeln!(out, "# {}", due_label(&m, 14));
            if let Some(d) = m.next_due() {
                let _ = writeln!(out, "# next due {d}");
            }
            let _ = writeln!(
                out,
                "# value: stored, never shown — use `shtum run` to give it to a program"
            );
        } else {
            let _ = writeln!(
                out,
                "# value: none yet — a person fills it at a terminal: shtum set {} --env {e}",
                m.name
            );
        }
        out.push_str(&toml::to_string_pretty(&m)?);
        out.push('\n');
    }
    Ok(out)
}

pub fn due_text(v: &Vault, within: i64) -> Result<String> {
    let mut rows: Vec<(i64, String)> = vec![];
    let mut none = vec![];
    let mut empty = vec![];
    for m in v.list(None)? {
        if !v.has_value(&m.name, &m.env) {
            empty.push(format!("{}/{}", m.env, m.name));
            continue;
        }
        match m.due(today(), within) {
            Due::Overdue(d) => {
                rows.push((-d, format!("{:<6} {:<32} OVERDUE by {d}d", m.env, m.name)))
            }
            Due::Soon(d) => rows.push((d, format!("{:<6} {:<32} due in {d}d", m.env, m.name))),
            Due::Fine(_) => {}
            Due::NoPolicy => none.push(format!("{}/{}", m.env, m.name)),
        }
    }
    rows.sort();
    let mut out = String::new();
    if rows.is_empty() {
        let _ = writeln!(out, "Nothing due in the next {within} days.");
    }
    for (_, r) in rows {
        let _ = writeln!(out, "{r}");
    }
    if !none.is_empty() {
        let _ = writeln!(
            out,
            "\nNo rotation policy ({}): {}\nSet one with `shtum meta NAME --env E rotate_every_days=90`.",
            none.len(),
            none.join(", ")
        );
    }
    if !empty.is_empty() {
        let _ = writeln!(
            out,
            "\nDeclared, no value yet ({}): {}\nFill one at your terminal with `shtum set NAME --env E`.",
            empty.len(),
            empty.join(", ")
        );
    }
    Ok(out)
}

/// Declare a secret with no value: its record, folder and metadata, for the CLI's `add` and the
/// MCP server's `declare_secret`. There is no value parameter, so nothing here can carry one.
pub fn declare(
    v: &Vault,
    name: &str,
    env: &str,
    folder: Option<&str>,
    fields: &[(String, String)],
) -> Result<Meta> {
    Vault::check(name, env)?;
    v.recipient(env)?;
    if v.has(name, env) {
        anyhow::bail!(
            "{name} already exists in {env} — describe it with `shtum meta`, fill it with `shtum set`"
        );
    }
    let mut m = Meta::new(name, env);
    if let Some(f) = folder {
        m.set_field("folder", f)?;
    }
    for (k, val) in fields {
        m.set_field(k, val)?;
    }
    v.save(&m)?;
    Ok(m)
}

pub fn update(v: &Vault, name: &str, env: &str, fields: &[(String, String)]) -> Result<Meta> {
    let mut m = v.load(name, env)?;
    for (k, val) in fields {
        m.set_field(k, val)?;
    }
    v.save(&m)?;
    Ok(m)
}
