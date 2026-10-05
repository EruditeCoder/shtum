//! `shtum hook`: a Claude Code `PreToolUse` hook that refuses the ways an agent could pull a
//! secret value into its own context.
//!
//! It reads the tool call as JSON on stdin and prints a deny decision, or nothing to allow.
//! Any input it cannot understand is allowed: a hook that breaks every tool call when the
//! vault is missing is a hook nobody keeps installed. It is a guard rail against well-meaning
//! agents, not a sandbox — see SECURITY.md.

use crate::vault::{Vault, home, valid_name};
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::Read;

pub fn main() {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return;
    }
    let Ok(call) = serde_json::from_str::<Value>(&input) else {
        return;
    };
    let ctx = Context::load();
    if let Some(reason) = decide(&call, &ctx) {
        let out = serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        });
        println!("{out}");
    }
}

pub struct Context {
    pub guard_dotenv: bool,
    pub names: BTreeSet<String>,
    pub identities: String,
}

impl Context {
    pub fn load() -> Context {
        let h = home();
        let identities = h.join("identities").to_string_lossy().into_owned();
        let Ok(v) = Vault::open_at(&h) else {
            return Context {
                guard_dotenv: true,
                names: BTreeSet::new(),
                identities,
            };
        };
        let mut names = BTreeSet::new();
        for env in v.envs() {
            let dir = v.vault_dir().join("secrets").join(env);
            for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                if let Some(n) = e.file_name().to_str().and_then(|n| n.strip_suffix(".toml"))
                    && valid_name(n)
                {
                    names.insert(n.to_string());
                }
            }
        }
        Context {
            guard_dotenv: v.config.guard_dotenv,
            names,
            identities,
        }
    }
}

const HUMAN_ONLY: &str = "is for a person at a terminal. A value an agent reads is sent to the model and \
saved in the transcript on disk. To give a program the value, run it under `shtum run --env <env> -- <command>`.";

const DOTENV: &str = "Reading a .env file puts every value in it into this conversation and its \
transcript. Use `shtum ls` / `shtum show NAME` for what is stored (everything but the value), \
`shtum import <file> --env dev` to move a file's keys into shtum without printing them, and \
`shtum run --env dev -- <command>` to run with them.";

pub fn decide(call: &Value, ctx: &Context) -> Option<String> {
    let tool = call.get("tool_name")?.as_str()?;
    let input = call.get("tool_input")?;
    let field = |k: &str| input.get(k).and_then(Value::as_str).unwrap_or("");
    match tool {
        "Bash" => bash(field("command"), ctx),
        "Read" | "NotebookRead" => path(field("file_path"), ctx),
        "Grep" | "Glob" => path(field("path"), ctx),
        _ => None,
    }
}

fn path(p: &str, ctx: &Context) -> Option<String> {
    if p.is_empty() {
        return None;
    }
    if p.starts_with(&ctx.identities) {
        return Some(
            "shtum's identity files decrypt every value; they are not for reading.".into(),
        );
    }
    if ctx.guard_dotenv && is_dotenv(p) {
        return Some(DOTENV.into());
    }
    None
}

/// `.env`, `.env.local`, `prod.env` — but not `.env.example` and its kin, which hold no values.
pub fn is_dotenv(p: &str) -> bool {
    let p = p.trim_matches(|c| c == '"' || c == '\'');
    let base = p.rsplit('/').next().unwrap_or(p);
    let safe = [
        ".example",
        ".sample",
        ".template",
        ".dist",
        ".defaults",
        ".schema",
        ".tpl",
    ];
    if safe.iter().any(|s| base.ends_with(s)) {
        return false;
    }
    base == ".env" || base.starts_with(".env.") || (base.ends_with(".env") && base.len() > 4)
}

const READERS: &[&str] = &[
    "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg", "ag", "ack", "sed",
    "awk", "gawk", "bat", "strings", "xxd", "od", "hexdump", "base64", "cut", "sort", "uniq", "nl",
    "tac", "diff", "jq", "yq", "vim", "view", "nano", "column", "paste", "tr", "fold", "wc",
    "dotenv", "printf", "envsubst",
];
const DUMPERS: &[&str] = &[
    "env", "printenv", "set", "export", "declare", "compgen", "typeset",
];

fn bash(cmd: &str, ctx: &Context) -> Option<String> {
    let c = cmd;
    if has_words(c, &["shtum", "reveal"]) || has_words(c, &["shtum", "backup-key"]) {
        return Some(format!(
            "`shtum reveal` and `shtum backup-key` {HUMAN_ONLY}"
        ));
    }
    if c.contains("dump-keychain") || (c.contains("find-generic-password") && c.contains("shtum")) {
        return Some(format!(
            "Reading shtum's keys out of the Keychain {HUMAN_ONLY}"
        ));
    }
    // Deleting needs no Keychain prompt (measured), and without its key an env's values are gone.
    if c.contains("delete-generic-password") && c.contains("shtum") {
        return Some(
            "Deleting shtum's Keychain item would make every value in that env unreadable.".into(),
        );
    }
    if c.contains(&ctx.identities) || c.contains("/.shtum/identities") {
        return Some(
            "shtum's identity files decrypt every value; they are not for reading.".into(),
        );
    }
    let runs_shtum = has_words(c, &["shtum", "run"]) || has_words(c, &["shtum", "fly"]);
    for seg in segments(c) {
        let words: Vec<&str> = seg
            .split_whitespace()
            .map(|w| w.trim_matches(|q| q == '"' || q == '\''))
            .collect();
        let Some(first) = words.iter().copied().find(|w| !w.contains('=')) else {
            continue;
        };
        let first = first.rsplit('/').next().unwrap_or(first);
        if ctx.guard_dotenv {
            let reads_file = READERS.contains(&first) && words.iter().skip(1).any(|w| is_dotenv(w));
            let redirected = seg.contains('<')
                && seg
                    .split('<')
                    .skip(1)
                    .any(|r| r.split_whitespace().next().is_some_and(is_dotenv));
            let sourced =
                (first == "source" || first == ".") && words.get(1).is_some_and(|w| is_dotenv(w));
            if reads_file || redirected || (sourced && dumps_or_echoes(c)) {
                return Some(DOTENV.into());
            }
        }
        let launched = if first == "shtum" {
            words
                .iter()
                .position(|w| *w == "--")
                .and_then(|i| words.get(i + 1))
                .copied()
        } else {
            Some(first)
        };
        let launched = launched.map(|w| w.rsplit('/').next().unwrap_or(w));
        if runs_shtum && launched.is_some_and(|w| DUMPERS.contains(&w)) {
            let first = launched.unwrap_or_default();
            return Some(format!(
                "`{first}` under `shtum run` would print the injected values. Output is masked when it is not \
                 a terminal, but do not ask for the values: run the program that needs them."
            ));
        }
    }
    if c.contains("/environ") {
        return Some(
            "Reading a process's environment would print the values shtum injected.".into(),
        );
    }
    if runs_shtum {
        for n in &ctx.names {
            if c.contains(&format!("${n}")) || c.contains(&format!("${{{n}")) {
                return Some(format!(
                    "This command expands ${n} itself, which would print or pass on the value. Let the program \
                     read {n} from its own environment."
                ));
            }
        }
    }
    None
}

fn dumps_or_echoes(c: &str) -> bool {
    c.contains("echo")
        || c.contains("printf")
        || segments(c).any(|s| {
            s.split_whitespace()
                .next()
                .is_some_and(|w| DUMPERS.contains(&w))
        })
}

/// The simple commands in a line, split on `|`, `;`, `&&`, `||`, `&`, newlines and `$(`/backticks.
fn segments(c: &str) -> impl Iterator<Item = &str> {
    c.split(['|', ';', '&', '\n', '`', '(', ')'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn has_words(c: &str, seq: &[&str]) -> bool {
    let words: Vec<&str> = c.split_whitespace().collect();
    words.windows(seq.len()).any(|w| {
        w.iter()
            .zip(seq)
            .all(|(a, b)| a.rsplit('/').next() == Some(*b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> Context {
        Context {
            guard_dotenv: true,
            names: ["RESEND_API_KEY".to_string()].into_iter().collect(),
            identities: "/Users/x/.shtum/identities".into(),
        }
    }

    fn bash_denied(cmd: &str) -> bool {
        decide(
            &json!({"tool_name": "Bash", "tool_input": {"command": cmd}}),
            &ctx(),
        )
        .is_some()
    }

    #[test]
    fn dotenv_names() {
        for yes in [
            ".env",
            "app/.env",
            ".env.local",
            ".env.production",
            "prod.env",
            "'.env'",
        ] {
            assert!(is_dotenv(yes), "{yes}");
        }
        for no in [
            ".env.example",
            "a/.env.sample",
            ".env.template",
            "env",
            "dotenv.rs",
            ".envrc",
            "x.env.dist",
        ] {
            assert!(!is_dotenv(no), "{no}");
        }
    }

    #[test]
    fn reading_a_dotenv_is_refused_and_moving_it_into_shtum_is_not() {
        for cmd in [
            "cat .env",
            "cat my-api/.env | head",
            "grep RESEND ../.env.local",
            "/bin/cat .env",
            "cd app && tail -n 5 .env",
            "while read l; do echo $l; done < .env",
            "source .env && echo $RESEND_API_KEY",
        ] {
            assert!(bash_denied(cmd), "{cmd}");
        }
        for cmd in [
            "shtum import .env --env dev",
            "cat .env.example",
            "ls -la .env",
            "git status",
            "source .env && npm test",
            "cp .env.example .env",
        ] {
            assert!(!bash_denied(cmd), "{cmd}");
        }
    }

    #[test]
    fn the_read_tool_is_refused_on_dotenv_and_identities() {
        let read = |p: &str| {
            decide(
                &json!({"tool_name": "Read", "tool_input": {"file_path": p}}),
                &ctx(),
            )
            .is_some()
        };
        assert!(read("/repo/.env"));
        assert!(read("/Users/x/.shtum/identities/prod.key"));
        assert!(!read("/repo/.env.example"));
        assert!(!read("/repo/src/main.rs"));
    }

    #[test]
    fn human_only_commands_and_dumps_are_refused() {
        for cmd in [
            "shtum reveal RESEND_API_KEY --env dev",
            "./target/debug/shtum backup-key --env prod",
            "security find-generic-password -s shtum.abc -a prod -w",
            "security dump-keychain -d",
            "security delete-generic-password -s shtum.abc -a prod",
            "shtum run --env dev -- env",
            "shtum run --env dev -- printenv RESEND_API_KEY",
            "shtum run --env dev -- sh -c 'echo $RESEND_API_KEY'",
            "shtum run -- node -e 'x' ${RESEND_API_KEY}",
            "shtum run -- cat /proc/self/environ",
            "cat ~/.shtum/identities/dev.key",
        ] {
            assert!(bash_denied(cmd), "{cmd}");
        }
        for cmd in [
            "shtum run --env dev -- npm test",
            "shtum ls",
            "shtum show RESEND_API_KEY",
            "echo $HOME",
            "shtum run --env dev -- node scripts/send.js",
        ] {
            assert!(!bash_denied(cmd), "{cmd}");
        }
    }

    #[test]
    fn junk_is_allowed() {
        assert!(decide(&json!({"nope": 1}), &ctx()).is_none());
        assert!(
            decide(
                &json!({"tool_name": "Write", "tool_input": {"file_path": ".env"}}),
                &ctx()
            )
            .is_none()
        );
    }
}
