//! `shtum mcp`: an MCP server over stdio for agents.
//!
//! Every tool here reads or writes what is known *about* a secret. None of them returns a value,
//! and none can be made to: there is no code path from this file to a decryption.

use crate::ops;
use crate::vault::Vault;
use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::io::{BufRead, Write};

const INSTRUCTIONS: &str = "shtum stores API keys and what is known about them: provider, dashboard, \
limits, plan, who uses them, when they rotate. You can read and edit all of that. You can never see a \
value, by design: anything you read goes to the model and into a transcript on disk. To give a program \
its keys, run it with `shtum run --env <env> -- <command>` in a shell (output is masked). When you learn \
something about a key — its rate limit, its plan, where to rotate it — record it with update_secret or \
in a doc, so the next agent knows.";

pub fn serve() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            write(
                &mut stdout,
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}),
            )?;
            continue;
        };
        let Some(id) = msg.get("id").cloned() else {
            continue;
        }; // a notification
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(json!({}));
        let reply = match method {
            "initialize" => Ok(json!({
                "protocolVersion": params.get("protocolVersion").cloned().unwrap_or(json!("2025-06-18")),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "shtum", "version": env!("CARGO_PKG_VERSION")},
                "instructions": INSTRUCTIONS,
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => Ok(call(&params)),
            other => Err(json!({"code": -32601, "message": format!("no method {other}")})),
        };
        let out = match reply {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error}),
        };
        write(&mut stdout, out)?;
    }
    Ok(())
}

fn write(out: &mut impl Write, v: Value) -> Result<()> {
    writeln!(out, "{v}")?;
    out.flush()?;
    Ok(())
}

fn tools() -> Value {
    let s = |d: &str| json!({"type": "string", "description": d});
    json!([
        {"name": "list_secrets", "description": "Every secret's name, env, folder, provider, rotation status (or 'no value yet') and users. No values.",
         "inputSchema": {"type": "object", "properties": {"env": s("Only this env, e.g. dev or prod"), "folder": s("Only this folder, e.g. stripe")}}},
        {"name": "declare_secret", "description": "Declare a secret that has no value yet, with its folder and what is known about it, so a person can fill it at their terminal with `shtum set NAME --env ENV`. Takes no value and never will: never ask the person to give you one.",
         "inputSchema": {"type": "object", "properties": {"name": s("An environment variable name, e.g. STRIPE_SECRET_KEY"), "env": s("Env, e.g. prod"), "folder": s("Optional group, e.g. stripe"), "fields": {"type": "object", "additionalProperties": {"type": "string"}}}, "required": ["name", "env"]}},
        {"name": "show_secret", "description": "Everything known about one secret: provider, dashboard, limits, plan, rotation, history by fingerprint, notes. Never the value.",
         "inputSchema": {"type": "object", "properties": {"name": s("e.g. RESEND_API_KEY"), "env": s("Omit to show every env it exists in")}, "required": ["name"]}},
        {"name": "update_secret", "description": "Set fields on a secret's record. Fields: folder, provider, description, dashboard, owner, plan, limits, notes, used_by (comma list), rotate_every_days, last_rotated (YYYY-MM-DD), expires (YYYY-MM-DD), or any custom lowercase field. An empty string clears a field.",
         "inputSchema": {"type": "object", "properties": {"name": s("Secret name"), "env": s("Env"), "fields": {"type": "object", "additionalProperties": {"type": "string"}}}, "required": ["name", "env", "fields"]}},
        {"name": "rotation_due", "description": "Secrets overdue or due for rotation or expiry soon, and those with no rotation policy.",
         "inputSchema": {"type": "object", "properties": {"within_days": {"type": "integer", "description": "Default 14"}}}},
        {"name": "list_docs", "description": "Names of the free-form docs (provider notes, runbooks).", "inputSchema": {"type": "object", "properties": {}}},
        {"name": "read_doc", "description": "Read one doc.", "inputSchema": {"type": "object", "properties": {"name": s("Doc name")}, "required": ["name"]}},
        {"name": "write_doc", "description": "Create or replace a doc. Markdown. Never put a secret value in a doc.",
         "inputSchema": {"type": "object", "properties": {"name": s("lowercase, digits, dashes, dots"), "content": s("Markdown")}, "required": ["name", "content"]}},
    ])
}

fn call(params: &Value) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    match run_tool(name, &args) {
        Ok(text) => json!({"content": [{"type": "text", "text": text}]}),
        Err(e) => json!({"content": [{"type": "text", "text": format!("{e:#}")}], "isError": true}),
    }
}

/// The `fields` object of a tool call as field=value pairs; absent means none.
fn fields_of(args: &Value) -> Result<Vec<(String, String)>> {
    let Some(f) = args.get("fields") else {
        return Ok(vec![]);
    };
    Ok(f.as_object()
        .context("fields must be an object of strings")?
        .iter()
        .map(|(k, val)| {
            let s = match val {
                Value::String(s) => s.clone(),
                Value::Array(a) => a
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                other => other.to_string(),
            };
            (k.clone(), s)
        })
        .collect())
}

fn run_tool(name: &str, args: &Value) -> Result<String> {
    let v = Vault::open()?;
    let arg = |k: &str| args.get(k).and_then(Value::as_str);
    let need = |k: &str| arg(k).with_context(|| format!("{k} is required"));
    match name {
        "list_secrets" => ops::list_text(&v, arg("env"), arg("folder")),
        "declare_secret" => {
            let m = ops::declare(
                &v,
                need("name")?,
                need("env")?,
                arg("folder"),
                &fields_of(args)?,
            )?;
            Ok(format!(
                "Declared {} in {}, no value yet. The person fills it at their terminal: shtum set {} --env {}\n\n{}",
                m.name,
                m.env,
                m.name,
                m.env,
                toml::to_string_pretty(&m)?
            ))
        }
        "show_secret" => ops::show_text(&v, need("name")?, arg("env")),
        "update_secret" => {
            let fields = fields_of(args)?;
            if fields.is_empty() {
                anyhow::bail!("fields must name at least one field");
            }
            let m = ops::update(&v, need("name")?, need("env")?, &fields)?;
            Ok(format!(
                "Updated {} in {}.\n\n{}",
                m.name,
                m.env,
                toml::to_string_pretty(&m)?
            ))
        }
        "rotation_due" => ops::due_text(
            &v,
            args.get("within_days")
                .and_then(Value::as_i64)
                .unwrap_or(14),
        ),
        "list_docs" => Ok(v.docs()?.join("\n")),
        "read_doc" => std::fs::read_to_string(v.doc_path(need("name")?)?).context("no such doc"),
        "write_doc" => {
            let doc = need("name")?;
            v.write_doc(doc, need("content")?)?;
            Ok(format!("Wrote doc {doc}."))
        }
        other => Err(anyhow!("no tool {other}")),
    }
}
