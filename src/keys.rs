//! What can be known about a key without showing it: what kind it is, from its prefix, and
//! whether its provider still accepts it, from one cheap read-only call.
//!
//! Where a key is sent is decided here and nowhere else. Each provider's address is written
//! in this file, and the provider is chosen from the value's own prefix. The `provider` field
//! a person or agent can edit is consulted only for a value with no telling prefix (a SerpAPI
//! key is 64 hex characters), and even then picks from this list, never an address. Otherwise
//! relabelling a Resend key as "Stripe" would send it to Stripe. Redirects are not followed,
//! so a key is never carried on to a host it was not written for.
//!
//! Nothing a provider says is printed as it said it: an error message can quote part of the
//! key ("Invalid API Key provided: sk_live_****1234"), so a check reports a status code in
//! shtum's own words and reads only named fields out of a successful answer.

use crate::vault::Check;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Probe {
    StripeAccount,
    Resend,
    Anthropic,
    AnthropicAdmin,
    OpenAi,
    Perplexity,
    Jina,
    GitHub,
    SerpApi,
    /// Nothing to ask the provider, and why.
    Offline(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Kind {
    pub provider: &'static str,
    pub kind: &'static str,
    pub mode: Option<&'static str>,
    pub probe: Probe,
}

const PUBLISHABLE: &str = "a publishable key is public by design; there is nothing to check";
const SIGNING: &str = "a signing secret is checked only by verifying a webhook it signed";

/// Longest prefix first, so `sk-ant-` is never read as OpenAI's `sk-`.
const PREFIXES: &[(&str, Kind)] = &[
    (
        "sk-ant-admin",
        k(
            "Anthropic",
            "Anthropic admin key",
            None,
            Probe::AnthropicAdmin,
        ),
    ),
    (
        "sk-ant-api",
        k("Anthropic", "Anthropic API key", None, Probe::Anthropic),
    ),
    (
        "sk-ant-oat",
        k(
            "Anthropic",
            "Anthropic OAuth token",
            None,
            Probe::Offline("an OAuth token is checked by the app that holds it"),
        ),
    ),
    (
        "sk_live_",
        k(
            "Stripe",
            "Stripe secret key",
            Some("live"),
            Probe::StripeAccount,
        ),
    ),
    (
        "sk_test_",
        k(
            "Stripe",
            "Stripe secret key",
            Some("test"),
            Probe::StripeAccount,
        ),
    ),
    (
        "rk_live_",
        k(
            "Stripe",
            "Stripe restricted key",
            Some("live"),
            Probe::StripeAccount,
        ),
    ),
    (
        "rk_test_",
        k(
            "Stripe",
            "Stripe restricted key",
            Some("test"),
            Probe::StripeAccount,
        ),
    ),
    (
        "pk_live_",
        k(
            "Stripe",
            "Stripe publishable key",
            Some("live"),
            Probe::Offline(PUBLISHABLE),
        ),
    ),
    (
        "pk_test_",
        k(
            "Stripe",
            "Stripe publishable key",
            Some("test"),
            Probe::Offline(PUBLISHABLE),
        ),
    ),
    (
        "whsec_",
        k(
            "Stripe",
            "Stripe webhook signing secret",
            None,
            Probe::Offline(SIGNING),
        ),
    ),
    (
        "github_pat_",
        k("GitHub", "GitHub fine-grained token", None, Probe::GitHub),
    ),
    ("ghp_", k("GitHub", "GitHub token", None, Probe::GitHub)),
    (
        "sk-proj-",
        k("OpenAI", "OpenAI project key", None, Probe::OpenAi),
    ),
    (
        "sk-svcacct-",
        k("OpenAI", "OpenAI service account key", None, Probe::OpenAi),
    ),
    (
        "pplx-",
        k("Perplexity", "Perplexity API key", None, Probe::Perplexity),
    ),
    ("jina_", k("Jina", "Jina API key", None, Probe::Jina)),
    ("re_", k("Resend", "Resend API key", None, Probe::Resend)),
    ("sk-", k("OpenAI", "OpenAI API key", None, Probe::OpenAi)),
    (
        "AKIA",
        k(
            "AWS",
            "AWS access key id",
            None,
            Probe::Offline("an AWS key id is only half of a credential"),
        ),
    ),
    (
        "AIza",
        k(
            "Google",
            "Google API key",
            None,
            Probe::Offline("a Google API key is checked per API it is enabled for"),
        ),
    ),
];

const fn k(
    provider: &'static str,
    kind: &'static str,
    mode: Option<&'static str>,
    probe: Probe,
) -> Kind {
    Kind {
        provider,
        kind,
        mode,
        probe,
    }
}

/// What a value is. `name` and `provider` are only for values whose prefix says nothing.
pub fn classify(value: &[u8], name: &str, provider: Option<&str>) -> Option<Kind> {
    let v = std::str::from_utf8(value).ok()?.trim();
    if let Some((_, kind)) = PREFIXES.iter().find(|(p, _)| v.starts_with(p)) {
        return Some(*kind);
    }
    let said_serp =
        provider.is_some_and(|p| p.eq_ignore_ascii_case("serpapi")) || name.contains("SERP");
    if said_serp && v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(k("SerpAPI", "SerpAPI key", None, Probe::SerpApi));
    }
    None
}

struct Reply {
    status: u16,
    body: String,
}

/// Where a provider lives. Tests in a debug build may point every provider at a local
/// server; a release build has no way to send a key anywhere but the address written here.
fn at(real_base: &str, path: &str) -> String {
    #[cfg(debug_assertions)]
    if let Ok(b) = std::env::var("SHTUM_TEST_PROVIDER_BASE") {
        return format!("{}{path}", b.trim_end_matches('/'));
    }
    format!("{real_base}{path}")
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent(concat!("shtum/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// One request. A failure is described by kind only: the library's own error can print the
/// address, and a SerpAPI address carries the key.
fn call(req: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Reply, String> {
    match req {
        Ok(mut r) => {
            let status = r.status().as_u16();
            let body = r
                .body_mut()
                .with_config()
                .limit(256 * 1024)
                .read_to_string()
                .unwrap_or_default();
            Ok(Reply { status, body })
        }
        Err(e) => Err(match e {
            ureq::Error::Timeout(_) => "timed out".into(),
            ureq::Error::HostNotFound => "could not find the provider (offline?)".into(),
            ureq::Error::ConnectionFailed => "could not connect to the provider".into(),
            ureq::Error::Io(_) => "the connection failed".into(),
            _ => "the request failed".into(),
        }),
    }
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or(serde_json::Value::Null)
}

/// Ask the provider whether it still accepts the value. Never returns the value or anything
/// the provider said verbatim.
pub fn check(kind: &Kind, value: &[u8]) -> Check {
    let at_now = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let done = |status: &str, detail: String, account: Option<String>| Check {
        at: at_now.clone(),
        status: status.into(),
        detail: scrub(&detail, value),
        account: account.map(|a| scrub(&a, value)),
    };
    let key = String::from_utf8_lossy(value).trim().to_string();
    let a = agent();
    let reply = match kind.probe {
        Probe::Offline(why) => return done("unknown", format!("not checked online: {why}"), None),
        Probe::StripeAccount => call(
            a.get(at("https://api.stripe.com", "/v1/account"))
                .header("Authorization", format!("Bearer {key}"))
                .call(),
        ),
        Probe::Resend => call(
            a.get(at("https://api.resend.com", "/domains"))
                .header("Authorization", format!("Bearer {key}"))
                .call(),
        ),
        Probe::Anthropic => call(
            a.get(at("https://api.anthropic.com", "/v1/models?limit=1"))
                .header("x-api-key", &key)
                .header("anthropic-version", "2023-06-01")
                .call(),
        ),
        Probe::AnthropicAdmin => call(
            a.get(at("https://api.anthropic.com", "/v1/organizations/me"))
                .header("x-api-key", &key)
                .header("anthropic-version", "2023-06-01")
                .call(),
        ),
        Probe::OpenAi => call(
            a.get(at("https://api.openai.com", "/v1/models"))
                .header("Authorization", format!("Bearer {key}"))
                .call(),
        ),
        // No free read-only call exists; an empty request is refused as malformed by a key it
        // accepts, and as unauthorised by one it does not. It does no work and costs nothing.
        Probe::Perplexity => call(
            a.post(at("https://api.perplexity.ai", "/chat/completions"))
                .header("Authorization", format!("Bearer {key}"))
                .header("Content-Type", "application/json")
                .send("{}"),
        ),
        Probe::Jina => call(
            a.post(at("https://api.jina.ai", "/v1/embeddings"))
                .header("Authorization", format!("Bearer {key}"))
                .header("Content-Type", "application/json")
                .send("{}"),
        ),
        Probe::GitHub => call(
            a.get(at("https://api.github.com", "/user"))
                .header("Authorization", format!("Bearer {key}"))
                .header("Accept", "application/vnd.github+json")
                .call(),
        ),
        // SerpAPI takes its key only in the address, which is why errors above never print one.
        Probe::SerpApi => call(
            a.get(at("https://serpapi.com", "/account.json"))
                .query("api_key", &key)
                .call(),
        ),
    };
    let r = match reply {
        Ok(r) => r,
        Err(why) => return done("unknown", why, None),
    };
    judge(kind, &r)
        .map(|(status, detail, account)| done(status, detail, account))
        .unwrap_or_else(|| {
            done(
                "unknown",
                format!("the provider answered {}", r.status),
                None,
            )
        })
}

/// Read a reply. `None` when the status says nothing either way (a 5xx, an odd code).
fn judge(kind: &Kind, r: &Reply) -> Option<(&'static str, String, Option<String>)> {
    let body = json(&r.body);
    let s = r.status;
    let refused = || {
        Some((
            "failing",
            format!(
                "{} refused it ({s}): rolled, expired, revoked or mistyped",
                kind.provider
            ),
            None,
        ))
    };
    let empty_probe = matches!(kind.probe, Probe::Perplexity | Probe::Jina);
    match s {
        429 => Some((
            "unknown",
            format!("{} is rate limiting; try again shortly", kind.provider),
            None,
        )),
        401 if kind.probe == Probe::Resend && body["name"] == "restricted_api_key" => {
            Some(("ok", "Resend accepted it (a sending-only key)".into(), None))
        }
        403 if kind.probe == Probe::StripeAccount && kind.kind.contains("restricted") => Some((
            "ok",
            "Stripe accepted it (this restricted key may not read the account)".into(),
            None,
        )),
        401 | 403 => refused(),
        // Resend answers a key it does not know with 400 "validation_error: API key is invalid"
        // (measured), where everyone else says 401.
        400 if kind.probe == Probe::Resend
            && body["message"]
                .as_str()
                .is_some_and(|m| m.contains("API key")) =>
        {
            refused()
        }
        400..=499 if empty_probe => Some(("ok", format!("{} accepted it", kind.provider), None)),
        200..=299 => Some((
            "ok",
            format!("{} accepted it", kind.provider),
            account(kind, &body),
        )),
        _ => None,
    }
}

/// Which account a key belongs to, from named fields only. Never an email address.
fn account(kind: &Kind, b: &serde_json::Value) -> Option<String> {
    let s = |v: &serde_json::Value| v.as_str().map(str::to_string).filter(|x| !x.is_empty());
    match kind.probe {
        Probe::StripeAccount => {
            let id = s(&b["id"])?;
            let name = s(&b["settings"]["dashboard"]["display_name"])
                .or_else(|| s(&b["business_profile"]["name"]));
            Some(match name {
                Some(n) => format!("{id} · {n}"),
                None => id,
            })
        }
        Probe::AnthropicAdmin => s(&b["name"]).map(|n| format!("organization {n}")),
        Probe::GitHub => s(&b["login"]).map(|l| format!("user {l}")),
        Probe::Resend => {
            let names: Vec<String> = b["data"]
                .as_array()?
                .iter()
                .filter_map(|d| s(&d["name"]))
                .take(3)
                .collect();
            (!names.is_empty()).then(|| format!("domains {}", names.join(", ")))
        }
        Probe::SerpApi => {
            let plan = s(&b["plan_name"]);
            let left = b["total_searches_left"].as_i64();
            match (plan, left) {
                (Some(p), Some(l)) => Some(format!("plan {p}, {l} searches left")),
                (Some(p), None) => Some(format!("plan {p}")),
                (None, Some(l)) => Some(format!("{l} searches left")),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Belt and braces: nothing shtum records about a value may contain the value.
fn scrub(s: &str, value: &[u8]) -> String {
    let v = String::from_utf8_lossy(value);
    let v = v.trim();
    if v.len() >= 6 {
        s.replace(v, "[shtum:value]")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_name_the_kind_and_mode() {
        let c = |v: &str| classify(v.as_bytes(), "X", None).map(|k| (k.kind, k.mode));
        assert_eq!(c("sk_live_abc"), Some(("Stripe secret key", Some("live"))));
        assert_eq!(
            c("rk_test_abc"),
            Some(("Stripe restricted key", Some("test")))
        );
        assert_eq!(
            c("pk_live_abc"),
            Some(("Stripe publishable key", Some("live")))
        );
        assert_eq!(
            c("whsec_abc"),
            Some(("Stripe webhook signing secret", None))
        );
        assert_eq!(c("sk-ant-api03-abc"), Some(("Anthropic API key", None)));
        assert_eq!(c("sk-proj-abc"), Some(("OpenAI project key", None)));
        assert_eq!(c("sk-abc"), Some(("OpenAI API key", None)));
        assert_eq!(c("re_abc"), Some(("Resend API key", None)));
        assert_eq!(c("pplx-abc"), Some(("Perplexity API key", None)));
        assert_eq!(c("mystery"), None);
    }

    #[test]
    fn a_label_cannot_redirect_a_key_with_a_telling_prefix() {
        let k = classify(b"re_abc", "STRIPE_KEY", Some("Stripe")).unwrap();
        assert_eq!(k.provider, "Resend");
    }

    #[test]
    fn serpapi_needs_both_its_shape_and_a_label() {
        let hex = "a".repeat(64);
        assert_eq!(
            classify(hex.as_bytes(), "SERPAPI_KEY", None)
                .unwrap()
                .provider,
            "SerpAPI"
        );
        assert_eq!(
            classify(hex.as_bytes(), "OTHER", Some("serpapi"))
                .unwrap()
                .provider,
            "SerpAPI"
        );
        assert!(classify(hex.as_bytes(), "OTHER", None).is_none());
        assert!(classify(b"short", "SERPAPI_KEY", None).is_none());
    }

    #[test]
    fn replies_are_judged_in_our_own_words() {
        let stripe = classify(b"sk_live_x", "K", None).unwrap();
        let r = |status: u16, body: &str| {
            judge(
                &stripe,
                &Reply {
                    status,
                    body: body.into(),
                },
            )
        };
        let ok = r(
            200,
            r#"{"id":"acct_1","settings":{"dashboard":{"display_name":"Acme"}},"email":"a@b.c"}"#,
        )
        .unwrap();
        assert_eq!(ok.0, "ok");
        assert_eq!(ok.2.as_deref(), Some("acct_1 · Acme"));
        let bad = r(
            401,
            r#"{"error":{"message":"Invalid API Key provided: sk_live_****1234"}}"#,
        )
        .unwrap();
        assert_eq!(bad.0, "failing");
        assert!(!bad.1.contains("1234"));
        assert!(r(503, "").is_none());
        let rk = classify(b"rk_live_x", "K", None).unwrap();
        assert_eq!(
            judge(
                &rk,
                &Reply {
                    status: 403,
                    body: String::new()
                }
            )
            .unwrap()
            .0,
            "ok"
        );
        let resend = classify(b"re_x", "K", None).unwrap();
        let bad = r#"{"statusCode":400,"message":"API key is invalid","name":"validation_error"}"#;
        assert_eq!(
            judge(
                &resend,
                &Reply {
                    status: 400,
                    body: bad.into()
                }
            )
            .unwrap()
            .0,
            "failing"
        );
        let jina = classify(b"jina_x", "K", None).unwrap();
        assert_eq!(
            judge(
                &jina,
                &Reply {
                    status: 422,
                    body: String::new()
                }
            )
            .unwrap()
            .0,
            "ok"
        );
        assert_eq!(
            judge(
                &jina,
                &Reply {
                    status: 401,
                    body: String::new()
                }
            )
            .unwrap()
            .0,
            "failing"
        );
    }

    #[test]
    fn scrub_removes_the_value() {
        assert_eq!(
            scrub("x sk_live_secret y", b"sk_live_secret\n"),
            "x [shtum:value] y"
        );
    }
}
