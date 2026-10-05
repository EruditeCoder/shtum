//! The binary end to end, on a throwaway vault with file-kept keys. Touch ID is answered by
//! `SHTUM_TEST_PRESENCE`, which only a debug build with the file keyring honours.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const LIVE: &str = "fake-live-value-9f8e7d6c";
const DEV: &str = "fake-dev-value-0123456789";

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        let e = Env {
            dir: tempfile::tempdir().unwrap(),
        };
        let out = e.shtum(&["init"], None);
        assert!(out.status.success(), "{}", text(&out));
        e
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_shtum"));
        c.args(args)
            .env("SHTUM_HOME", self.home())
            .env("SHTUM_KEYRING", "file")
            .env("SHTUM_TEST_PRESENCE", "allow")
            .current_dir(self.dir.path());
        c
    }

    fn shtum(&self, args: &[&str], stdin: Option<&str>) -> Output {
        self.run(self.cmd(args), stdin)
    }

    fn run(&self, mut c: Command, stdin: Option<&str>) -> Output {
        c.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        let mut sink = child.stdin.take().unwrap();
        if let Some(s) = stdin {
            sink.write_all(s.as_bytes()).unwrap();
        }
        drop(sink);
        child.wait_with_output().unwrap()
    }

    fn ok(&self, args: &[&str], stdin: Option<&str>) -> String {
        let out = self.shtum(args, stdin);
        assert!(
            out.status.success(),
            "shtum {args:?} failed: {}",
            text(&out)
        );
        text(&out)
    }

    fn write(&self, name: &str, body: &str) -> PathBuf {
        let p = self.dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    fn with_secrets(&self) {
        let f = self.write(
            ".env",
            &format!("RESEND_API_KEY={LIVE}\nSTRIPE_KEY=\"{DEV}\"\nPORT=3000\nEMPTY=\n"),
        );
        self.ok(&["import", f.to_str().unwrap(), "--env", "prod"], None);
        let f = self.write("dev.env", &format!("STRIPE_KEY={DEV}\n"));
        self.ok(&["import", f.to_str().unwrap(), "--env", "dev"], None);
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn files_under(p: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    for e in std::fs::read_dir(p).unwrap().flatten() {
        let path = e.path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[test]
fn no_value_is_ever_printed_or_stored_in_the_clear() {
    let e = Env::new();
    let f = e.write(
        ".env",
        &format!("RESEND_API_KEY={LIVE}\nSTRIPE_KEY=\"{DEV}\"\nPORT=3000\nEMPTY=\n"),
    );
    let out = e.ok(&["import", f.to_str().unwrap(), "--env", "prod"], None);
    assert!(
        out.contains("RESEND_API_KEY") && out.contains("added"),
        "{out}"
    );
    assert!(out.contains("EMPTY") && out.contains("skipped"), "{out}");
    let mut seen = out;
    seen += &e.ok(&["ls"], None);
    seen += &e.ok(&["show", "RESEND_API_KEY"], None);
    seen += &e.ok(&["meta", "STRIPE_KEY", "--env", "prod"], None);
    seen += &e.ok(&["status"], None);
    assert!(
        !seen.contains(LIVE) && !seen.contains(DEV),
        "a value was printed:\n{seen}"
    );

    for file in files_under(&e.home().join("vault")) {
        let body = std::fs::read_to_string(&file).unwrap();
        assert!(
            !body.contains(LIVE) && !body.contains(DEV),
            "{} holds a value",
            file.display()
        );
    }
    let age =
        std::fs::read_to_string(e.home().join("vault/secrets/prod/RESEND_API_KEY.age")).unwrap();
    assert!(age.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(e.home().join("vault/secrets/prod/RESEND_API_KEY.age"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let mode = std::fs::metadata(e.home().join("identities/prod.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn run_injects_values_and_masks_them_in_output() {
    let e = Env::new();
    e.with_secrets();
    let out = e.shtum(
        &[
            "run",
            "--env",
            "prod",
            "--",
            "sh",
            "-c",
            "echo key=$RESEND_API_KEY; echo err=$STRIPE_KEY >&2; echo port=$PORT",
        ],
        None,
    );
    assert!(out.status.success(), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("key=[shtum:RESEND_API_KEY]"), "{stdout}");
    assert!(stderr.contains("err=[shtum:STRIPE_KEY]"), "{stderr}");
    assert!(
        stdout.contains("port=3000"),
        "short values are not masked: {stdout}"
    );
    assert!(!text(&out).contains(LIVE) && !text(&out).contains(DEV));

    // The program really got the value: compare inside the child, print only the verdict.
    let check = format!("[ \"$RESEND_API_KEY\" = \"{LIVE}\" ] && echo same || echo different");
    let out = e.shtum(
        &[
            "run",
            "--env",
            "prod",
            "--only",
            "RESEND_API_KEY",
            "--",
            "sh",
            "-c",
            &check,
        ],
        None,
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("same"),
        "{}",
        text(&out)
    );

    // --only leaves the rest out.
    let out = e.shtum(
        &[
            "run",
            "--env",
            "prod",
            "--only",
            "PORT",
            "--",
            "sh",
            "-c",
            "echo [${RESEND_API_KEY:-unset}]",
        ],
        None,
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("[unset]"),
        "{}",
        text(&out)
    );
}

#[test]
fn run_passes_the_exit_code_through() {
    let e = Env::new();
    e.with_secrets();
    let out = e.shtum(&["run", "--env", "dev", "--", "sh", "-c", "exit 7"], None);
    assert_eq!(out.status.code(), Some(7));
    let out = e.shtum(
        &["run", "--env", "dev", "--", "sh", "-c", "kill -TERM $$"],
        None,
    );
    assert_eq!(out.status.code(), Some(128 + 15));
}

#[test]
fn a_protected_env_needs_the_person_and_dev_does_not() {
    let e = Env::new();
    e.with_secrets();
    let mut c = e.cmd(&["run", "--env", "prod", "--", "true"]);
    c.env("SHTUM_TEST_PRESENCE", "deny");
    let out = e.run(c, None);
    assert!(!out.status.success());
    assert!(text(&out).contains("not confirmed"), "{}", text(&out));

    let mut c = e.cmd(&["run", "--env", "dev", "--", "true"]);
    c.env("SHTUM_TEST_PRESENCE", "deny");
    assert!(e.run(c, None).status.success());

    // Replacing a prod value needs the person too.
    let mut c = e.cmd(&["set", "RESEND_API_KEY", "--env", "prod"]);
    c.env("SHTUM_TEST_PRESENCE", "deny");
    assert!(!e.run(c, Some("fake-new-value-123")).status.success());
}

#[test]
fn setting_a_new_value_records_a_rotation() {
    let e = Env::new();
    e.with_secrets();
    assert!(
        e.ok(
            &["set", "STRIPE_KEY", "--env", "dev"],
            Some(&format!("{DEV}\n"))
        )
        .contains("unchanged")
    );
    let out = e.ok(
        &["set", "STRIPE_KEY", "--env", "dev", "--note", "drill"],
        Some("fake-rotated-value-999999"),
    );
    assert!(out.contains("rotated"), "{out}");
    let show = e.ok(&["show", "STRIPE_KEY", "--env", "dev"], None);
    assert!(show.contains("last_rotated"), "{show}");
    assert_eq!(show.matches("[[history]]").count(), 2, "{show}");
    assert!(show.contains("drill"));

    // Import does not overwrite a differing value unless asked.
    let f = e.write("again.env", &format!("STRIPE_KEY={DEV}\n"));
    let out = e.ok(&["import", f.to_str().unwrap(), "--env", "dev"], None);
    assert!(out.contains("differs"), "{out}");
    let check = "[ \"$STRIPE_KEY\" = fake-rotated-value-999999 ] && echo kept";
    let out = e.shtum(&["run", "--env", "dev", "--", "sh", "-c", check], None);
    assert!(String::from_utf8_lossy(&out.stdout).contains("kept"));
}

#[test]
fn metadata_is_editable_except_what_shtum_maintains() {
    let e = Env::new();
    e.with_secrets();
    e.ok(
        &[
            "meta",
            "RESEND_API_KEY",
            "--env",
            "prod",
            "provider=Resend",
            "rotate_every_days=90",
            "limits=3000/day",
            "region=eu",
        ],
        None,
    );
    let show = e.ok(&["show", "RESEND_API_KEY", "--env", "prod"], None);
    for want in [
        "provider = \"Resend\"",
        "rotate_every_days = 90",
        "limits = \"3000/day\"",
        "region = \"eu\"",
    ] {
        assert!(show.contains(want), "{want} missing:\n{show}");
    }
    assert!(
        !e.shtum(
            &["meta", "RESEND_API_KEY", "--env", "prod", "fingerprint=x"],
            None
        )
        .status
        .success()
    );
    assert!(
        !e.shtum(&["meta", "../../etc", "--env", "prod", "provider=x"], None)
            .status
            .success()
    );
}

#[test]
fn due_lists_what_is_overdue() {
    let e = Env::new();
    e.with_secrets();
    e.ok(
        &[
            "meta",
            "RESEND_API_KEY",
            "--env",
            "prod",
            "expires=2020-01-01",
        ],
        None,
    );
    let out = e.ok(&["due"], None);
    assert!(
        out.contains("RESEND_API_KEY") && out.contains("OVERDUE"),
        "{out}"
    );
    assert!(out.contains("No rotation policy"), "{out}");
}

#[test]
fn reveal_and_backup_key_refuse_without_a_terminal() {
    let e = Env::new();
    e.with_secrets();
    for args in [
        vec!["reveal", "RESEND_API_KEY", "--env", "prod"],
        vec!["backup-key", "--env", "prod"],
    ] {
        let out = e.shtum(&args, None);
        assert!(!out.status.success());
        assert!(
            text(&out).contains("only runs at a terminal"),
            "{}",
            text(&out)
        );
        assert!(!text(&out).contains(LIVE) && !text(&out).contains("AGE-SECRET-KEY"));
    }
}

#[test]
fn a_project_file_chooses_the_env() {
    let e = Env::new();
    e.with_secrets();
    let out = e.shtum(&["run", "--", "true"], None);
    assert!(
        !out.status.success() && text(&out).contains("which env"),
        "{}",
        text(&out)
    );
    e.write(".shtum.toml", "env = \"dev\"\nonly = [\"STRIPE_KEY\"]\n");
    let out = e.shtum(
        &[
            "run",
            "--",
            "sh",
            "-c",
            "[ -n \"$STRIPE_KEY\" ] && [ -z \"$RESEND_API_KEY\" ] && echo scoped",
        ],
        None,
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("scoped"),
        "{}",
        text(&out)
    );
}

#[test]
fn fly_sync_pipes_values_to_fly_and_masks_its_output() {
    let e = Env::new();
    e.with_secrets();
    let bin = e.dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let got = e.dir.path().join("fly-stdin");
    let fake = format!(
        "#!/bin/sh\necho \"args: $*\"\ncat > {}\ncat {}\n",
        got.display(),
        got.display()
    );
    let fly = bin.join("fly");
    std::fs::write(&fly, fake).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fly, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut c = e.cmd(&[
        "fly",
        "sync",
        "--env",
        "prod",
        "--app",
        "my-api",
        "--only",
        "RESEND_API_KEY,STRIPE_KEY",
        "--stage",
    ]);
    c.env(
        "PATH",
        format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
    );
    let out = e.run(c, None);
    assert!(out.status.success(), "{}", text(&out));
    let printed = text(&out);
    assert!(
        printed.contains("args: secrets import -a my-api --stage"),
        "{printed}"
    );
    assert!(
        printed.contains("RESEND_API_KEY=[shtum:RESEND_API_KEY]"),
        "{printed}"
    );
    assert!(!printed.contains(LIVE));
    let sent = std::fs::read_to_string(&got).unwrap();
    assert_eq!(sent, format!("RESEND_API_KEY={LIVE}\nSTRIPE_KEY={DEV}\n"));
    assert!(
        e.ok(&["show", "RESEND_API_KEY", "--env", "prod"], None)
            .contains("fly:my-api")
    );
}

#[test]
fn the_hook_denies_through_the_binary() {
    let e = Env::new();
    e.with_secrets();
    let call = |cmd: &str| {
        let body =
            serde_json::json!({"tool_name": "Bash", "tool_input": {"command": cmd}}).to_string();
        String::from_utf8(e.shtum(&["hook"], Some(&body)).stdout).unwrap()
    };
    assert!(call("cat .env").contains("\"permissionDecision\":\"deny\""));
    assert!(call("shtum run --env dev -- sh -c 'echo $STRIPE_KEY'").contains("deny"));
    assert_eq!(call("shtum run --env dev -- npm test"), "");
    assert_eq!(e.shtum(&["hook"], Some("not json")).stdout, b"");
}

#[test]
fn the_mcp_server_answers_and_never_returns_a_value() {
    let e = Env::new();
    e.with_secrets();
    let msgs = [
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}),
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_secrets","arguments":{}}}),
        serde_json::json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"show_secret","arguments":{"name":"RESEND_API_KEY"}}}),
        serde_json::json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"update_secret","arguments":{"name":"RESEND_API_KEY","env":"prod","fields":{"plan":"Pro","used_by":["my-api"]}}}}),
        serde_json::json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"write_doc","arguments":{"name":"resend","content":"# Resend\nRotate at resend.com/api-keys"}}}),
        serde_json::json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_doc","arguments":{"name":"../shtum"}}}),
    ];
    let input: String = msgs.iter().map(|m| format!("{m}\n")).collect();
    let out = e.shtum(&["mcp"], Some(&input));
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        lines.len(),
        7,
        "one reply per request, none for the notification"
    );
    assert_eq!(lines[0]["result"]["serverInfo"]["name"], "shtum");
    assert_eq!(lines[1]["result"]["tools"].as_array().unwrap().len(), 8);
    assert!(
        lines[2]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("RESEND_API_KEY")
    );
    assert!(
        lines[4]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("plan = \"Pro\"")
    );
    assert_eq!(lines[6]["result"]["isError"], true);
    let all = String::from_utf8_lossy(&out.stdout);
    assert!(!all.contains(LIVE) && !all.contains(DEV));
    assert!(e.ok(&["doc", "show", "resend"], None).contains("Rotate at"));
}

#[test]
fn a_declared_secret_waits_in_its_folder_for_a_value() {
    let e = Env::new();
    e.with_secrets();
    // declare two Stripe keys with no value, in a folder, with what is known about them
    let out = e.ok(
        &[
            "add",
            "STRIPE_SECRET_KEY",
            "--env",
            "prod",
            "--folder",
            "stripe",
            "provider=Stripe",
            "dashboard=https://dashboard.stripe.com/apikeys",
        ],
        None,
    );
    assert!(
        out.contains("Declared STRIPE_SECRET_KEY in prod (folder stripe), no value yet"),
        "{out}"
    );
    e.ok(
        &[
            "add",
            "STRIPE_WEBHOOK_SECRET",
            "--env",
            "prod",
            "--folder",
            "stripe",
        ],
        None,
    );
    // a second declaration of the same name, and a folder that names a path, are refused
    assert!(
        !e.shtum(&["add", "STRIPE_SECRET_KEY", "--env", "prod"], None)
            .status
            .success()
    );
    assert!(
        !e.shtum(
            &["add", "X_KEY", "--env", "prod", "--folder", "../etc"],
            None
        )
        .status
        .success()
    );
    // no value file exists for them
    let files = files_under(&e.home());
    assert!(
        files
            .iter()
            .any(|f| f.ends_with("prod/STRIPE_SECRET_KEY.toml"))
    );
    assert!(
        !files
            .iter()
            .any(|f| f.ends_with("prod/STRIPE_SECRET_KEY.age"))
    );

    // ls groups by folder and says what has no value; --folder narrows it
    let ls = e.ok(&["ls"], None);
    assert!(ls.contains("stripe/") && ls.contains("(no folder)"), "{ls}");
    assert!(
        ls.lines()
            .any(|l| l.contains("STRIPE_SECRET_KEY") && l.contains("no value yet")),
        "{ls}"
    );
    let only = e.ok(&["ls", "--folder", "stripe"], None);
    assert!(
        only.contains("STRIPE_WEBHOOK_SECRET") && !only.contains("RESEND_API_KEY"),
        "{only}"
    );
    let show = e.ok(&["show", "STRIPE_SECRET_KEY", "--env", "prod"], None);
    assert!(
        show.contains("value: none yet") && show.contains("folder = \"stripe\""),
        "{show}"
    );
    assert!(e.ok(&["due"], None).contains("Declared, no value yet (2)"));

    // a run over the whole env leaves them out and says so; naming one refuses
    let run = e.shtum(&["run", "--env", "prod", "--", "sh", "-c", "echo ok"], None);
    assert!(run.status.success(), "{}", text(&run));
    assert!(
        text(&run).contains("declared without a value, left out"),
        "{}",
        text(&run)
    );
    let named = e.shtum(
        &[
            "run",
            "--env",
            "prod",
            "--only",
            "STRIPE_SECRET_KEY",
            "--",
            "true",
        ],
        None,
    );
    assert!(!named.status.success());
    assert!(
        text(&named).contains("has no value yet"),
        "{}",
        text(&named)
    );
    let fly = e.shtum(
        &[
            "fly",
            "sync",
            "--env",
            "prod",
            "--app",
            "x",
            "--only",
            "STRIPE_WEBHOOK_SECRET",
        ],
        None,
    );
    assert!(
        !fly.status.success() && text(&fly).contains("has no value yet"),
        "{}",
        text(&fly)
    );

    // the first set fills it: added, not a rotation, the record kept
    let set = e.ok(
        &["set", "STRIPE_SECRET_KEY", "--env", "prod"],
        Some("sk_live_filled_123\n"),
    );
    assert!(set.contains("STRIPE_SECRET_KEY in prod: added."), "{set}");
    let show = e.ok(&["show", "STRIPE_SECRET_KEY", "--env", "prod"], None);
    assert!(
        show.contains("provider = \"Stripe\"") && show.contains("folder = \"stripe\""),
        "{show}"
    );
    assert!(
        !show.contains("last_rotated") && show.contains("value: stored"),
        "{show}"
    );
    // an import fills a declared secret without --overwrite: a first value, not a differing one
    let f = e.write(
        "hook.env",
        "STRIPE_WEBHOOK_SECRET=whsec_from_the_file_456\n",
    );
    let imp = e.ok(&["import", f.to_str().unwrap(), "--env", "prod"], None);
    assert!(
        imp.lines()
            .any(|l| l.starts_with("STRIPE_WEBHOOK_SECRET") && l.contains("added")),
        "{imp}"
    );
    // set --folder files a secret too
    e.ok(
        &["set", "NEW_KEY", "--env", "dev", "--folder", "misc"],
        Some("v1\n"),
    );
    assert!(e.ok(&["ls", "--folder", "misc"], None).contains("NEW_KEY"));
    // and nothing anywhere printed the value
    for args in [&["ls"][..], &["show", "STRIPE_SECRET_KEY"], &["due"]] {
        assert!(!e.ok(args, None).contains("sk_live_filled_123"));
    }
}

#[test]
fn the_mcp_server_declares_without_a_value() {
    let e = Env::new();
    let msgs = [
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"declare_secret","arguments":{"name":"STRIPE_SECRET_KEY","env":"prod","folder":"stripe","fields":{"provider":"Stripe"}}}}),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_secrets","arguments":{"folder":"stripe"}}}),
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"declare_secret","arguments":{"name":"STRIPE_SECRET_KEY","env":"prod"}}}),
    ];
    let input: String = msgs.iter().map(|m| format!("{m}\n")).collect();
    let out = e.shtum(&["mcp"], Some(&input));
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let t = |i: usize| {
        lines[i]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert!(
        t(0).contains("Declared STRIPE_SECRET_KEY in prod, no value yet"),
        "{}",
        t(0)
    );
    assert!(
        t(1).contains("STRIPE_SECRET_KEY") && t(1).contains("no value yet"),
        "{}",
        t(1)
    );
    assert_eq!(
        lines[2]["result"]["isError"], true,
        "a second declaration is refused"
    );
    assert!(!files_under(&e.home()).iter().any(
        |f| f.extension().is_some_and(|x| x == "age") && f.to_string_lossy().contains("STRIPE")
    ));
}
