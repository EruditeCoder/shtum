//! Starting a program with secrets in its environment.
//!
//! This is the only way a value leaves shtum for an agent: into a child process's environment,
//! never onto shtum's own output. When the output is not a person's terminal, the child's
//! stdout and stderr pass through [`Redactor`] on the way out.

use crate::redact::Redactor;
use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use zeroize::Zeroizing;

pub type Value = Zeroizing<Vec<u8>>;

pub struct Job<'a> {
    pub program: &'a [String],
    /// Set in the child's environment.
    pub vars: &'a [(String, Value)],
    /// Written to the child's stdin and then closed; otherwise stdin is inherited.
    pub stdin: Option<Value>,
    /// Masked in the child's output. Usually the same values as `vars`.
    pub mask: &'a [(String, Value)],
}

static CHILD: AtomicI32 = AtomicI32::new(0);
static PIPED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn forward(sig: libc::c_int) {
    let pid = CHILD.load(Ordering::SeqCst);
    // At a terminal, Ctrl-C already reaches the child through the foreground process group;
    // sending it again would make a dev server skip its graceful shutdown.
    if pid > 0 && (sig != libc::SIGINT || PIPED.load(Ordering::SeqCst)) {
        unsafe { libc::kill(pid, sig) };
    }
}

pub fn at_a_terminal() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::isatty(1) == 1 && libc::isatty(2) == 1
    }
    #[cfg(not(unix))]
    false
}

/// Run the job and return the exit code to leave with.
pub fn run(job: Job) -> Result<i32> {
    let Some((prog, args)) = job.program.split_first() else {
        bail!("nothing to run — put the command after --, like: shtum run -- npm test");
    };
    let piped = !at_a_terminal();
    PIPED.store(piped, Ordering::SeqCst);

    let mut cmd = Command::new(prog);
    cmd.args(args);
    for (name, value) in job.vars {
        if value.contains(&0) {
            bail!("{name} contains a NUL byte and cannot go in an environment variable");
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            cmd.env(name, std::ffi::OsString::from_vec(value.to_vec()));
        }
        #[cfg(not(unix))]
        cmd.env(name, String::from_utf8_lossy(value).into_owned());
    }
    if job.stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    if piped {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let mut child = cmd.spawn().with_context(|| format!("starting {prog}"))?;
    CHILD.store(child.id() as i32, Ordering::SeqCst);
    #[cfg(unix)]
    unsafe {
        let h = forward as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGINT, h);
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGHUP, h);
    }

    let mut threads = vec![];
    if let Some(data) = job.stdin {
        let mut sink = child.stdin.take().expect("stdin was piped");
        threads.push(std::thread::spawn(move || {
            let _ = sink.write_all(&data);
        }));
    }
    if piped {
        let pairs = || job.mask.iter().map(|(n, v)| (n.as_str(), &v[..]));
        let out = child.stdout.take().expect("stdout was piped");
        let err = child.stderr.take().expect("stderr was piped");
        let (r1, r2) = (Redactor::new(pairs()), Redactor::new(pairs()));
        threads.push(std::thread::spawn(move || pump(out, r1, std::io::stdout())));
        threads.push(std::thread::spawn(move || pump(err, r2, std::io::stderr())));
    }

    let status = child.wait().context("waiting for the command")?;
    for t in threads {
        let _ = t.join();
    }
    CHILD.store(0, Ordering::SeqCst);
    if let Some(code) = status.code() {
        return Ok(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return Ok(128 + sig);
        }
    }
    Ok(1)
}

fn pump(mut from: impl Read, mut r: Redactor, mut to: impl Write) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let safe = r.push(&buf[..n]);
                if to.write_all(&safe).and_then(|_| to.flush()).is_err() {
                    return;
                }
            }
        }
    }
    let _ = to.write_all(&r.finish());
    let _ = to.flush();
}
