//! Asking the person to be there.
//!
//! A protected env (prod) is decrypted only after the person proves they are at the machine:
//! Touch ID, or the login password when there is no sensor (`LAPolicyDeviceOwnerAuthentication`).
//! An agent cannot answer that prompt, which is the point — it can start `shtum run --env prod`,
//! and nothing happens until the person looks up and agrees.
//!
//! Off macOS the fallback is typing the env's name on `/dev/tty`, which a process with no
//! controlling terminal — every agent's shell — cannot open.

use anyhow::{Result, bail};

/// `test_ok` is true only for the file keyring. Even then the override is honoured only in a
/// debug build, so no environment variable can skip the prompt in a release binary.
pub fn confirm(reason: &str, test_ok: bool) -> Result<()> {
    #[cfg(debug_assertions)]
    if test_ok && let Ok(v) = std::env::var("SHTUM_TEST_PRESENCE") {
        return if v == "allow" {
            Ok(())
        } else {
            bail!("not confirmed (test)")
        };
    }
    let _ = test_ok;
    platform(reason)
}

#[cfg(target_os = "macos")]
fn platform(reason: &str) -> Result<()> {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::sync::mpsc;
    use std::time::Duration;

    let (tx, rx) = mpsc::channel::<bool>();
    let reply = RcBlock::new(move |ok: Bool, _err: *mut NSError| {
        let _ = tx.send(ok.as_bool());
    });
    let ctx = unsafe { LAContext::new() };
    let text = NSString::from_str(reason);
    unsafe {
        ctx.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &text,
            &reply,
        );
    }
    eprintln!("shtum: waiting for Touch ID or your password…");
    match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(true) => Ok(()),
        Ok(false) => bail!("not confirmed — this env needs you present (Touch ID or password)"),
        Err(_) => {
            unsafe { ctx.invalidate() };
            bail!("timed out waiting for Touch ID or your password")
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn platform(reason: &str) -> Result<()> {
    use std::io::{BufRead, BufReader, Write};
    let env = reason
        .rsplit('(')
        .next()
        .unwrap_or("")
        .trim_end_matches(')')
        .to_string();
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty");
    let Ok(mut tty) = tty else {
        bail!("this env needs you present, and there is no terminal to ask on");
    };
    write!(tty, "{reason}\nType {env:?} to continue: ")?;
    let mut line = String::new();
    BufReader::new(tty.try_clone()?).read_line(&mut line)?;
    if line.trim() == env {
        Ok(())
    } else {
        bail!("not confirmed")
    }
}
