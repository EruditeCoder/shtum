# shtum

An agent-safe store for API keys and what is known about them. Read README.md and SECURITY.md.

## The rule

**No code path may give a value to an agent.** A value leaves shtum only into a child process's
environment (`run.rs`), into `fly secrets import`'s stdin (`fly_sync`), or onto a terminal after
Touch ID (`reveal`, `backup-key`). Before adding a command or an MCP tool, check that it cannot
print, return, log or error-message a value. Error messages name secrets, never contents.

## Working here

- `cargo test` runs unit tests and `tests/cli.rs`, which drives the binary on a temp vault with
  `SHTUM_KEYRING=file` and `SHTUM_TEST_PRESENCE=allow|deny`. That override exists only in debug
  builds (check: `grep -ac SHTUM_TEST_PRESENCE target/release/shtum` is 0).
- Never run the tests or a scratch vault without `SHTUM_HOME`: the default is the real vault.
- A test with the Keychain backend writes to the login Keychain; delete its items afterwards
  (`security delete-generic-password -s shtum.<id> -a <env>`). Anything touching a protected env
  without the file keyring opens a Touch ID prompt on the person's screen.
- No home-made cryptography: age does the encrypting.
- `cargo fmt` and `cargo clippy --all-targets` clean before committing.
