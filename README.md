# shtum

shtum keeps API keys for people who work with AI agents. Agents can read and update everything about a key except the key itself. (*Keep shtum: say nothing.*)

## Why

Anything an agent reads is sent to a model and saved in a transcript on disk. A key an agent once read from a `.env` file stays in plain text in a log you will never clean up.

Agents are still good at tracking what surrounds a key: its provider, dashboard, rate limit, last rotation, and which services break if it changes. shtum lets them keep that record without ever seeing a value.

## How it works

- **Metadata is open to agents.** Provider, dashboard, owner, plan, limits, users, rotation policy, expiry, notes and docs. Agents read it and add to it as they learn.
- **Values never reach an agent.** A value goes only into a program's environment (`shtum run`) or a deploy target (`shtum fly sync`).
- **Output is masked.** Any output that is not your terminal shows each value as `[shtum:NAME]`.
- **Printing a value is guarded.** The one command that prints a value needs a terminal and Touch ID.

shtum is one local Rust binary. Values are encrypted with [age](https://age-encryption.org), a file-encryption tool, and the encryption keys are kept in the macOS Keychain.

## Requirements

- macOS (the Keychain and Touch ID protect the keys)
- Rust 1.88 or later

## Install

1. Install the binary:

   ```sh
   cargo install --git https://github.com/EruditeCoder/shtum
   ```

   From a clone, `cargo install --path .` does the same.

2. Create the vault:

   ```sh
   shtum init
   ```

   This creates `~/.shtum/vault` with two **envs** (named sets of values): `dev` and `prod`. `prod` is **protected**: using, replacing or deleting one of its values asks for Touch ID or your password. Add another env with `shtum env add staging --protected`.

3. Back up each env's private key to a password manager or paper. It exists only in this Mac's Keychain, so losing the Mac without a copy means losing the values.

   ```sh
   shtum backup-key --env prod
   shtum backup-key --env dev
   ```

## Usage

### Add values

```sh
# Import an existing .env. Prints names, never values.
shtum import ../my-api/.env --env dev --skip PORT,NODE_ENV

# Add or rotate one value from a hidden prompt or stdin
shtum set RESEND_API_KEY --env prod
```

### Describe keys

Agents can do this too.

```sh
shtum meta RESEND_API_KEY --env prod provider=Resend dashboard=https://resend.com/api-keys \
  rotate_every_days=90 limits="3,000 emails/day on Pro" used_by=my-api
```

### List keys and rotations

```sh
shtum ls                 # everything, grouped by folder, with rotation status
shtum show RESEND_API_KEY
shtum due                # overdue, due within 14 days, and keys with no rotation policy
```

### Declare keys before you have them

`shtum add` records a key and what is known about it, in a folder, without taking a value. An agent can do this; you fill in the value at your terminal.

```sh
shtum add STRIPE_SECRET_KEY --env prod --folder stripe provider=Stripe \
  dashboard=https://dashboard.stripe.com/apikeys used_by=my-api
shtum ls --folder stripe                 # STRIPE_SECRET_KEY ... no value yet
shtum set STRIPE_SECRET_KEY --env prod   # hidden prompt; the first value is "added", not a rotation
```

A declared key with no value is skipped by `shtum run` and `shtum fly sync` over a whole env, and they say which keys they skipped. Naming one with `--only` refuses and shows the `shtum set` command that fills it.

### Run programs

```sh
shtum run --env dev -- npm run dev
shtum run --env dev --only RESEND_API_KEY -- node scripts/send-test.js
```

To skip the flags, name the env and keys in the project's `.shtum.toml`. Then `shtum run -- npm test` works on its own:

```toml
env = "dev"
only = ["RESEND_API_KEY", "STRIPE_SECRET_KEY"]   # optional; default is the whole env
```

### Deploy to Fly.io

```sh
shtum fly sync --env prod --app my-api --stage
```

### Rotations

Replacing a value with `shtum set` records a rotation. `last_rotated` moves to today, and the history gains the new value's **fingerprint**: a salted hash prefix that shows whether two copies match without revealing either.

## Agent setup

1. Run:

   ```sh
   shtum setup
   ```

2. Paste the two commands it prints. One installs the hook in `~/.claude/settings.json`; the other registers the MCP server. shtum never edits your agent settings itself.

3. Optionally, add this line to a project's `CLAUDE.md`:

   > Secrets are in shtum. Never read a `.env` file. `shtum ls` and `shtum show NAME` say what exists; run programs with `shtum run -- <command>`; when you learn something about a key, record it with `shtum meta` or the shtum MCP tools.

### The hook

A Claude Code `PreToolUse` hook runs before each tool call and can refuse it. shtum's hook refuses:

- reading `.env` files with Read, Grep or shell readers
- `shtum reveal` and `shtum backup-key`
- reading or deleting shtum's Keychain items
- `env` or `printenv` under `shtum run`
- a command that expands `$SECRET_NAME` itself

Each refusal tells the agent what to do instead.

### The MCP server

An MCP (Model Context Protocol) server gives agents tools to call. shtum's tools are `list_secrets`, `show_secret`, `declare_secret`, `update_secret`, `rotation_due`, `list_docs`, `read_doc` and `write_doc`. None of them can take or return a value.

## Where things live

```
~/.shtum/                      SHTUM_HOME overrides
  vault/                       safe to keep in a private git repo
    shtum.toml                 envs, which are protected, each env's public key
    secrets/<env>/<NAME>.toml  metadata (plaintext)
    secrets/<env>/<NAME>.age   the value, encrypted
    docs/<name>.md             notes, runbooks
```

Private keys are never in `vault/`. They are in the macOS Keychain, under service `shtum.<vault id>`, one item per env. With `SHTUM_KEYRING=file` (for tests, and the only option off macOS) they are 0600 files in `~/.shtum/identities/`.

## Limitations

- **Metadata is not encrypted.** The vault shows which services you use, so keep its repo private.
- **macOS first.** Off macOS, private keys are files, without the Keychain or Touch ID.

## Security

[SECURITY.md](SECURITY.md) covers what shtum protects against, what it does not, and what was measured rather than assumed.

## License

MIT
