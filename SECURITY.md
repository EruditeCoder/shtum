# Security

## The threat model, plainly

shtum is built against **accidental exposure by agents that mean well**: a coding agent that
reads a `.env` to "check the config", prints an environment while debugging, or runs a test that
logs a request header. Each of these puts a live key into a model's context and into a
transcript on disk, where it stays.

shtum is **not** a sandbox against a hostile process running as you. Anything that can run
`shtum run --env dev -- <its own program>` can have that program send the dev values anywhere.
The defences below make the accident hard. They do not make an attack impossible, and nothing
running as your user could.

## What protects what

| Risk | Defence |
|---|---|
| A value at rest on disk | Encrypted with age (X25519 + ChaCha20-Poly1305) to its env's key. Files are 0600, directories 0700. |
| The vault repo leaking | It holds ciphertext and metadata only. Private keys are in the Keychain, never in `vault/`. Metadata does reveal which providers you use. |
| An agent reading a value through shtum | No command prints a value except `reveal` and `backup-key`, which need a terminal on stdin and stdout and Touch ID. An agent's shell has neither. The MCP server has no code path to decryption. |
| A program printing a value it was given | `shtum run` masks every injected value of 8 or more characters as `[shtum:NAME]` whenever stdout or stderr is not a terminal. Masking works across chunk boundaries. |
| An agent reading a `.env` file | The hook refuses Read/Grep/shell readers on `.env`, `.env.*` and `*.env` (but not `.env.example` and similar). |
| Production used without you | Protected envs ask for Touch ID or your password (`LAPolicyDeviceOwnerAuthentication`) for every run, sync, reveal, replacement and deletion. There is no time-based caching. |
| Another program reading the Keychain item | Measured: `security find-generic-password -w` on shtum's item opens a macOS prompt instead of returning the key. The hook also refuses it. |
| Another program deleting the Keychain item | Measured: deleting needs **no** prompt. The hook refuses it, and `shtum backup-key` exists so a deleted or lost key can be restored. |
| Reading a child's environment with `ps` | Measured on macOS 26: `ps -E` / `ps eww` do not show another process's environment. |

## Known gaps

- Masking is literal. A value that is base64-encoded, URL-encoded, split or otherwise transformed
  before being printed gets through. Values shorter than 8 characters are not masked.
- At your own terminal nothing is masked: you are the one reading it.
- A program run under `shtum run` can write a value to a file, and an agent can then read that file.
- The hook matches command text, not the actual shell grammar. It is a guard rail and will
  miss creative spellings.
- The test-only override `SHTUM_TEST_PRESENCE` is compiled into **debug builds only** and only
  works with the file keyring. A release build ignores it.
- Each rebuild of the binary changes its code signature, so macOS asks again before letting it
  read the Keychain. That is expected.

## Reporting

Please open a private security advisory on the repository, or email the maintainer, rather than
filing a public issue.
