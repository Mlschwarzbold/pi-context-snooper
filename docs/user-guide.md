# Context-Snooper User Guide

A practical reference for day-to-day use of the context-snooper extension.
See the root `README.md` for project history and architecture.

---

## 1. Installation

```bash
# One-off (development)
pi --extension /path/to/context-snooper/index.ts
```

Permanent load (choose one):

```bash
# User-wide: symlink or copy into your personal extensions dir
cp index.ts ~/.pi/agent/extensions/context-snooper.ts

# Project-local
mkdir -p .pi/extensions && cp index.ts .pi/extensions/context-snooper.ts
```

No build step is required — Pi loads TypeScript extensions directly via `jiti`.
The only dependency is the `@earendil-works/pi-coding-agent` type package (already
present in any Pi installation).

---

## 2. The Five Statuses

Every secret the scanner finds carries exactly one status:

| Status | Badge | Where it's stored | Sent to LLM? | Agent may use it? |
|---|---|---|---|---|
| `UNCLASSIFIED` | yellow | (nowhere yet — needs review) | No (redacted) | No — broker asks for confirmation even for `write`/`edit` |
| `PROTECTED` | red | `secrets-catalog.json` (`use: "expand"`) | No (redacted) | **Yes**, with policy (auto for `write`/`edit`, confirmation otherwise) |
| `DISALLOWED` | magenta | `secrets-catalog.json` (`use: "deny"`) | No (redacted) | **Never** — broker refuses expansion |
| `ALLOWED` | green | `secrets-allowlist.json` | **Yes** (as-is) | n/a (it's intentionally visible) |
| `FALSE POSITIVE` | cyan | `secrets-allowlist.json` | **Yes** (as-is) | n/a (it was never a secret) |

---

## 3. Day-to-Day Workflow

### 3.1 First time in a project

1. Start Pi with the extension loaded.
2. Do your work. Whenever a secret enters the context (reading a `.env`, a tool
   printing a token, you pasting a key), you'll see one warning notification:
   `[Snoop] Redacting N secret(s) before LLM call. Run /snoop to classify.`
3. Run `/snoop`:
   - It lists **only unclassified** secrets, color-coded, grouped by value
     (`×3 (msgs #2, #5, #9)` = one secret seen in three places).
   - Pick a secret and choose one of the four actions. A label prompt appears
     with a smart default (e.g. `AWS Access Key`) — **Enter accepts it**.
4. When done: `No unclassified secrets in context. Run '/snoop list' to view all.`

### 3.2 Choosing the right action

- **Protected** — it's a real credential you don't want the model to *see*, but
  the agent may still *use* it (write it to a config, pass it to a local tool).
- **Disallowed** — it's a real credential the agent must **never** use
  (production passwords, other people's tokens). It stays redacted and the
  broker refuses to expand it anywhere.
- **Allowed** — you *want* the model to see this value (public-looking test
  fixtures, mock keys, staging tokens you deliberately exposed).
- **False Positive** — the scanner misfired (a build token, a UUID-like
  identifier, a hash). Whitelisting stops the noise.

### 3.3 Auditing

- `/snoop list` — every secret in the context, all statuses, color-coded.
- Verify on-disk state any time:
  ```bash
  cat secrets-catalog.json   # id + label only — no plaintext
  cat secrets-allowlist.json
  ```

### 3.4 Fixing hand-edited files

If you (or a teammate, or a script) edited the JSON files by hand and broke an
invariant (a secret in both lists, a stale duplicate, a missing `id`):

```
/snoop fix
```

Reconciles both files: allowlist wins, built-in defaults are stripped from the
catalog file, missing ids are filled in, duplicates removed. Idempotent.

---

## 4. Command Reference

| Command | Effect |
|---|---|
| `/snoop` | List & classify **unclassified** secrets |
| `/snoop list` | List **all** secrets, color-coded |
| `/snoop fix` | Reconcile hand-edited list files |
| `/snoop salt` | View / set / generate the HMAC key |
| `/snoop salt <key>` | Set the **project** key (`.pi-hmac-key` in cwd) |
| `/snoop salt --global <key>` | Set the **global** key (`~/.pi/context-snooper.key`) |
| `/snoop help` | In-terminal help menu |

Tab completion is registered for all subcommands.

---

## 5. The Files

| File | Scope | Contents |
|---|---|---|
| `secrets-catalog.json` (cwd) | project | protected + disallowed entries: `{ id, label, status, use, source, addedAt }` — **no plaintext** |
| `secrets-allowlist.json` (cwd) | project | allowed + false-positive entries: `{ id, label, decision, source, addedAt }` — **no plaintext** |
| `.pi-hmac-key` (cwd) | project | project HMAC key. Auto-added to `.gitignore` when created by the extension |
| `~/.pi/context-snooper.key` | user | global HMAC key, written `0600` |
| `CONTEXT_SNOOPER_KEY` / `ORG_HMAC_KEY` env | explicit | overrides everything; use for team-shared keys |

Invariants (enforced at load time, persisted by `/snoop fix`):

- **Allowlist always wins** — a value in both lists is treated as allowed.
- **User-managed files only** — built-in defaults live in code and never land in `secrets-catalog.json`.
- **One status per value** — classifying a secret removes it from the opposite list.

---

## 6. Team / Organization Setup

The HMAC key makes team sharing safe:

1. **Generate one org key** (any long random string, e.g. `openssl rand -hex 32`).
2. **Distribute it once** through your existing secret store (1Password, Doppler,
   AWS Secrets Manager…) — never commit it.
3. **Set it** in each developer's environment:
   ```bash
   export ORG_HMAC_KEY="..."
   ```
   or place it as `.pi-hmac-key` in the repo and keep it **out** of git
   (or use a private "snooper-keys" repo synced to `<cwd>/.pi-hmac-key`).
4. **Share the catalog**: with a shared key, `secrets-catalog.json` (ids +
   labels, no plaintext) can be committed to the repository. Every team member's
   agent then protects the same set of credentials automatically.
5. **Rotate** credentials the usual way; rotate the org key only when someone
   leaves or the key leaks — existing ids must be re-issued (`/snoop fix`
   after re-classifying).

> ⚠️ Changing the key invalidates all existing ids. The extension warns you
> before updating if lists already contain entries.

---

## 7. The Agent's Experience

At session start the agent receives a short, hidden standing note:

> Secret redaction is active in this session (context-snooper).
> Credentials are replaced with `[REDACTED_SECRET:<id>]` placeholders…
> Use them verbatim… Do NOT attempt to guess, reconstruct, probe, or test
> placeholder values…

So the agent treats placeholders as expected behavior instead of
investigating them. The note is invisible in the transcript
(`display: false`) but present in LLM context for the whole session.

When the agent writes `[REDACTED_SECRET:ab12cd34]` into a `write`/`edit`
tool call, the **secret broker** restores the real value *locally* before
execution — but **only for secrets you classified as `Protected`**. Anything
unclassified still triggers a confirmation dialog in every tool (it hasn't
been reviewed, so the agent shouldn't get to use it silently). For `bash`,
`powershell`, and custom tools, classified-protected secrets get the same
confirmation dialog, showing exactly what will run with the secret expanded.
`DISALLOWED` secrets are never expanded — the tool receives the literal
placeholder and fails safely.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Secret no longer redacted after changing the key | Old ids no longer match. Re-classify the secret (`/snoop`) under the new key. |
| `/snoop fix` reports "dropped N built-in default(s)" | Your catalog file contained a value that lives in code (`DEFAULT_CATALOG`). Normal — the file is user-managed only. |
| Confirmation dialog never appears in CI/print mode | Expected: non-interactive modes never expand placeholders. |
| Two projects must use different catalogs | They have different cwds → different files. Nothing to do. |
| Model says "I can't use the key" | It can't *see* it — that's correct. Classify it as `Protected` first; the broker then auto-expands it for local file writes (shell usage still confirms). |
