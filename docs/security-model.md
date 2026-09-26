# Security Model

What context-snooper guarantees, what it deliberately does not, and why.
Read this before relying on it for production credentials.

---

## 1. Threat Model

**Primary threat:** secrets present in the agent's context being transmitted to
**remote LLM provider endpoints** (and third parties they trust with the
payload).

**In scope:**
- Everything serialized into outbound LLM requests: user prompts, assistant
  history, thinking blocks, tool results, tool-call arguments, compaction
  summaries, bash outputs, extension-injected messages.
- Local tool execution that would *echo* a secret back into context
  (the echo loop, see §4.4).
- LLM-driven exfiltration via the broker (prompt injection tricking the agent
  into running `curl … <secret>`).

**Out of scope (by explicit decision):**
- Malicious or buggy *local* code sharing the Pi process (other extensions,
  debuggers, same-user processes). The vault is plain in-memory; no OS-level
  isolation is provided.
- Secrets inside **images** (screenshots, pasted PNGs, base64 image blocks).
  No OCR is performed.
- Secrets in **thinking blocks** on replay: thinking is detected and flagged
  by `/snoop`, but not redacted, because providers replay thinking under
  cryptographic signatures and mutating it can break provider requests.
- **Tool egress in general**: a custom tool that sends its arguments somewhere
  is not intercepted (only the broker's expansion policy applies).

---

## 2. Guarantees

### 2.1 Redaction is on the send path, not a filter
Redaction happens in the `context` lifecycle hook — *after* Pi has assembled
the exact payload, *before* it is dispatched. If a hook fails to run, the
request does not go out. There is no "scan-and-hope" window.

### 2.2 Detection quality
- **Catalog / allowlist matches (HMAC + exact value): deterministic, zero
  false positives.** If the value is in your lists, the decision is exact.
- **Pattern matches:** high precision for the supported shapes
  (`AKIA…`, `ghp_…`, `sk-…`, PEM headers, `FAKE_DB_…`).
- **Entropy matches:** best-effort heuristic (≥3.8 bits/char, char diversity,
  length 16–96) with guards against UUIDs, 32/40/64-hex digests.
  Expect occasional false positives (which `/snoop` exists to absorb) and
  misses for human-choosen passphrases that look like ordinary words.

### 2.3 Storage safety
- List files store **HMAC ids + labels, never plaintext** (after
  classification).
- The HMAC key is the trust anchor: without it, ids are meaningless.
  The project key is auto-`.gitignore`d; the global key is `0600`.
- Redaction is **request-local**: the Pi session file keeps original text
  (that's Pi's design; it makes `/resume` and audit work). Treat session
  files as sensitive, on par with `.env`.

### 2.4 Invariants
- A value can never be both allowlisted and protected: at load time the
  allowlist wins; `/snoop fix` persists the invariant; classification is
  mutual-exclusion by construction.
- Built-in code defaults never leak into user-managed files.
- The agent cannot "learn" a placeholder's real value through the model:
  the value only ever reaches Pi-local code (vault → tool boundary).
- **No silent use of unreviewed secrets**: `write`/`edit` auto-expand only
  placeholders whose id is a classified `Protected` catalog entry; anything
  unclassified (or disallowed) always requires a visible confirmation, even in
  auto-expand tools (`canAutoExpand`).

---

## 3. The Echo Loop (and why it's closed)

The dangerous sequence: broker expands `[REDACTED_SECRET:x]` → tool runs →
tool prints the plaintext → result enters context → next LLM call.

The loop is closed because the **same `context` hook that redacts outbound
payloads re-scans every turn**, including tool results that just arrived. The
plaintext exists for the duration of one local tool execution and is
re-masked before the next request. Net effect: the remote model has never
seen the raw value.

---

## 4. Known Residual Risks

Be explicit about these; they are where this tool is *defense-in-depth, not a
cage*.

1. **Images.** A screenshot of a terminal containing the secret bypasses
   every text detector. Mitigation: don't paste screenshots of secret-bearing
   screens; treat images as untrusted inputs.
2. **Session files & exports.** `~/.pi/agent/sessions/*.jsonl` contains
   originals by design. `/export`, `/share`, and `/bug` can exfiltrate them.
   Review before sharing; keep session dirs out of version control and backups
   you don't control.
3. **Thinking replay.** Some providers sign thinking blocks; we don't mutate
   them. A secret already inside a thinking block from *before* redaction was
   enabled (e.g. an older resumed session) may travel with the signature.
   Start a fresh session when switching on redaction for sensitive work.
4. **Tool egress.** Custom tools are free to send arguments where they like.
   The broker's confirmation prompt covers *placeholder expansion* into
   non-file tools; it does not police arbitrary tool behavior.
5. **Local code isolation.** The vault lives in Pi's process. Any code running
   as your user with access to that process (other extensions, debuggers) can
   read it. This is an accepted trade-off for zero IPC latency; if your threat
   model includes hostile local code, move the vault behind an OS keychain or
   a separate authenticated helper process.
6. **Heuristic misses.** Entropy is a detector, not a proof. Low-entropy
   passwords and semantically secret words that lack structure are only
   caught if you've cataloged them (HMAC exact-match). **Catalog your
   organization's real credentials** — that's the layer with 100% precision.

---

## 5. Verification Checklist

To confirm the protection is active in a given session:

1. **Catalog a fake value** (e.g. add `snoop_canary_123!` via `/snoop`).
2. **Echo it through the agent**: ask it to read a file containing it, or
   paste it.
3. **Check redaction**: the warning notification fires; the model's visible
   response quotes `[REDACTED_SECRET:<id>]`, not the value.
4. **Check broker auto-expansion**: classify the canary as `Protected`, then ask
   the agent to write the placeholder into a local file; confirm the real value
   lands in the file with no confirmation dialog.
5. **Check disallowed refusal**: classify the canary as `Disallowed`, ask the
   agent to write it; the file should contain the literal
   `[REDACTED_SECRET:<id>]` placeholder.
6. **Inspect storage**:
   ```bash
   cat secrets-catalog.json   # id + label, no plaintext
   cat secrets-allowlist.json
   ```
7. **Audit the list**: `/snoop list` should show `[PROTECTED]` /
   `[DISALLOWED]` / `[ALLOWED]` as expected.

---

## 6. What "Prevention" Does and Doesn't Mean

This tool **prevents** the default, automated path: agent turns that would
otherwise carry a secret to the provider now carry a placeholder instead.

It does **not** make the machine "leak-proof." It removes the *accidental*
channel and makes *deliberate* channels (image paste, session export, a
prompt-injected tool call that gets approved) require an explicit, visible
human action.

Treat secrets that enter context as **compromised-local**. The catalog/allowlist
files and session logs are now your source of truth for *which* credentials
were present, so you can rotate them deliberately rather than by guessing.
