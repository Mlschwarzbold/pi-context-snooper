# Context Snooper

A security safeguard extension for the [Pi](https://pi.dev) coding agent that detects, catalogs, and prevents sensitive credentials from leaking to external LLM providers.

---

## Documentation

| Document | Audience |
|---|---|
| [`docs/user-guide.md`](docs/user-guide.md) | Operators — installation, daily workflow, command reference, file/team setup |
| [`docs/security-model.md`](docs/security-model.md) | Everyone relying on it — guarantees, residual risks, verification checklist |
| [`docs/developer-notes.md`](docs/developer-notes.md) | Maintainers — module map, data contracts, invariants, testing conventions |

This file is the project history: goals, what's done, architectural decisions, roadmap.

---

## 1. Project Overview & Idea

When working with terminal AI coding agents, sensitive information—such as database passwords in `.env` files, API tokens in configuration files, private keys, or command outputs—frequently enters the active conversation context. Once in context, these secrets are transmitted over the network to LLM provider endpoints.

**Context Snooper** acts as a local security boundary. It inspects the agent's active context window, identifies potential secrets through a combination of exact catalog matching, pattern matching, and Shannon entropy analysis, and gives developers full interactive control over what is protected versus what is allowed.

> **Important Security Note**: Context Snooper is designed as a **last layer of defense**, not a fail-proof solution. It should never substitute for safe credentials handling practices such as using environment variables, secret managers, or least-privilege access controls. Always treat this extension as an additional safety net rather than your primary security mechanism.

---

## 2. Goals

- **Zero-leakage protection**: Ensure sensitive credentials never leave the developer's machine in LLM request payloads.
- **Support for low-entropy & custom credentials**: Catch organizational secrets (e.g. database passwords) that lack standardized prefixes or high entropy.
- **Accurate classification & low noise**: Distinguish real credentials from common false positives (UUIDs, Git commit hashes, hex digests) and allow developers to mark exceptions easily.
- **Low latency**: In-process, delta-aware scanning that introduces negligible delay (<5ms) to agent turns.
- **Safe credential storage**: Support HMAC-hashed fingerprints so tracking and allowlisting secrets does not create a new local plaintext leak.

---

## 3. What Has Already Been Done (v1)

### Detection Pipeline
- **Exact Catalog Denylist**: Loads known secrets from `secrets-catalog.json` (plus built-in defaults) and performs substring checks to catch low-entropy credentials with 100% accuracy.
- **Pattern Matcher**: Catches well-known credential shapes using regular expressions:
  - AWS Access Keys (`AKIA...`)
  - GitHub Personal Access Tokens (`ghp_...`, `gho_...`, etc.)
  - OpenAI / Anthropic Keys (`sk-...`, `FAKE_sk-...`)
  - Prefixed Database Passwords (`FAKE_DB_...`)
  - PEM Private Key headers (`-----BEGIN ... PRIVATE KEY-----`)
- **Shannon Entropy Engine**:
  - Tokenizes context messages on whitespace, quotes, and syntax delimiters.
  - Automatically filters out common false positives: UUIDs, 32/40/64-character hex strings (Git commits, MD5/SHA digests), and tokens lacking character diversity.
  - Evaluates Shannon entropy ($H = -\sum p \log_2(p)$) with a threshold of $\ge 3.8$ bits/char.
- **Context Inspection**:
  - Extracts text across user prompts, assistant replies, internal model thinking blocks, tool execution results, and tool-call arguments.

### Interactive UI & Commands
- **`/snoop` (Default Mode)**:
  - Focused view: only scans and displays **unclassified secrets** requiring review.
  - If all secrets are classified, notifies the user immediately with zero clutter.
- **`/snoop list` (Audit Mode)**:
  - Comprehensive view: lists **all secrets** in the active context.
  - **Color-Coded Status Badges**:
    - `[PROTECTED]` (**Bold Red**): Catalog / denylist credentials.
    - `[DISALLOWED]` (**Bold Magenta**): Redacted AND broker-blocked — the agent may never use them.
    - `[ALLOWED]` (**Bold Green**): Approved secret exceptions.
    - `[FALSE POSITIVE]` (**Bold Cyan**): Non-secret tokens marked safe.
    - `[UNCLASSIFIED]` (**Bold Yellow**): Unreviewed candidates.
  - Selecting any entry allows inspecting or updating its classification.
- **`/snoop salt [value]` (Salt Management)**:
  - Run without arguments (`/snoop salt`) to view the current salt source and a masked preview (`a7f3...90d1`).
  - Interactive menu to set Project salt (`<cwd>/.pi-hmac-key`), set Global salt (`~/.pi/context-snooper.key`), or generate a cryptographically random 32-byte key.
  - Supports direct assignment: `/snoop salt <key>` or `/snoop salt --global <key>`.
  - Automatically adds `.pi-hmac-key` to `.gitignore` to prevent accidental commits of local project keys.
  - Checks if existing catalog/allowlist hashes exist and displays an invalidation confirmation before updating.
- **`/snoop help`**: In-terminal help menu listing all subcommands, statuses, and redaction/broker behavior.
- **`/snoop fix`**: One-shot reconciliation of hand-edited `secrets-catalog.json` / `secrets-allowlist.json` against the invariants: allowlist wins, built-in defaults stripped from the catalog file, missing HMAC ids filled in, duplicates removed. Idempotent; reports what it changed.
- **Agent-facing redactor note** (`session_start`): a short standing message is injected once per session via `pi.sendMessage(display: false)`. It is hidden in the TUI but participates in LLM context, telling the agent that `[REDACTED_SECRET:<id>]` placeholders are expected security behavior, must be used verbatim, and must never be probed or reconstructed — so the agent does not "go crazy" investigating them.
- **Five-Way Decision Menu**:
  - **Protected**: Saves secret HMAC to `secrets-catalog.json` (`use: "expand"`); removes from allowlist.
  - **Disallowed**: Saves secret HMAC to `secrets-catalog.json` (`use: "deny"`); removes from allowlist. Still redacted, but the broker refuses to expand its placeholder — the agent is never allowed to use it.
  - **Allowed**: Saves secret HMAC to `secrets-allowlist.json`; removes from catalog.
  - **False Positive**: Saves token to `secrets-allowlist.json`; removes from catalog.
  - **Dismiss**: Leaves existing configurations unchanged.
- **Smart Labels**: Prompts user with pre-filled default label (`ctx.ui.input`); pressing **Enter** accepts the default immediately.

### Verification & Testing
- Automated unit test suite (`test.ts`) using Node.js built-in `node:assert`.
- Zero external build dependencies; runs natively on Node.js 22.19+ and 24+.

---

## 4. Architectural Decisions

1. **In-Process Pi Extension**
   - Implemented as a TypeScript extension using Pi's extension runtime (`ExtensionAPI`).
   - Runs inside the Pi process via `jiti`, eliminating compilation steps.
   - Command output and dialogs (`ctx.ui.notify`, `ctx.ui.select`, `ctx.ui.confirm`) remain local to the terminal UI and **are never written to the session context or visible to the agent**.

2. **Decoupled Detection Core**
   - Detection logic (`shannonEntropy`, `scanText`, `scanMessages`, `extractTokens`) consists of pure functions independent of Pi's session runtime.
   - Enables fast, automated unit testing with mock message graphs without requiring a live Pi instance.

3. **Multi-Stage Detection Hierarchy**
   - `Allowlist` checks run first as a fast-exit filter.
   - `Exact Catalog` runs second for zero-false-positive exact matches.
   - `Patterns` run third for structured tokens.
   - `Entropy` runs last on remaining candidates, minimizing redundant calculations.

4. **Structured JSON Metadata with Labels**
   - Both `secrets-catalog.json` and `secrets-allowlist.json` store structured records with human-readable labels:
     ```json
     {
       "value": "fake_staging_db_password_2025!",
       "label": "Staging DB Password",
       "status": "protected",
       "source": "catalog",
       "addedAt": "2025-01-01T00:00:00.000Z"
     }
     ```
   - When classifying secrets in `/snoop`, an input dialog appears with a smart auto-generated default label (e.g. `"AWS Access Key"`, `"Database password"`, `"High-entropy token (24c)"`). Users can simply press **Enter** to accept the default or type a custom name.
   - Catalog hits in the findings list display their friendly label directly instead of a generic `"exact-match"`.
   - Maintains mutual exclusion between catalog and allowlist to prevent contradictory states.

5. **List Invariants**
   - **Allowlist always wins**: `loadCatalog()` drops any value also present in the allowlist, so a secret can never be both allowed and protected, even after hand-edits.
   - **User-managed files only**: built-in `DEFAULT_CATALOG` entries live in code and are never written to `secrets-catalog.json`.
   - **Deduplicated classification**: `/snoop` groups findings by secret value (`×N (msgs #a, #b)`), so one secret appearing in many messages is classified once.

6. **Plaintext Testing Before HMAC Migration**
   - v1 uses readable plaintext strings for rapid verification and debugging with fake credentials.
   - The data model and architecture are designed for a straightforward drop-in migration to HMAC-keyed hashing in v2.

7. **Redaction Context for the Agent**
   - Instead of polluting the user's project files (AGENTS.md) or hijacking the system prompt, the redaction convention is delivered as a `custom_message` entry (`display: false`) at `session_start`.
   - It persists with the branch (survives `/resume`), is invisible in the transcript, costs a few dozen tokens once, and is prompt-cache stable for subsequent turns.
   - The secret broker vault is pruned on every `context` call: entries whose placeholder no longer appears in the active context are dropped, so the RAM footprint tracks the conversation instead of growing with it.

---

## 5. What Needs To Be Done (Roadmap)

### Phase 2: Automatic Pre-LLM Redaction (Done)
- Hook into Pi's `context` / `context_with_system` lifecycle events.
- Intercept outgoing messages immediately before they are dispatched to the provider.
- Dynamically replace un-whitelisted secrets with stable placeholder tokens (e.g., `[REDACTED_SECRET:<id>]`).

**Implementation notes**:
- Redaction is request-local: `pi.on("context", ...)` returns replaced messages without touching the persisted session file.
- Every non-allowlisted secret (catalog, pattern, or entropy hit) is replaced with a stable placeholder `[REDACTED_SECRET:<id>]` where `id` is the first 8 hex chars of the keyed HMAC-SHA256 of the value, so the model sees the same token each time it reappears.
- Redacted fields: user/assistant/custom text, tool-result text, tool-call argument values, compaction/branch summaries, and bash command/output. Thinking blocks and images are skipped in v1 (provider replay signatures; no OCR).
- One notification per new secret value per session; the session file and `/snoop` still see originals.

### Phase 3: HMAC Keyed Storage (Done)
- Secrets are identified and stored by their cryptographic HMAC digest (`id`), completely removing plaintext credentials from `secrets-catalog.json` and `secrets-allowlist.json`.
- Key resolution: `CONTEXT_SNOOPER_KEY` / `ORG_HMAC_KEY` env vars, `<cwd>/.pi-hmac-key`, or global `~/.pi/context-snooper.key`.
- Enables team-wide shared salt configurations for syncing database credential denylists across repositories without committing plaintext passwords.

### Phase 4: Delta Scanning & Performance Optimization (Done)
- **$O(1)$ Message Cache**: Uses a zero-leak `WeakMap<object, CachedHit[]>` keyed on persistent `AgentMessage` object references.
- **Incremental Turn Processing**: During normal multi-turn conversations, previously scanned messages are served from memory in <0.01ms; only newly appended turns (user messages, tool results) are parsed.
- **Automatic Invalidation**: Automatically clears and rebuilds cache when `catalog`, `allowlist`, salt key, or scanning filters change.
- **Diagnostics**: Exposes `getScanCacheStats()` (`hits`, `misses`) and `clearScanCache()`.

### Phase 5: Secret Broker & Tool Re-Expansion (Done)
- **Ephemeral In-Memory Vault** (`secretVault: Map<id, plaintext>`): populated as a side effect of redaction — the raw secret is captured exactly once while passing through on its way out. Cleared on `session_shutdown` / `session_before_switch`. Never persisted.
- **Expansion Policy** (`tool_call` hook, mutates `event.input` in place):
  - `write` / `edit` (local file mutations): auto-expand — but only for secrets classified as `Protected`; unclassified or disallowed placeholders always confirm.
  - All other tools (`bash`, `powershell`, custom): interactive confirmation showing the *really executing* payload with the secret expanded; declining runs the tool with literal placeholders (fails safely). Non-interactive modes never expand.
  - **Disallowed secrets are never expanded** — their placeholder ids are resolved from `use: "deny"` catalog entries at every tool call and left as literal placeholders.
- **Echo guarantee**: any tool result containing plaintext is re-redacted by the `context` hook before the next model request, so the expansion is never observable by the model.
- **Safe failure**: unknown placeholder ids are left as literal placeholders.

---

## 6. Usage & Testing

### Run Automated Tests
```bash
npm test
```

### Run Inside Pi
Load the extension directly in any Pi session:
```bash
pi --extension ./index.ts
```

Full walkthroughs live in [`docs/user-guide.md`](docs/user-guide.md). Quick tour:

Within Pi:
1. Provide or trigger text containing a secret (e.g. `fake_staging_db_password_2025!` or a high-entropy string).
   - Secrets in the catalog will be replaced with `[REDACTED_SECRET:<id>]` before each LLM call; the model never sees the raw value.
   - The agent receives a standing note (hidden in the transcript) explaining that placeholders are expected security behavior.
2. Type `/snoop` and press Enter to review **unclassified** secrets.
3. Review findings and choose an action (**Protected**, **Disallowed**, **Allowed**, or **False Positive**). Allowed secrets are no longer redacted.
4. Useful extras: `/snoop list` (color-coded audit of everything), `/snoop fix` (reconcile hand-edited list files), `/snoop salt` (manage the HMAC key), `/snoop help`.
