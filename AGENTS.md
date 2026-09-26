# AGENTS.md — context-snooper

Orientation for AI agents working in this repo. Optimized for a fast start
and for re-orientation **after context compaction**: if you don't remember
this session, read this file first, then `docs/developer-notes.md`.

## What this project is

A Pi coding-agent extension (`index.ts`) that prevents secrets from leaving
the machine to LLM providers:

1. **Detects** secrets in the live context (4-stage scan: catalog exact value →
   catalog HMAC → regex patterns → Shannon entropy).
2. **Redacts** every non-allowlisted secret to `[REDACTED_SECRET:<8hex>]`
   in the `context` lifecycle hook, before each LLM call (request-local —
   session files keep originals).
3. **Brokers** expansion: the ephemeral in-memory `secretVault`
   (`id → plaintext`, populated at redaction time) lets tools use the real
   value locally via the `tool_call` hook, which mutates `event.input` in place.
4. **Classifies** interactively via `/snoop` (5 statuses, see below).

## File map

- `index.ts` — the whole extension, single file, zero external deps.
- `test.ts` — 21 test groups, `node:assert` only, runs as `npm test`.
  Snapshots/restores `secrets-catalog.json`, `secrets-allowlist.json`,
  `.pi-hmac-key`, `.gitignore` around the run.
- `secrets-catalog.json` / `secrets-allowlist.json` — project list files
  (test fixtures in this repo; restored after `npm test`).
- `README.md` — project history, goals, architecture narrative, roadmap.
- `docs/user-guide.md` — operator docs. `docs/security-model.md` — guarantees
  and residual risks. `docs/developer-notes.md` — internals, contracts,
  conventions, sharp edges. **Keep all four in sync when behavior changes.**

## The 5 statuses

| Status | Stored as | LLM sees | Agent may use |
|---|---|---|---|
| UNCLASSIFIED | nowhere | no (redacted) | no — confirmation required in ALL tools |
| PROTECTED | catalog, `use:"expand"` | no | yes, auto for `write`/`edit`, else confirm |
| DISALLOWED | catalog, `use:"deny"` | no | never — broker refuses expansion |
| ALLOWED | allowlist | yes (as-is) | n/a |
| FALSE_POSITIVE | allowlist | yes (as-is) | n/a |

## Invariants (enforced + tested — do not break)

1. **Allowlist wins**: `loadCatalog` drops any value matching the allowlist by
   id **or** value (key-agnostic).
2. **User-managed files only**: code `DEFAULT_CATALOG` never persists to the catalog file.
3. **Mutual exclusion** on classification: `recordClassification` removes from
   the opposite list in the same write.
4. **Idempotent** `/snoop fix` (`fixLists` → `changed: false` on clean state).
5. **Safe failure**: unknown ids, missing vault entries, unconfirmed expansion
   → literal placeholder stays. Never leak to avoid a friction moment.
6. **Auto-expand gate**: `write`/`edit` auto-expand only ids in
   `getExpandableIds(catalog)`; unclassified/disallowed always confirm
   (`canAutoExpand`).

## Critical data contracts

- **Placeholder**: `[REDACTED_SECRET:<8-hex>]` — 8-hex =
  `computeHmac(value, key).slice(0, 8)`. Catalog `id` is the **12-char** HMAC.
  `PLACEHOLDER_PATTERN`, `getDeniedIds`, `getExpandableIds` all operate on the
  8-char prefix. Changing id length → update all three.
- **Key resolution order**: `CONTEXT_SNOOPER_KEY` → `ORG_HMAC_KEY` →
  `<cwd>/.pi-hmac-key` → `~/.pi/context-snooper.key` (auto-created 0600) → dev fallback.
- **HMAC key discipline footgun**: `computeHmac`/`secretId`/`matchCandidateInList`
  default to `getHmacKey()` (NO cwd); `recordClassification`/`loadCatalog(cwd)`
  use `getHmacKey(cwd)`. Tests after the project-salt test (test 15) MUST pass
  an explicit key or they silently mismatch.

## How to run

```bash
npm test                       # 21 groups; must pass before committing changes
pi --extension ./index.ts      # interactive; try /snoop, /snoop list, /snoop help,
                               # /snoop fix, /snoop salt
```
Node 22.19+/24 native TS type-stripping — no build step, no dependencies.

## Pi integration surface (which hook does what)

- `session_start` → `sendMessage(display:false)` redactor note (agent-facing
  standing instructions; persists with branch; invisible in TUI).
- `context` → redact + populate `secretVault` + `pruneVault`.
- `tool_call` → broker expansion with policy (auto / confirm / never).
- `session_shutdown` / `session_before_switch` → clear vault + scan cache.
- `registerCommand("snoop")` → default scan, `list`, `fix`, `salt`, `help`.
- Output of `/snoop` (notify/select/confirm) is **terminal-only**, never in
  LLM context. (Exceptions: the `session_start` note, by design.)

## Known sharp edges

- Thinking blocks: **scanned but never redacted** (provider replay signatures).
- Images: never inspected.
- `redactMessage` returns the **original object** when unchanged (identity
  matters to the `WeakMap` delta cache).
- `expandSecretsInPlace` is in-place only for objects/arrays; strings go
  through `expandInput` (assigns the replacement).
- Delta cache (`WeakMap` on `AgentMessage` refs) re-stamps on
  `catalog.length:allowlist.length:key:includeAllowed` change.
- Session files keep plaintext originals (Pi design) — treat as sensitive.

## Conventions

- Ponytail style: minimal code, stdlib only, `ponytail:` comments for
  deliberate shortcuts with their upgrade path.
- Every non-trivial behavior change ships with a test-group addition to
  `test.ts` (sequential numbering, `restoreFiles()` stays last).
- Doc updates accompany behavior changes: README (history/roadmap),
  `docs/user-guide.md`, `docs/security-model.md`, `docs/developer-notes.md`,
  and this file.

## State (update when things change)

- All roadmap phases complete: detection, catalog/allowlist + labels,
  pre-LLM redaction, HMAC-keyed storage, `/snoop salt`, delta scanning,
  secret broker, DISALLOWED tier, help/fix, agent-facing redactor note,
  auto-expand gate, `docs/` set.
- 21/21 test groups passing.
- Not yet done: live-provider canary checklist (security-model §5), optional
  `/snoop report` audit export, footer status line, org key sync tooling.
- Stray files from manual testing: `fake-api-key.txt`, `notes.txt`
  (delete or promote to fixtures).
