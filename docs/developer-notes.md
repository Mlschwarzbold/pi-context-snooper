# Developer Notes

Internal structure, public API surface, and conventions for extending
context-snooper. For user-facing behavior see `docs/user-guide.md`; for
security guarantees see `docs/security-model.md`.

---

## 1. Module Map

Everything lives in a single file, `index.ts`, organized into four sections:

| Section | Key exports | Responsibility |
|---|---|---|
| **Keys & storage** | `getHmacKey`, `getHmacKeyInfo`, `setHmacKey`, `computeHmac`, `loadCatalog`, `loadAllowlist`, `saveCatalog`, `saveAllowlist`, `hasPersistedEntries` | Key resolution (env → project → global), HMAC ids, file I/O with invariants |
| **Detection** | `scanText`, `scanMessages`, `scanMessageWithCache`, `clearScanCache`, `getScanCacheStats`, `shannonEntropy`, `extractTokens`, `extractHmacCandidates`, `extractTextsFromMessage`, `matchCandidateInList`, `groupHitsByValue` | 4-stage scan (catalog value → catalog HMAC → patterns → entropy), delta cache (`WeakMap` keyed on `AgentMessage` objects) |
| **Redaction & broker** | `buildRedactionEntries`, `redactMessages`, `redactInString`, `secretVault`, `expandInput`, `expandSecretsInPlace`, `hasPlaceholder`, `getDeniedIds`, `pruneVault` | Outbound placeholder substitution; inbound tool-boundary expansion; vault lifecycle |
| **Pi integration** | `secretId`, `fixLists`, `REDACTOR_NOTE`, `generateDefaultLabel`, `formatSecretPreview`, `getStatusBadge`, default export | `/snoop` command, `context`/`tool_call`/`session_start`/`session_shutdown` hooks |

The default export is the extension factory; it wires the hooks and registers
the `/snoop` command. All logic is importable and testable without Pi.

---

## 2. Data Contracts

### Placeholder format (do not change)
```
[REDACTED_SECRET:<8-hex>]
```
- 8-hex = `computeHmac(value, key).slice(0, 8)` — the **first 8 chars of the
  12-char id**. `PLACEHOLDER_PATTERN` and `getDeniedIds` both operate on this
  prefix. If you change the id length, update all three.
- Ids are deterministic per `(value, key)` — stable across sessions, sessions'
  branches, and Pi restarts.

### `SecretHit.status`
`"unclassified" | "protected" | "disallowed" | "allowed" | "false_positive"`.
`scanText(includeAllowed: false)` (the default, used by redaction and the
default `/snoop` view) suppresses `allowed`/`false_positive` **only** —
`disallowed` and `protected` always flow through.

### File entries
- `secrets-catalog.json`: `{ id?, value?, label, status, use?, source, addedAt }`
  — `use: "deny"` marks DISALLOWED. `value` may be absent (pure-HMAC entry).
- `secrets-allowlist.json`: `{ id?, value?, label, decision, source, addedAt }`
  — `decision: "allowed" | "false_positive"`.

### Key resolution order
1. `CONTEXT_SNOOPER_KEY` env
2. `ORG_HMAC_KEY` env
3. `<cwd>/.pi-hmac-key`
4. `~/.pi/context-snooper.key` (auto-created `0600`)
5. hardcoded dev fallback

---

## 3. Invariants (enforced, tested)

1. **Allowlist wins** — `loadCatalog` drops any catalog value whose HMAC id or
   plaintext value matches an allowlist entry (key-agnostic, i.e. it works
   even when one side is id-only and the other value-only).
2. **User-managed files only** — `saveCatalog` (via `recordClassification` /
   `fixLists`) never persists `DEFAULT_CATALOG` values.
3. **Mutual exclusion on classification** — `recordClassification` removes the
   value from the opposite list in the same write.
4. **Idempotent fix** — `fixLists` reports `changed: false` on an already-clean
   state.
5. **Safe failure everywhere** — unknown placeholder ids, missing vault
   entries, or unconfirmed expansions all leave the literal placeholder in
   place. The tool would rather fail loudly than leak silently.

---

## 4. Performance Characteristics

- **Delta cache**: `WeakMap<object, CachedHit[]>` keyed on the stable
  `AgentMessage` references Pi reuses. Per-turn cost = parse new messages only.
  Cache stamp = `catalog.length:allowlist.length:key:includeAllowed`; any
  classification or key change re-stamps and refills lazily.
- **Vault pruning**: O(vault × context) substring check per `context` call;
  vault stays small because entries are dropped when their placeholder leaves
  the active branch.
- **Per-request redaction**: one `JSON.stringify` per changed message;
  typical turn adds <5 ms.

---

## 5. Conventions & Testing

- **No external dependencies.** Tests run with `node test.ts`
  (Node 22.19+/24 native TS type-stripping). `node:assert/strict` only.
- **Snapshot/restore**: `test.ts` snapshots `secrets-catalog.json`,
  `secrets-allowlist.json`, `.pi-hmac-key`, and `.gitignore` at start and
  restores them at the end. If you add a test that writes other files, extend
  `restoreFiles()`.
- **Key discipline in tests**: after test 15 sets a *project* salt, any key
  computation must pass an explicit `key` matching `getHmacKey(cwd)`.
  `matchCandidateInList`/`computeHmac`/`secretId` default to
  `getHmacKey()` (no cwd) — a footgun that silently mismatches once a project
  salt exists.
- **New detectors**: add a `PATTERNS` entry (regex + human name → becomes the
  default label). Keep patterns anchored (`\b`) to avoid mid-word false
  positives. Entropy tuning knobs: `extractTokens` min/max length,
  `entropyThreshold`, `isHexDigest`/`isUUID` guards.
- **New statuses**: `SecretStatus` → `getStatusBadge` → `/snoop` filter
  (`includeAllowed` semantics in `scanText`) → README tables. Four places.

---

## 6. Known Sharp Edges

- **Auto-expand gate**: `write`/`edit` auto-expand only placeholders whose id
  is in `getExpandableIds(catalog)` (classified `use !== "deny"`). Unclassified
  secrets live in the vault but fall back to the confirmation path — decided
  intentionally: no silent use of unreviewed credentials.
- **Thinking blocks are scanned but never redacted** (provider signature
  replay risk). They *are* detected by `/snoop`.
- **Images are never inspected.**
- **`redactMessage` returns the original object** when nothing changed
  (identity-preserving; the delta cache relies on stable message references).
- **`expandSecretsInPlace` is in-place only for objects/arrays**; strings must
  go through `expandInput` (which assigns the replacement).
- **Vault ≠ persistence.** The vault is RAM-only for the session; the session
  file still holds originals (Pi design). Rebuild path if ever needed:
  re-scan `buildSessionContext()`.
