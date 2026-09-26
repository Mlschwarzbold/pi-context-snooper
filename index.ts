import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { createHmac, createHash, randomBytes } from "node:crypto";

export type SecretStatus = "unclassified" | "protected" | "disallowed" | "allowed" | "false_positive";

export interface CatalogEntry {
  id?: string;             // HMAC fingerprint (e.g. "f83a21bc90d1")
  value?: string;          // Optional plaintext (for testing/legacy)
  label: string;
  status: "protected";
  /** "expand": broker may expand at tool boundary (default). "deny": agent may never use it. */
  use?: "expand" | "deny";
  source: string;
  addedAt: string;
}

export interface AllowlistEntry {
  id?: string;             // HMAC fingerprint
  value?: string;          // Optional plaintext
  label: string;
  decision: "allowed" | "false_positive";
  source: string;
  addedAt: string;
}

export interface SecretHit {
  type: "catalog" | "pattern" | "entropy";
  rule: string;
  matched: string;
  role: string;
  messageIndex: number;
  status: SecretStatus;
}

export const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
};

export function getStatusBadge(status: SecretStatus): string {
  switch (status) {
    case "protected":
      return `${ANSI.bold}${ANSI.red}[PROTECTED]${ANSI.reset}`;
    case "disallowed":
      return `${ANSI.bold}\x1b[35m[DISALLOWED]${ANSI.reset}`;
    case "allowed":
      return `${ANSI.bold}${ANSI.green}[ALLOWED]${ANSI.reset}`;
    case "false_positive":
      return `${ANSI.bold}${ANSI.cyan}[FALSE POSITIVE]${ANSI.reset}`;
    case "unclassified":
      return `${ANSI.bold}${ANSI.yellow}[UNCLASSIFIED]${ANSI.reset}`;
  }
}

export const DEFAULT_CATALOG: CatalogEntry[] = [
  { value: "fake_staging_db_password_2025!", label: "Staging DB Password", status: "protected", source: "catalog", addedAt: "2025-01-01T00:00:00.000Z" },
  { value: "fake_org_secret_token_abc123", label: "Org Secret Token", status: "protected", source: "catalog", addedAt: "2025-01-01T00:00:00.000Z" },
  { value: "super_secret_test_credential_99", label: "Test Credential 99", status: "protected", source: "catalog", addedAt: "2025-01-01T00:00:00.000Z" },
];

export const PATTERNS = [
  { name: "Fake/Real OpenAI Key", regex: /\b(?:FAKE_)?sk-[a-zA-Z0-9_\-]{20,}\b/g },
  { name: "Fake DB Password prefix", regex: /\bFAKE_DB_[a-zA-Z0-9_!@#$%^&*]{8,}\b/g },
  { name: "AWS Access Key", regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "GitHub Token", regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b/g },
  { name: "Private Key Header", regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
];

export interface HmacKeyInfo {
  key: string;
  source: "env" | "project" | "global" | "default";
  path?: string;
  envVar?: string;
}

export function getHmacKeyInfo(cwd?: string): HmacKeyInfo {
  if (process.env.CONTEXT_SNOOPER_KEY) {
    return { key: process.env.CONTEXT_SNOOPER_KEY.trim(), source: "env", envVar: "CONTEXT_SNOOPER_KEY" };
  }
  if (process.env.ORG_HMAC_KEY) {
    return { key: process.env.ORG_HMAC_KEY.trim(), source: "env", envVar: "ORG_HMAC_KEY" };
  }
  if (cwd) {
    const projKey = resolve(cwd, ".pi-hmac-key");
    if (existsSync(projKey)) {
      try {
        const k = readFileSync(projKey, "utf8").trim();
        if (k) return { key: k, source: "project", path: projKey };
      } catch {}
    }
  }
  const home = process.env.HOME || process.env.USERPROFILE || "";
  if (home) {
    const globalKey = resolve(home, ".pi", "context-snooper.key");
    if (existsSync(globalKey)) {
      try {
        const k = readFileSync(globalKey, "utf8").trim();
        if (k) return { key: k, source: "global", path: globalKey };
      } catch {}
    }
    try {
      const dir = resolve(home, ".pi");
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      const newKey = randomBytes(32).toString("hex");
      writeFileSync(globalKey, newKey, { encoding: "utf8", mode: 0o600 });
      return { key: newKey, source: "global", path: globalKey };
    } catch {}
  }
  return { key: "context-snooper-default-dev-salt-key-2025", source: "default" };
}

export function getHmacKey(cwd?: string): string {
  return getHmacKeyInfo(cwd).key;
}

export function setHmacKey(
  newKey: string,
  scope: "project" | "global",
  cwd = process.cwd(),
): { path: string; gitignored: boolean } {
  const cleanKey = newKey.trim();
  if (!cleanKey) throw new Error("HMAC salt cannot be empty");

  if (scope === "project") {
    const keyPath = resolve(cwd, ".pi-hmac-key");
    writeFileSync(keyPath, cleanKey, { encoding: "utf8", mode: 0o600 });

    let gitignored = false;
    const gitignorePath = resolve(cwd, ".gitignore");
    try {
      if (existsSync(gitignorePath)) {
        const content = readFileSync(gitignorePath, "utf8");
        if (!content.includes(".pi-hmac-key")) {
          const appendContent = content.endsWith("\n") || content.length === 0 ? ".pi-hmac-key\n" : "\n.pi-hmac-key\n";
          writeFileSync(gitignorePath, content + appendContent, "utf8");
        }
        gitignored = true;
      }
    } catch {}

    return { path: keyPath, gitignored };
  } else {
    const home = process.env.HOME || process.env.USERPROFILE || "";
    if (!home) throw new Error("Cannot determine user home directory for global salt");
    const dir = resolve(home, ".pi");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const keyPath = resolve(dir, "context-snooper.key");
    writeFileSync(keyPath, cleanKey, { encoding: "utf8", mode: 0o600 });
    const res = { path: keyPath, gitignored: false };
    clearScanCache();
    return res;
  }
}

export function hasPersistedEntries(cwd?: string): boolean {
  if (!cwd) return false;
  const catPath = resolve(cwd, "secrets-catalog.json");
  const allowPath = resolve(cwd, "secrets-allowlist.json");

  try {
    if (existsSync(catPath)) {
      const parsed = JSON.parse(readFileSync(catPath, "utf8"));
      if (Array.isArray(parsed) && parsed.length > 0) return true;
    }
    if (existsSync(allowPath)) {
      const parsed = JSON.parse(readFileSync(allowPath, "utf8"));
      if (Array.isArray(parsed) && parsed.length > 0) return true;
    }
  } catch {}
  return false;
}

export function computeHmac(secret: string, key = getHmacKey()): string {
  return createHmac("sha256", key).update(secret.trim()).digest("hex").slice(0, 12);
}

export function matchCandidateInList<T extends { id?: string; value?: string }>(
  candidate: string,
  list: T[],
  key = getHmacKey(),
): T | undefined {
  const candHmac = computeHmac(candidate, key);
  return list.find((item) => (item.id && item.id === candHmac) || (item.value && item.value === candidate));
}

export function extractHmacCandidates(text: string): string[] {
  const tokens = text
    .split(/[\s"'\`=,;:<>()\[\]{}|\\/@]+/)
    .map((t) => t.trim())
    .filter((t) => t.length >= 8 && t.length <= 96);
  return Array.from(new Set(tokens));
}

export function shannonEntropy(str: string): number {
  if (!str) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    h -= p * Math.log2(p);
  }
  return h;
}

export function hasCharDiversity(str: string): boolean {
  let classes = 0;
  if (/[a-z]/.test(str)) classes++;
  if (/[A-Z]/.test(str)) classes++;
  if (/[0-9]/.test(str)) classes++;
  if (/[^a-zA-Z0-9]/.test(str)) classes++;
  return classes >= 2;
}

const isHexDigest = (s: string) =>
  /^[0-9a-fA-F]+$/.test(s) && (s.length === 32 || s.length === 40 || s.length === 64);
const isUUID = (s: string) =>
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s);

export function generateDefaultLabel(hit: SecretHit): string {
  if (hit.type === "pattern") {
    return hit.rule.replace("Fake/Real ", "").replace(" prefix", "");
  }
  if (hit.type === "catalog") {
    if (hit.matched.includes("db") || hit.matched.includes("password")) return "Database password";
    if (hit.matched.includes("token")) return "Service token";
    if (hit.matched.includes("key") || hit.matched.includes("credential")) return "API credential";
    return `Catalog secret (${hit.matched.length}c)`;
  }
  return `High-entropy token (${hit.matched.length}c)`;
}

export function formatSecretPreview(secret: string, prefixLen = 10, suffixLen = 8): string {
  if (secret.length <= prefixLen + suffixLen + 3) return secret;
  return `${secret.slice(0, prefixLen)}...${secret.slice(-suffixLen)}`;
}

export function extractTokens(text: string, minLen = 16, maxLen = 96): string[] {
  return text
    .split(/[\s"'\`=,;:<>()\[\]{}|\\/@]+/)
    .map((t) => t.trim())
    .filter((t) => t.length >= minLen && t.length <= maxLen);
}

export function extractTextsFromMessage(msg: any): string[] {
  const texts: string[] = [];
  if (!msg) return texts;
  if (typeof msg.content === "string") texts.push(msg.content);
  else if (Array.isArray(msg.content)) {
    for (const b of msg.content) {
      if (b.type === "text" && typeof b.text === "string") texts.push(b.text);
      if (b.type === "thinking" && typeof b.thinking === "string") texts.push(b.thinking);
      if (b.type === "toolCall" && b.arguments) texts.push(JSON.stringify(b.arguments));
    }
  }
  if (typeof msg.summary === "string") texts.push(msg.summary);
  if (typeof msg.command === "string") texts.push(msg.command);
  if (typeof msg.output === "string") texts.push(msg.output);
  return texts;
}

export function loadCatalog(cwd?: string, key = getHmacKey(cwd)): CatalogEntry[] {
  const map = new Map<string, CatalogEntry>(
    DEFAULT_CATALOG.map((e) => [e.value!, { ...e, id: computeHmac(e.value!, key) }]),
  );
  if (cwd) {
    const customPath = resolve(cwd, "secrets-catalog.json");
    if (existsSync(customPath)) {
      try {
        const raw = JSON.parse(readFileSync(customPath, "utf8"));
        if (Array.isArray(raw)) {
          for (const item of raw) {
            const id = item.id || (item.value ? computeHmac(item.value, key) : undefined);
            const entryKey = id || item.value;
            if (!entryKey) continue;
            map.set(entryKey, {
              id,
              value: item.value,
              label: typeof item.label === "string" && item.label.trim() ? item.label.trim() : "Protected secret",
              status: "protected",
              use: item.use === "deny" ? "deny" : "expand",
              source: item.source ?? "catalog",
              addedAt: item.addedAt ?? new Date().toISOString(),
            });
          }
        }
      } catch {}
    }
    // Invariant: allowlist always wins (match by id AND by value, key-agnostic)
    const allowed = loadAllowlist(cwd, key);
    for (const a of allowed) {
      if (a.id) map.delete(a.id);
      if (a.value) map.delete(a.value);
      if (a.id && !a.value) {
        for (const [k, e] of map) {
          if (e.value && computeHmac(e.value, key) === a.id) map.delete(k);
        }
      }
    }
  }
  return Array.from(map.values());
}

export function saveCatalog(cwd: string, entries: CatalogEntry[]): void {
  writeFileSync(resolve(cwd, "secrets-catalog.json"), JSON.stringify(entries, null, 2), "utf8");
  clearScanCache();
}

export function loadAllowlist(cwd?: string, key = getHmacKey(cwd)): AllowlistEntry[] {
  const list: AllowlistEntry[] = [];
  if (cwd) {
    const customPath = resolve(cwd, "secrets-allowlist.json");
    if (existsSync(customPath)) {
      try {
        const raw = JSON.parse(readFileSync(customPath, "utf8"));
        if (Array.isArray(raw)) {
          for (const item of raw) {
            const id = item.id || (item.value ? computeHmac(item.value, key) : undefined);
            list.push({
              id,
              value: item.value,
              label:
                typeof item.label === "string" && item.label.trim()
                  ? item.label.trim()
                  : item.decision === "false_positive"
                    ? "False positive"
                    : "Allowed secret",
              decision: item.decision ?? "allowed",
              source: item.source ?? "unknown",
              addedAt: item.addedAt ?? new Date().toISOString(),
            });
          }
        }
      } catch {}
    }
  }
  return list;
}

export function saveAllowlist(cwd: string, entries: AllowlistEntry[]): void {
  writeFileSync(resolve(cwd, "secrets-allowlist.json"), JSON.stringify(entries, null, 2), "utf8");
  clearScanCache();
}

export function recordClassification(
  cwd: string,
  secret: string,
  action: "protected" | "disallowed" | "allowed" | "false_positive",
  source: string,
  label?: string,
  key: string = getHmacKey(cwd),
): { catalog: CatalogEntry[]; allowlist: AllowlistEntry[] } {
  let catalog = loadCatalog(cwd, key);
  let allowlist = loadAllowlist(cwd, key);
  const now = new Date().toISOString();
  const id = computeHmac(secret, key);
  const defaultValues = new Set(DEFAULT_CATALOG.map((d) => d.value!));
  const finalLabel =
    label?.trim() ||
    (action === "false_positive"
      ? "False positive"
      : action === "allowed"
        ? "Allowed secret"
        : action === "disallowed"
          ? "Disallowed secret"
          : "Protected secret");

  if (action === "protected" || action === "disallowed") {
    const use = action === "disallowed" ? "deny" : "expand";
    allowlist = allowlist.filter((e) => e.value !== secret && e.id !== id);
    const existing = catalog.find((e) => e.value === secret || e.id === id);
    if (existing) {
      existing.status = "protected";
      existing.use = use;
      existing.source = source;
      existing.id = id;
      if (label?.trim()) existing.label = label.trim();
    } else if (!defaultValues.has(secret)) {
      catalog.push({
        id,
        label: finalLabel,
        status: "protected",
        use,
        source,
        addedAt: now,
      });
    }
  } else {
    catalog = catalog.filter((e) => e.value !== secret && e.id !== id);
    const existing = allowlist.find((e) => e.value === secret || e.id === id);
    if (existing) {
      existing.decision = action;
      existing.source = source;
      existing.id = id;
      if (label?.trim()) existing.label = label.trim();
    } else {
      allowlist.push({
        id,
        label: finalLabel,
        decision: action,
        source,
        addedAt: now,
      });
    }
  }

  // Save only non-default entries without plaintext values
  saveCatalog(cwd, catalog.filter((e) => !e.value || !defaultValues.has(e.value)));
  saveAllowlist(cwd, allowlist);
  return { catalog, allowlist };
}

export interface ScanOptions {
  includeAllowed?: boolean;
  entropyThreshold?: number;
  key?: string;
}

export function scanText(
  text: string,
  role = "unknown",
  messageIndex = 0,
  catalog: CatalogEntry[] = DEFAULT_CATALOG,
  allowlist: AllowlistEntry[] = [],
  options: ScanOptions | number = {},
): SecretHit[] {
  const opts: ScanOptions = typeof options === "number" ? { entropyThreshold: options } : options;
  const {
    includeAllowed = false,
    entropyThreshold = 3.8,
    key = getHmacKey(),
  } = opts;

  const hits: SecretHit[] = [];
  const seen = new Set<string>();

  const resolveStatus = (matched: string, baseStatus: SecretStatus): SecretStatus => {
    const allowHit = matchCandidateInList(matched, allowlist, key);
    if (allowHit) return allowHit.decision;
    const catHit = matchCandidateInList(matched, catalog, key);
    if (catHit) return catHit.use === "deny" ? "disallowed" : "protected";
    return baseStatus;
  };

  const addHit = (type: "catalog" | "pattern" | "entropy", rule: string, matched: string, baseStatus: SecretStatus) => {
    if (seen.has(matched)) return;
    const status = resolveStatus(matched, baseStatus);
    if (!includeAllowed && (status === "allowed" || status === "false_positive")) return;
    seen.add(matched);
    hits.push({ type, rule, matched, role, messageIndex, status });
  };

  // 1. Exact catalog search (value-based for entries with .value)
  for (const item of catalog) {
    if (item.value && text.includes(item.value)) {
      addHit("catalog", item.label || "exact-match", item.value, "protected");
    }
  }

  // 2. HMAC catalog search (for entries with .id)
  const hmacEntries = catalog.filter((c) => Boolean(c.id));
  if (hmacEntries.length > 0) {
    for (const tok of extractHmacCandidates(text)) {
      const match = matchCandidateInList(tok, hmacEntries, key);
      if (match) {
        addHit("catalog", match.label || "Catalog secret", tok, "protected");
      }
    }
  }

  // 3. Pattern matching
  for (const { name, regex } of PATTERNS) {
    const rx = new RegExp(regex.source, regex.flags);
    let match: RegExpExecArray | null;
    while ((match = rx.exec(text)) !== null) {
      addHit("pattern", name, match[0], "unclassified");
    }
  }

  // 4. High-entropy candidate tokens
  for (const tok of extractTokens(text)) {
    if (isHexDigest(tok) || isUUID(tok) || !hasCharDiversity(tok)) continue;
    const entropy = shannonEntropy(tok);
    if (entropy >= entropyThreshold) {
      addHit("entropy", `entropy (${entropy.toFixed(2)} bits)`, tok, "unclassified");
    }
  }

  return hits;
}

export interface CachedHit {
  type: "catalog" | "pattern" | "entropy";
  rule: string;
  matched: string;
  role: string;
  status: SecretStatus;
}

let _activeCache = new WeakMap<object, CachedHit[]>();
let lastCacheStamp = "";
let cacheStats = { hits: 0, misses: 0 };

export function clearScanCache(): void {
  _activeCache = new WeakMap<object, CachedHit[]>();
  lastCacheStamp = "";
  cacheStats = { hits: 0, misses: 0 };
}

export function getScanCacheStats(): { hits: number; misses: number } {
  return { ...cacheStats };
}

function getCacheStamp(catalog: CatalogEntry[], allowlist: AllowlistEntry[], key: string, includeAllowed: boolean): string {
  return `${catalog.length}:${allowlist.length}:${key}:${includeAllowed}`;
}

export function scanMessageWithCache(
  msg: any,
  role: string,
  messageIndex: number,
  catalog: CatalogEntry[],
  allowlist: AllowlistEntry[],
  options: ScanOptions = {},
): SecretHit[] {
  if (!msg || typeof msg !== "object") {
    const texts = extractTextsFromMessage(msg);
    const hits: SecretHit[] = [];
    for (const t of texts) hits.push(...scanText(t, role, messageIndex, catalog, allowlist, options));
    return hits;
  }

  const { includeAllowed = false, key = getHmacKey() } = options;
  const currentStamp = getCacheStamp(catalog, allowlist, key, includeAllowed);
  if (currentStamp !== lastCacheStamp) {
    _activeCache = new WeakMap<object, CachedHit[]>();
    lastCacheStamp = currentStamp;
    cacheStats = { hits: 0, misses: 0 };
  }

  let cached = _activeCache.get(msg);
  if (cached) {
    cacheStats.hits++;
  } else {
    cacheStats.misses++;
    const texts = extractTextsFromMessage(msg);
    const rawHits: SecretHit[] = [];
    for (const t of texts) {
      rawHits.push(...scanText(t, role, messageIndex, catalog, allowlist, options));
    }
    cached = rawHits.map(({ type, rule, matched, role, status }) => ({
      type,
      rule,
      matched,
      role,
      status,
    }));
    _activeCache.set(msg, cached);
  }

  return cached.map((c) => ({
    ...c,
    messageIndex,
  }));
}

export function scanMessages(
  messages: any[],
  catalog: CatalogEntry[] = DEFAULT_CATALOG,
  allowlist: AllowlistEntry[] = [],
  options: ScanOptions = {},
): SecretHit[] {
  const allHits: SecretHit[] = [];
  messages.forEach((msg, idx) => {
    const role = msg?.role ?? "unknown";
    allHits.push(...scanMessageWithCache(msg, role, idx, catalog, allowlist, options));
  });
  return allHits;
}

/** One entry per unique secret value, with all message indices it appeared in. */
export function groupHitsByValue(hits: SecretHit[]): { hit: SecretHit; indices: number[] }[] {
  const map = new Map<string, { hit: SecretHit; indices: number[] }>();
  for (const h of hits) {
    const g = map.get(h.matched);
    if (g) g.indices.push(h.messageIndex);
    else map.set(h.matched, { hit: h, indices: [h.messageIndex] });
  }
  return Array.from(map.values());
}

export function secretId(value: string, key = getHmacKey()): string {
  return computeHmac(value, key).slice(0, 8);
}

export interface RedactionEntry {
  value: string;
  placeholder: string;
}

/** Build placeholder entries for every non-allowlisted secret across the context, longest value first. */
export function buildRedactionEntries(
  messages: any[],
  catalog: CatalogEntry[] = DEFAULT_CATALOG,
  allowlist: AllowlistEntry[] = [],
  key = getHmacKey(),
): RedactionEntry[] {
  const map = new Map<string, string>();
  const hits = scanMessages(messages, catalog, allowlist, { key, includeAllowed: false });
  for (const hit of hits) {
    const id = secretId(hit.matched, key);
    if (!map.has(hit.matched)) {
      map.set(hit.matched, `[REDACTED_SECRET:${id}]`);
    }
    // Broker: capture plaintext exactly once, while it passes through on the way out.
    secretVault.set(id, hit.matched);
  }
  return Array.from(map.entries())
    .map(([value, placeholder]) => ({ value, placeholder }))
    .sort((a, b) => b.value.length - a.value.length);
}

export function redactInString(text: string, entries: RedactionEntry[]): string {
  let out = text;
  for (const { value, placeholder } of entries) {
    out = out.split(value).join(placeholder);
  }
  return out;
}

function redactJsonValue(value: unknown, entries: RedactionEntry[]): unknown {
  if (typeof value === "string") return redactInString(value, entries);
  if (Array.isArray(value)) return value.map((v) => redactJsonValue(v, entries));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactJsonValue(v, entries);
    return out;
  }
  return value;
}

export function redactMessage(msg: any, entries: RedactionEntry[]): any {
  if (!msg || typeof msg !== "object" || entries.length === 0) return msg;
  const out: any = { ...msg };
  let changed = false;

  if (typeof out.content === "string") {
    const r = redactInString(out.content, entries);
    if (r !== out.content) { out.content = r; changed = true; }
  } else if (Array.isArray(out.content)) {
    out.content = out.content.map((block: any) => {
      if (block && block.type === "text" && typeof block.text === "string") {
        const r = redactInString(block.text, entries);
        if (r !== block.text) { changed = true; return { ...block, text: r }; }
      }
      if (block && block.type === "toolCall" && block.arguments !== undefined) {
        const r = redactJsonValue(block.arguments, entries);
        if (JSON.stringify(r) !== JSON.stringify(block.arguments)) { changed = true; return { ...block, arguments: r }; }
      }
      return block;
    });
  }

  if (typeof out.summary === "string") {
    const r = redactInString(out.summary, entries);
    if (r !== out.summary) { out.summary = r; changed = true; }
  }
  if (typeof out.command === "string") {
    const r = redactInString(out.command, entries);
    if (r !== out.command) { out.command = r; changed = true; }
  }
  if (typeof out.output === "string") {
    const r = redactInString(out.output, entries);
    if (r !== out.output) { out.output = r; changed = true; }
  }

  return changed ? out : msg;
}

export function redactMessages(messages: any[], entries: RedactionEntry[]): any[] {
  return messages.map((m) => redactMessage(m, entries));
}

// --- Secret Broker ---
// In-memory vault populated at redaction time: id -> plaintext.
// Lives only for the current session; cleared on shutdown/switch.
export const secretVault = new Map<string, string>();

export const PLACEHOLDER_PATTERN = /\[REDACTED_SECRET:([a-f0-9]{8})\]/g;

export function hasPlaceholder(value: unknown): boolean {
  return JSON.stringify(value ?? "").includes("[REDACTED_SECRET:");
}

/** Recursively replace placeholders with vaulted plaintext, mutating objects/arrays in place.
 *  Unknown ids are left as the literal placeholder (safe failure, no expansion).
 *  Ids in denyIds (disallowed secrets) are never expanded. */
export function expandSecretsInPlace(
  value: unknown,
  vault: Map<string, string> = secretVault,
  denyIds?: ReadonlySet<string>,
): void {
  if (typeof value === "string") return; // primitives can't mutate; use expandInput()
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      if (typeof value[i] === "string") value[i] = expandString(value[i] as string, vault, denyIds);
      else expandSecretsInPlace(value[i], vault, denyIds);
    }
    return;
  }
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      if (typeof v === "string") obj[k] = expandString(v, vault, denyIds);
      else expandSecretsInPlace(v, vault, denyIds);
    }
  }
}

function expandString(s: string, vault: Map<string, string>, denyIds?: ReadonlySet<string>): string {
  if (!s.includes("[REDACTED_SECRET:")) return s;
  return s.replace(PLACEHOLDER_PATTERN, (m, id) =>
    vault.has(id) && !denyIds?.has(id) ? vault.get(id)! : m,
  );
}

/** Expand placeholders in a tool-call input object (mutates in place, returns it for convenience). */
export function expandInput<T>(
  input: T,
  vault: Map<string, string> = secretVault,
  denyIds?: ReadonlySet<string>,
): T {
  if (typeof input === "string") {
    return expandString(input, vault, denyIds) as unknown as T;
  }
  expandSecretsInPlace(input, vault, denyIds);
  return input;
}

/** Placeholder ids of catalog entries marked use:"deny" (agent may not use these).
 *  Uses the 8-char prefix — the exact id format that appears in [REDACTED_SECRET:...]. */
export function getDeniedIds(catalog: CatalogEntry[]): Set<string> {
  const ids = new Set<string>();
  for (const e of catalog) if (e.use === "deny" && e.id) ids.add(e.id.slice(0, 8));
  return ids;
}

/** Placeholder ids of catalog entries the agent is allowed to use (use !== "deny"). */
export function getExpandableIds(catalog: CatalogEntry[]): Set<string> {
  const ids = new Set<string>();
  for (const e of catalog) if (e.use !== "deny" && e.id) ids.add(e.id.slice(0, 8));
  return ids;
}

/** Distinct placeholder ids present in a tool-call input. */
export function placeholderIdsIn(input: unknown): string[] {
  const s = JSON.stringify(input ?? "");
  if (!s.includes("[REDACTED_SECRET:")) return [];
  const ids = new Set<string>();
  for (const m of s.matchAll(PLACEHOLDER_PATTERN)) ids.add(m[1]);
  return [...ids];
}

/** True when every placeholder in the input maps to a classified, expandable catalog entry.
 *  Unclassified (never vault-reviewed) or disallowed placeholders fall back to confirmation. */
export function canAutoExpand(
  input: unknown,
  expandableIds: ReadonlySet<string>,
  denyIds: ReadonlySet<string>,
): boolean {
  const ids = placeholderIdsIn(input);
  if (ids.length === 0) return true;
  return ids.every((id) => expandableIds.has(id) && !denyIds.has(id));
}

/** Standing agent-facing explanation of redaction, injected once per session (hidden in TUI). */
export const REDACTOR_NOTE = [
  "Secret redaction is active in this session (context-snooper).",
  "- Credentials found in the context are replaced with [REDACTED_SECRET:<id>] placeholders before reaching the model.",
  "- Placeholders are opaque values: use them verbatim where a value is expected (e.g. writing them into a file is fine).",
  "- Do NOT attempt to guess, reconstruct, probe, or test placeholder values; the real credential never appears in the context.",
  "- Seeing a placeholder where a value is expected is normal security behavior, not an error.",
].join("\n");

/** Drop vault entries whose placeholder no longer appears in the active context. Returns count removed. */
export function pruneVault(messages: any[]): number {
  if (secretVault.size === 0) return 0;
  const joined = messages.map((m) => extractTextsFromMessage(m).join(" ")).join(" ");
  let removed = 0;
  for (const id of [...secretVault.keys()]) {
    if (!joined.includes(`[REDACTED_SECRET:${id}]`)) {
      secretVault.delete(id);
      removed++;
    }
  }
  return removed;
}

/** Reconcile hand-edited catalog/allowlist files against the invariants:
 *  allowlist wins, no built-in defaults in the catalog file, missing ids filled in, duplicates removed. */
export function fixLists(cwd: string, key = getHmacKey(cwd)): { changed: boolean; notes: string[] } {
  const notes: string[] = [];
  const defaultValues = new Set(DEFAULT_CATALOG.map((d) => d.value!));

  // Catalog: effective set (defaults + file, allowlist overlaps already dropped), user-managed only.
  let defaultsDropped = 0;
  let idsAdded = 0;
  const catalog = loadCatalog(cwd, key).filter((e) => {
    if (e.value && defaultValues.has(e.value)) {
      defaultsDropped++;
      return false;
    }
    return true;
  }).map((e) => {
    if (e.value && !e.id) {
      e.id = computeHmac(e.value, key);
      idsAdded++;
    }
    if (!e.label) e.label = "Protected secret";
    return e;
  });

  // Allowlist: dedupe by id/value.
  const seen = new Set<string>();
  let dupesDropped = 0;
  const allowlist: AllowlistEntry[] = [];
  for (const a of loadAllowlist(cwd, key)) {
    const k = a.id || a.value;
    if (!k || seen.has(k)) {
      dupesDropped++;
      continue;
    }
    seen.add(k);
    allowlist.push(a);
  }

  const catRaw = safeReadJson(resolve(cwd, "secrets-catalog.json"));
  const allowRaw = safeReadJson(resolve(cwd, "secrets-allowlist.json"));
  const changed =
    JSON.stringify(catalog) !== JSON.stringify(catRaw) || JSON.stringify(allowlist) !== JSON.stringify(allowRaw);

  if (defaultsDropped) notes.push(`dropped ${defaultsDropped} built-in default(s) from catalog file`);
  if (idsAdded) notes.push(`filled in ${idsAdded} missing HMAC id(s)`);
  if (dupesDropped) notes.push(`removed ${dupesDropped} duplicate allowlist entrie(s)`);
  if (changed) {
    saveCatalog(cwd, catalog);
    saveAllowlist(cwd, allowlist);
  }
  return { changed, notes };
}

function safeReadJson(path: string): unknown {
  try {
    return existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : [];
  } catch {
    return [];
  }
}

export default function (pi: ExtensionAPI) {
  const notifiedSecrets = new Set<string>();

  // Auto-expand tools: local file mutations only. Everything else needs confirmation.
  const AUTO_EXPAND_TOOLS = new Set(["write", "edit"]);
  // Tell the agent about redaction up front, so it treats placeholders as expected
  // instead of "going crazy" trying to investigate them. Hidden in the TUI, but
  // participates in LLM context for the life of the session (and on /resume).
  pi.on("session_start", () => {
    pi.sendMessage({
      customType: "context-snooper",
      content: REDACTOR_NOTE,
      display: false,
    });
  });

  pi.on("session_shutdown", () => {
    secretVault.clear();
    clearScanCache();
  });
  pi.on("session_before_switch", () => {
    secretVault.clear();
    clearScanCache();
  });

  // Secret Broker: expand [REDACTED_SECRET:<id>] placeholders back to plaintext
  // only at the local tool boundary. Disallowed secrets are never expanded;
  // unclassified secrets always require confirmation even in auto-expand tools.
  pi.on("tool_call", async (event, ctx) => {
    if (!hasPlaceholder(event.input)) return;

    const catalog = loadCatalog(ctx.cwd);
    const denyIds = getDeniedIds(catalog);
    const expandableIds = getExpandableIds(catalog);
    const auto =
      AUTO_EXPAND_TOOLS.has(event.toolName) &&
      canAutoExpand(event.input, expandableIds, denyIds);
    if (!auto) {
      if (!ctx.hasUI) {
        // Non-interactive: fail safe. Tool runs with literal placeholders.
        return;
      }
      // Show the user what will REALLY execute with the secret expanded.
      const preview = JSON.stringify(expandInput(structuredClone(event.input), secretVault, denyIds), null, 2);
      const allow = await ctx.ui.confirm(
        `Secret Expansion: ${event.toolName}`,
        `The agent wants to run this with a redacted secret expanded to its real value:\n\n${preview}\n\nAllow?`,
      );
      if (!allow) return; // run with placeholders (fails safely, no leak)
    }

    expandInput(event.input, secretVault, denyIds);
  });

  pi.on("context", (event, ctx) => {
    const key = getHmacKey(ctx.cwd);
    const catalog = loadCatalog(ctx.cwd, key);
    const allowlist = loadAllowlist(ctx.cwd, key);
    const entries = buildRedactionEntries(event.messages, catalog, allowlist, key);
    // Drop vault entries whose placeholder left the active context (e.g. after compaction).
    pruneVault(event.messages);
    if (entries.length === 0) return;

    if (ctx.hasUI) {
      const fresh = entries.filter((e) => !notifiedSecrets.has(e.value));
      if (fresh.length > 0) {
        ctx.ui.notify(`[Snoop] Redacting ${fresh.length} secret(s) before LLM call. Run /snoop to classify.`, "warning");
      }
      for (const e of fresh) notifiedSecrets.add(e.value);
    }

    return { messages: redactMessages(event.messages, entries) };
  });

  pi.registerCommand("snoop", {
    description: "Scan context for secrets (/snoop: unclassified only, /snoop list: all secrets with colors)",
    getArgumentCompletions: (prefix) => {
      const subcommands = ["list", "all", "salt", "salt --global", "fix", "help"];
      const matches = subcommands.filter((c) => c.startsWith(prefix.toLowerCase()));
      return matches.map((c) => ({
        value: c,
        label: c,
        description:
          c.startsWith("salt")
            ? "Manage HMAC salt key"
            : c === "fix"
              ? "Reconcile hand-edited catalog/allowlist files"
              : c === "help"
                ? "Show help menu"
                : "List all context secrets (color-coded)",
      }));
    },
    handler: async (args: string, ctx: ExtensionCommandContext) => {
      const trimmedArgs = args.trim();
      const lowerArgs = trimmedArgs.toLowerCase();

      // Subcommand: /snoop help
      if (lowerArgs === "help" || lowerArgs === "-h") {
        const lines = [
          "/snoop                     — list & classify UNCLASSIFIED secrets only",
          "/snoop list                — list ALL secrets, color-coded by status",
          "/snoop fix                 — reconcile hand-edited catalog/allowlist files",
          "/snoop salt                — view / set / generate HMAC salt (project or global)",
          "/snoop salt <key>          — set the project salt directly",
          "/snoop salt --global <key> — set the global salt directly",
          "/snoop help                — show this menu",
          "",
          "Statuses:",
          "  [UNCLASSIFIED]  needs your review",
          "  [PROTECTED]     redacted; broker may expand it in local tools",
          "  [DISALLOWED]    redacted; broker NEVER expands it (agent must not use it)",
          "  [ALLOWED]       intentional secret, sent to the LLM as-is",
          "  [FALSE POSITIVE] benign token, sent to the LLM as-is",
          "",
          "Redaction: every non-allowlisted secret becomes [REDACTED_SECRET:<id>] before each LLM call.",
          "Broker: write/edit auto-expand placeholders; bash & other tools ask first; disallowed never expand.",
        ];
        if (ctx.hasUI) {
          await ctx.ui.select("Context-Snooper Help", lines);
        } else {
          ctx.ui.notify(lines.join("\n"), "info");
        }
        return;
      }

      // Subcommand: /snoop fix
      if (lowerArgs === "fix") {
        const res = fixLists(ctx.cwd);
        const summary = res.changed ? res.notes.join("; ") : "lists already consistent";
        ctx.ui.notify(`[Snoop] fix: ${summary}`, res.changed ? "warning" : "info");
        return;
      }

      // Subcommand: /snoop salt [...]
      if (trimmedArgs.startsWith("salt")) {
        const saltSubArg = trimmedArgs.slice(4).trim();
        const currentInfo = getHmacKeyInfo(ctx.cwd);
        const preview = formatSecretPreview(currentInfo.key, 6, 4);

        let scope: "project" | "global" = "project";
        let targetKey: string | undefined;

        if (saltSubArg.includes("--global") || saltSubArg.startsWith("-g")) {
          scope = "global";
          targetKey = saltSubArg.replace(/--global|-g/, "").trim() || undefined;
        } else if (saltSubArg.length > 0) {
          scope = "project";
          targetKey = saltSubArg;
        }

        // If no key was passed as argument, open interactive dialog
        if (!targetKey) {
          if (!ctx.hasUI) {
            ctx.ui.notify(`Current Salt: [${currentInfo.source.toUpperCase()}] ${preview}`, "info");
            return;
          }

          const scopeChoice = await ctx.ui.select(
            `HMAC Salt: [${currentInfo.source.toUpperCase()}] "${preview}"`,
            [
              "1. Set Project Salt (.pi-hmac-key in current project)",
              "2. Set Global Salt (~/.pi/context-snooper.key for all projects)",
              "3. Generate New Random Key (Project)",
              "4. Generate New Random Key (Global)",
              "5. Cancel",
            ],
          );

          if (!scopeChoice || scopeChoice.startsWith("5.")) return;

          if (scopeChoice.startsWith("1.")) {
            scope = "project";
            const val = await ctx.ui.input("Enter new Project HMAC Salt / Secret Key:");
            if (!val || !val.trim()) return;
            targetKey = val.trim();
          } else if (scopeChoice.startsWith("2.")) {
            scope = "global";
            const val = await ctx.ui.input("Enter new Global HMAC Salt / Secret Key:");
            if (!val || !val.trim()) return;
            targetKey = val.trim();
          } else if (scopeChoice.startsWith("3.")) {
            scope = "project";
            targetKey = randomBytes(32).toString("hex");
          } else if (scopeChoice.startsWith("4.")) {
            scope = "global";
            targetKey = randomBytes(32).toString("hex");
          }
        }

        if (!targetKey) return;

        // Check if existing entries exist in catalog or allowlist
        if (hasPersistedEntries(ctx.cwd) && ctx.hasUI) {
          const confirm = await ctx.ui.confirm(
            "Warning: Existing Catalog Hashes",
            "Changing the salt will invalidate existing entries in secrets-catalog.json and secrets-allowlist.json (stored hashes will no longer match). Proceed?",
          );
          if (!confirm) {
            ctx.ui.notify("[Snoop] Salt update cancelled.", "info");
            return;
          }
        }

        try {
          const res = setHmacKey(targetKey, scope, ctx.cwd);
          const gitnote = res.gitignored ? " (added to .gitignore)" : "";
          ctx.ui.notify(`[Snoop] Set ${scope} salt in ${res.path}${gitnote}.`, "info");
        } catch (err: any) {
          ctx.ui.notify(`[Snoop] Failed to set salt: ${err.message}`, "error");
        }
        return;
      }

      const isListMode = trimmedArgs.toLowerCase() === "list" || trimmedArgs.toLowerCase() === "all";
      const key = getHmacKey(ctx.cwd);
      const catalog = loadCatalog(ctx.cwd, key);
      const allowlist = loadAllowlist(ctx.cwd, key);
      const { messages } = ctx.sessionManager.buildSessionContext();

      // In list mode, scan for all statuses. In default mode, scan for unclassified only.
      const allHits = scanMessages(messages, catalog, allowlist, { includeAllowed: isListMode, key });
      const hits = isListMode ? allHits : allHits.filter((h) => h.status === "unclassified");

      if (hits.length === 0) {
        if (isListMode) {
          ctx.ui.notify(`[Snoop] No secrets detected (${messages.length} messages checked).`, "info");
        } else {
          ctx.ui.notify(`[Snoop] No unclassified secrets in context. Run '/snoop list' to view all.`, "info");
        }
        return;
      }

      ctx.ui.notify(
        `[Snoop] Found ${hits.length} ${isListMode ? "total" : "unclassified"} secret(s)!`,
        isListMode ? "info" : "warning",
      );
      if (!ctx.hasUI) return;

      let unclassified = groupHitsByValue(hits);

      while (unclassified.length > 0) {
        const items = unclassified.map((g, i) =>
          `${i + 1}. ${getStatusBadge(g.hit.status)} ${g.hit.rule}: "${formatSecretPreview(g.hit.matched)}" x${g.indices.length} (msgs #${g.indices.join(", #")})`
        );
        items.push("Exit");

        const title = isListMode
          ? `All Context Secrets (${unclassified.length} items)`
          : `Unclassified Secrets (${unclassified.length} remaining)`;
        const selected = await ctx.ui.select(title, items);
        if (!selected || selected === "Exit") break;

        let currentIndex = parseInt(selected.split(".")[0], 10) - 1;
        if (Number.isNaN(currentIndex) || currentIndex < 0 || currentIndex >= unclassified.length) {
          currentIndex = 0;
        }

        while (currentIndex < unclassified.length) {
          const hit = unclassified[currentIndex].hit;
          const preview = formatSecretPreview(hit.matched, 12, 10);
          const title = `Classify [${currentIndex + 1}/${unclassified.length}] ${getStatusBadge(hit.status)}: "${preview}" (${hit.matched.length}c, ${unclassified[currentIndex].indices.length}x)`;

          const choice = await ctx.ui.select(title, [
            "1. Protected — catalog: redacted, agent may use",
            "2. Disallowed — catalog: redacted, agent may NOT use",
            "3. Allowed — allowlist: sent to LLM as-is",
            "4. False Positive — allowlist: sent to LLM as-is",
            "5. Skip — Next secret",
            "6. Back to List (or press Esc)",
          ]);

          if (!choice || choice.startsWith("6.")) break;

          let action: "protected" | "disallowed" | "allowed" | "false_positive" | undefined;
          if (choice.startsWith("1.")) action = "protected";
          else if (choice.startsWith("2.")) action = "disallowed";
          else if (choice.startsWith("3.")) action = "allowed";
          else if (choice.startsWith("4.")) action = "false_positive";
          else if (choice.startsWith("5.")) {
            currentIndex++;
            continue;
          }

          if (action) {
            const defaultLabel = generateDefaultLabel(hit);
            const input = await ctx.ui.input(`Label for "${preview}" (Enter to keep):`, defaultLabel);
            if (input === undefined) continue;
            const label = input.trim() || defaultLabel;
            recordClassification(ctx.cwd, hit.matched, action, hit.type, label, key);
            ctx.ui.notify(`[Snoop] ${action.toUpperCase()}: "${label}"`, "info");
            const val = hit.matched;
            unclassified = unclassified.filter((g) => g.hit.matched !== val);
          }

          if (currentIndex >= unclassified.length) {
            currentIndex = 0;
          }
        }
      }

      if (unclassified.length === 0) {
        ctx.ui.notify("[Snoop] All items processed.", "info");
      }
    },
  });
}
