import assert from "node:assert/strict";
import { existsSync, unlinkSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

// Tests mutate secrets-catalog.json / secrets-allowlist.json in cwd; restore originals afterwards.
const catalogPath = resolve(process.cwd(), "secrets-catalog.json");
const allowlistPath = resolve(process.cwd(), "secrets-allowlist.json");
const keyPath = resolve(process.cwd(), ".pi-hmac-key");
const gitignorePath = resolve(process.cwd(), ".gitignore");
const originalCatalog = existsSync(catalogPath) ? readFileSync(catalogPath, "utf8") : undefined;
const originalAllowlist = existsSync(allowlistPath) ? readFileSync(allowlistPath, "utf8") : undefined;
const originalKey = existsSync(keyPath) ? readFileSync(keyPath, "utf8") : undefined;
const originalGitignore = existsSync(gitignorePath) ? readFileSync(gitignorePath, "utf8") : undefined;

function restoreFiles() {
  if (originalCatalog !== undefined) writeFileSync(catalogPath, originalCatalog, "utf8");
  else if (existsSync(catalogPath)) unlinkSync(catalogPath);
  if (originalAllowlist !== undefined) writeFileSync(allowlistPath, originalAllowlist, "utf8");
  else if (existsSync(allowlistPath)) unlinkSync(allowlistPath);
  if (originalKey !== undefined) writeFileSync(keyPath, originalKey, "utf8");
  else if (existsSync(keyPath)) unlinkSync(keyPath);
  if (originalGitignore !== undefined) writeFileSync(gitignorePath, originalGitignore, "utf8");
  else if (existsSync(gitignorePath)) unlinkSync(gitignorePath);
}
import {
  shannonEntropy,
  hasCharDiversity,
  scanText,
  scanMessages,
  loadCatalog,
  loadAllowlist,
  recordClassification,
  formatSecretPreview,
  generateDefaultLabel,
  groupHitsByValue,
  buildRedactionEntries,
  redactMessages,
  computeHmac,
  matchCandidateInList,
  getStatusBadge,
  getHmacKeyInfo,
  getHmacKey,
  setHmacKey,
  hasPersistedEntries,
  clearScanCache,
  getScanCacheStats,
  secretVault,
  expandInput,
  expandSecretsInPlace,
  hasPlaceholder,
  secretId,
  getDeniedIds,
  getExpandableIds,
  placeholderIdsIn,
  canAutoExpand,
  pruneVault,
  fixLists,
  REDACTOR_NOTE,
  DEFAULT_CATALOG,
  type AllowlistEntry,
  type SecretHit,
} from "./index.ts";

// 0. Secret preview formatting & label generation
assert.equal(formatSecretPreview("short"), "short");
assert.equal(formatSecretPreview("fake_staging_db_password_2025!", 8, 6), "fake_sta..._2025!");

assert.equal(
  generateDefaultLabel({ type: "pattern", rule: "AWS Access Key", matched: "AKIA123", role: "user", messageIndex: 0 }),
  "AWS Access Key",
);
assert.equal(
  generateDefaultLabel({ type: "catalog", rule: "exact", matched: "my_db_password", role: "user", messageIndex: 0 }),
  "Database password",
);
assert.equal(
  generateDefaultLabel({ type: "entropy", rule: "entropy", matched: "12345678901234567890", role: "user", messageIndex: 0 }),
  "High-entropy token (20c)",
);

// 1. Entropy calculation check
assert.equal(shannonEntropy(""), 0);
assert.equal(shannonEntropy("aaaa"), 0);
assert(shannonEntropy("abcdefgh12345678") > 3.8);

// 2. Character diversity check
assert(!hasCharDiversity("abcdefghijklmnop"));
assert(hasCharDiversity("abcdefGHIJKL1234"));

// 3. Exact catalog match with metadata
const catalogHits = scanText("DATABASE_URL=fake_staging_db_password_2025!");
assert.equal(catalogHits.length, 1);
assert.equal(catalogHits[0].type, "catalog");
assert.equal(catalogHits[0].matched, "fake_staging_db_password_2025!");

// 4. Pattern match
const patternHits = scanText("Here is the key: FAKE_sk-abcdef1234567890abcdef123456");
assert.equal(patternHits.length, 1);
assert.equal(patternHits[0].type, "pattern");
assert.equal(patternHits[0].rule, "Fake/Real OpenAI Key");

// 5. Entropy detection on random token
const entropyHits = scanText("random_token: aB3!dE9#kL2$mN8%pQ1^99zZ");
assert(entropyHits.some((h) => h.type === "entropy"));

// 6. Whitelist / Allowlist suppression test
const allowlist: AllowlistEntry[] = [
  { value: "fake_staging_db_password_2025!", label: "Staging DB Password", decision: "allowed", source: "catalog", addedAt: "2025-01-01" },
  { value: "aB3!dE9#kL2$mN8%pQ1^99zZ", label: "Safe token", decision: "false_positive", source: "entropy", addedAt: "2025-01-01" },
];

const suppressedCatalog = scanText("DATABASE_URL=fake_staging_db_password_2025!", "user", 0, DEFAULT_CATALOG, allowlist);
assert.equal(suppressedCatalog.length, 0, "Whitelisted catalog secret should not trigger hit");

const suppressedEntropy = scanText("random_token: aB3!dE9#kL2$mN8%pQ1^99zZ", "user", 0, DEFAULT_CATALOG, allowlist);
assert.equal(suppressedEntropy.length, 0, "Whitelisted entropy secret should not trigger hit");

// 7. Context scan across multiple messages with allowlist
const fakeMessages = [
  { role: "user", content: "Can you connect with fake_org_secret_token_abc123 ?" },
  { role: "assistant", content: [{ type: "text", text: "Connecting now." }] },
  {
    role: "toolResult",
    content: [{ type: "text", text: "output: AKIA1234567890ABCDEF created" }],
  },
];
const msgHits = scanMessages(fakeMessages, DEFAULT_CATALOG, []);
assert.equal(msgHits.length, 2);

const msgHitsWithAllow = scanMessages(fakeMessages, DEFAULT_CATALOG, [
  { value: "AKIA1234567890ABCDEF", label: "Test AWS key", decision: "allowed", source: "pattern", addedAt: "2025-01-01" },
]);
assert.equal(msgHitsWithAllow.length, 1);
assert.equal(msgHitsWithAllow[0].matched, "fake_org_secret_token_abc123");

// 8. Pre-LLM redaction
const catalogForRedaction = [...DEFAULT_CATALOG];
const allowForRedaction: AllowlistEntry[] = [
  { value: "fake_staging_db_password_2025!", label: "Staging DB", decision: "allowed", source: "catalog", addedAt: "2025-01-01" },
];
const redactMessagesTest = [
  { role: "user", content: "Use fake_staging_db_password_2025! and fake_org_secret_token_abc123" },
  {
    role: "assistant",
    content: [
      { type: "text", text: "OK, running it" },
      { type: "thinking", thinking: "thinking" },
      { type: "toolCall", id: "c1", name: "bash", arguments: { command: `echo fake_org_secret_token_abc123` } },
    ],
  },
  { role: "toolResult", toolCallId: "c1", toolName: "bash", content: [{ type: "text", text: "out: AKIA1234567890ABCDEF" }], isError: false },
];
const entries = buildRedactionEntries(redactMessagesTest, catalogForRedaction, allowForRedaction);
assert(!entries.some((e) => e.value === "fake_staging_db_password_2025!"), "allowlisted secret must not be redacted");
assert(entries.some((e) => e.value === "fake_org_secret_token_abc123"));
assert(entries.some((e) => e.value === "AKIA1234567890ABCDEF"));

const redacted = redactMessages(redactMessagesTest, entries);
assert(!redacted[0].content.includes("fake_org_secret_token_abc123"));
assert(redacted[0].content.includes("fake_staging_db_password_2025!"), "allowlisted secret passes through");
assert(!JSON.stringify(redacted[1].content).includes("fake_org_secret_token_abc123"), "toolCall arguments redacted");
assert(!redacted[2].content[0].text.includes("AKIA1234567890ABCDEF"));

// deterministic placeholder: same secret -> same id across messages
const same1 = redacted[0].content.match(/\[REDACTED_SECRET:[a-f0-9]{8}\]/);
assert(same1, "placeholder format");
const t = redacted[2].content[0].text;
const same2 = t.match(/\[REDACTED_SECRET:[a-f0-9]{8}\]/);
assert(same2);

// original messages untouched (request-local transform)
assert(redactMessagesTest[0].content.includes("fake_org_secret_token_abc123"), "originals not mutated");

// 9. Classification & Mutual Exclusion persistence test with labels and HMAC
// Use an explicit key (recordClassification writes with getHmacKey(cwd));
// default arg of matchCandidateInList() resolves without cwd.
const baseKey = getHmacKey(process.cwd());
const testSecret = "test_temporary_classification_secret_xyz";
const testSecretId = computeHmac(testSecret, baseKey);
recordClassification(process.cwd(), testSecret, "allowed", "entropy", "Temporary test secret");
let loadedAllow = loadAllowlist(process.cwd(), baseKey);
const allowEntry = matchCandidateInList(testSecret, loadedAllow, baseKey);
assert(allowEntry && allowEntry.decision === "allowed" && allowEntry.label === "Temporary test secret");
assert.equal(allowEntry.id, testSecretId, "stored with HMAC id");

recordClassification(process.cwd(), testSecret, "protected", "catalog", "Promoted protected secret");
loadedAllow = loadAllowlist(process.cwd(), baseKey);
const loadedCat = loadCatalog(process.cwd(), baseKey);
assert(!matchCandidateInList(testSecret, loadedAllow, baseKey), "Promoted to protected should be removed from allowlist");
const catEntry = matchCandidateInList(testSecret, loadedCat, baseKey);
assert(catEntry && catEntry.status === "protected" && catEntry.label === "Promoted protected secret");
assert.equal(catEntry.id, testSecretId, "catalog entry has HMAC id");

// Clean up test entry from catalog and allowlist
recordClassification(process.cwd(), testSecret, "false_positive", "entropy");
const cleanAllow = loadAllowlist(process.cwd(), baseKey).filter((e) => e.value !== testSecret && e.id !== testSecretId);
const cleanCat = loadCatalog(process.cwd(), baseKey).filter((e) => e.value !== testSecret && e.id !== testSecretId);
import { saveAllowlist, saveCatalog } from "./index.ts";
saveAllowlist(process.cwd(), cleanAllow);
saveCatalog(process.cwd(), cleanCat);

// 10. Hit grouping: same secret value across messages collapses to one entry
const g = groupHitsByValue([
  { type: "catalog", rule: "exact-match", matched: "S1", role: "user", messageIndex: 1 },
  { type: "catalog", rule: "exact-match", matched: "S1", role: "toolResult", messageIndex: 4 },
  { type: "pattern", rule: "AWS Access Key", matched: "S2", role: "user", messageIndex: 2 },
] as SecretHit[]);
assert.equal(g.length, 2);
assert.deepEqual(g[0].indices, [1, 4]);
assert.equal(g[1].hit.matched, "S2");

// 11. Code defaults never get baked into the catalog file
recordClassification(process.cwd(), "temp_check_secret_value_1", "allowed", "entropy");
const rawCatalog = JSON.parse(
  readFileSync(resolve(process.cwd(), "secrets-catalog.json"), "utf8"),
);
assert(Array.isArray(rawCatalog));
for (const d of DEFAULT_CATALOG) {
  assert(!rawCatalog.some((e) => e.value === d.value), `default ${d.value} must not be persisted`);
}
// cleanup
recordClassification(process.cwd(), "temp_check_secret_value_1", "false_positive", "entropy");
saveAllowlist(process.cwd(), loadAllowlist(process.cwd()).filter((e) => e.value !== "temp_check_secret_value_1"));

// 12. Invariant: allowlist wins over catalog on load (self-heals hand edits)
const overlapSecret = "overlapping_test_secret_value";
const overlapKey = getHmacKey(process.cwd());
const overlapId = computeHmac(overlapSecret, overlapKey);
saveCatalog(process.cwd(), [{ id: overlapId, label: "Overlap Cat", status: "protected", source: "catalog", addedAt: "2025-01-01" }]);
saveAllowlist(process.cwd(), [{ id: overlapId, label: "Overlap Allow", decision: "allowed", source: "pattern", addedAt: "2025-01-01" }]);
assert(
  !matchCandidateInList(overlapSecret, loadCatalog(process.cwd(), overlapKey), overlapKey),
  "allowlisted value must be excluded from catalog",
);
saveCatalog(process.cwd(), []);
saveAllowlist(process.cwd(), []);

// 13. HMAC matching: matching secret by HMAC id without plaintext stored
const pureHmacSecret = "super_secret_db_pass_123";
const pureHmacId = computeHmac(pureHmacSecret);
const hmacCatalog = [{ id: pureHmacId, label: "Zero-plaintext DB Password", status: "protected" as const, source: "catalog", addedAt: "2025-01-01" }];
const hmacHits = scanText("DATABASE_URL=postgres://user:super_secret_db_pass_123@localhost", "user", 0, hmacCatalog, []);
assert.equal(hmacHits.length, 1);
assert.equal(hmacHits[0].matched, pureHmacSecret);
assert.equal(hmacHits[0].rule, "Zero-plaintext DB Password");
assert.equal(hmacHits[0].status, "protected");

// 14. /snoop vs /snoop list (includeAllowed)
const mixedMessages = [
  { role: "user", content: "AKIA1234567890ABCDEF and some unclassified FAKE_sk-abcdef1234567890abcdef123456" },
];
const allowedOnly = [{ id: computeHmac("AKIA1234567890ABCDEF"), label: "Test Key", decision: "allowed" as const, source: "pattern", addedAt: "2025-01-01" }];
// Default scan (includeAllowed = false): AKIA is suppressed
const defaultHits = scanMessages(mixedMessages, [], allowedOnly, { includeAllowed: false });
assert.equal(defaultHits.length, 1);
assert(defaultHits[0].matched.startsWith("FAKE_sk"));
assert.equal(defaultHits[0].status, "unclassified");

// List mode (includeAllowed = true): both returned with distinct status
const listHits = scanMessages(mixedMessages, [], allowedOnly, { includeAllowed: true });
assert.equal(listHits.length, 2);
const allowedHit = listHits.find((h) => h.matched === "AKIA1234567890ABCDEF");
assert(allowedHit && allowedHit.status === "allowed");
const unclassifiedHit = listHits.find((h) => h.matched.startsWith("FAKE_sk"));
assert(unclassifiedHit && unclassifiedHit.status === "unclassified");

// Status color badges
assert(getStatusBadge("protected").includes("[PROTECTED]"));
assert(getStatusBadge("allowed").includes("[ALLOWED]"));
assert(getStatusBadge("unclassified").includes("[UNCLASSIFIED]"));
assert(getStatusBadge("false_positive").includes("[FALSE POSITIVE]"));

// 15. Salt management: getHmacKeyInfo, setHmacKey, .gitignore auto-append, hasPersistedEntries
const initialInfo = getHmacKeyInfo(process.cwd());
assert(initialInfo.key.length > 0);

// Test setting project salt
const testProjectSalt = "custom_project_salt_test_123456";
writeFileSync(gitignorePath, "node_modules\n", "utf8");
const setResult = setHmacKey(testProjectSalt, "project", process.cwd());
assert.equal(setResult.path, keyPath);
assert.equal(setResult.gitignored, true);
assert(readFileSync(gitignorePath, "utf8").includes(".pi-hmac-key"));

const projectInfo = getHmacKeyInfo(process.cwd());
assert.equal(projectInfo.source, "project");
assert.equal(projectInfo.key, testProjectSalt);

// Test hasPersistedEntries
saveCatalog(process.cwd(), [{ id: "123", label: "t", status: "protected", source: "catalog", addedAt: "2025" }]);
assert.equal(hasPersistedEntries(process.cwd()), true);
saveCatalog(process.cwd(), []);
assert.equal(hasPersistedEntries(process.cwd()), false);

// 16. Delta scanning cache: only newly appended messages are parsed
clearScanCache();
const deltaMsg1 = { role: "user", content: "Check AKIA1234567890ABCDEF in message 1" };
const deltaMsg2 = { role: "assistant", content: [{ type: "text", text: "Connecting to server" }] };
const deltaMsg3 = { role: "toolResult", content: [{ type: "text", text: "Got FAKE_sk-abcdef1234567890abcdef123456" }] };

// Turn 1: scans msg1
scanMessages([deltaMsg1], [], []);
let stats = getScanCacheStats();
assert.equal(stats.misses, 1, "msg1 was parsed (miss=1)");
assert.equal(stats.hits, 0, "no cache hits yet");

// Turn 2: scans msg1 + msg2
// msg1 must hit cache, msg2 is parsed as delta
scanMessages([deltaMsg1, deltaMsg2], [], []);
stats = getScanCacheStats();
assert.equal(stats.misses, 2, "only msg2 was newly parsed (miss=2)");
assert.equal(stats.hits, 1, "msg1 was served from cache (hit=1)");

// Turn 3: scans msg1 + msg2 + msg3
// msg1 and msg2 hit cache, msg3 is parsed as delta
scanMessages([deltaMsg1, deltaMsg2, deltaMsg3], [], []);
stats = getScanCacheStats();
assert.equal(stats.misses, 3, "only msg3 was newly parsed (miss=3)");
assert.equal(stats.hits, 3, "msg1 and msg2 were served from cache (hits=3)");

// Invalidation: clearScanCache forces re-parsing
clearScanCache();
stats = getScanCacheStats();
assert.equal(stats.misses, 0);
assert.equal(stats.hits, 0);
scanMessages([deltaMsg1], [], []);
assert.equal(getScanCacheStats().misses, 1);

// 17. Secret broker: vault population + placeholder expansion
secretVault.clear();
const brokerMsgs = [{ role: "user", content: "key is fake_org_secret_token_abc123 ok" }];
buildRedactionEntries(brokerMsgs, DEFAULT_CATALOG, []);
const brokerId = secretId("fake_org_secret_token_abc123");
assert.equal(secretVault.get(brokerId), "fake_org_secret_token_abc123", "vault populated at redaction time");

// Round-trip: model writes an env file referencing the placeholder
const envFile = { path: ".env", content: `DB_PASS=[REDACTED_SECRET:${brokerId}]` };
assert(hasPlaceholder(envFile));
expandInput(envFile);
assert.equal(envFile.content, "DB_PASS=fake_org_secret_token_abc123", "placeholder expands to plaintext");
assert(!hasPlaceholder(envFile), "no placeholders left after expansion");

// Unknown id fails safe: placeholder stays literal
const unknownInput = { content: "tok=[REDACTED_SECRET:deadbeef]" };
expandInput(unknownInput);
assert.equal(unknownInput.content, "tok=[REDACTED_SECRET:deadbeef]", "unknown id not expanded");

// In-place mutation of nested structures (bash command preview path)
const bashInput: any = { command: "export K=[REDACTED_SECRET:" + brokerId + "]", opts: { env: [`X=[REDACTED_SECRET:${brokerId}]`] } };
expandSecretsInPlace(bashInput);
assert.equal(bashInput.command, "export K=fake_org_secret_token_abc123");
assert.equal(bashInput.opts.env[0], "X=fake_org_secret_token_abc123");

secretVault.clear();

// 18. Disallowed tier: redacted + broker refuses expansion
const testKey = getHmacKey(process.cwd()); // project salt set in test 15
const disallowedSecret = "disallowed_prod_db_password_456";
const disallowedId = computeHmac(disallowedSecret, testKey);
recordClassification(process.cwd(), disallowedSecret, "disallowed", "catalog", "Prod DB (agent must not use)");

// catalog entry carries use:"deny" and is removed from allowlist
const catAfter = loadCatalog(process.cwd(), testKey);
const disEntry = matchCandidateInList(disallowedSecret, catAfter, testKey);
assert(disEntry && disEntry.use === "deny", "disallowed stored as use:deny in catalog");
assert.equal(disEntry.id, disallowedId);
assert(!matchCandidateInList(disallowedSecret, loadAllowlist(process.cwd(), testKey), testKey), "disallowed must not be in allowlist");
assert.deepEqual(Array.from(getDeniedIds(catAfter)), [disallowedId.slice(0, 8)], "denied ids use placeholder 8-char prefix");

// scan resolves status "disallowed"
const disHits = scanText(`pw=${disallowedSecret}`, "user", 0, catAfter, [], { key: testKey });
assert.equal(disHits.length, 1);
assert.equal(disHits[0].status, "disallowed");
assert(getStatusBadge("disallowed").includes("[DISALLOWED]"));

// still redacted (passes includeAllowed=false filter => covered by redaction scan)
const disEntries = buildRedactionEntries(
  [{ role: "user", content: `pw=${disallowedSecret}` }],
  catAfter,
  [],
  testKey,
);
assert.equal(disEntries.length, 1, "disallowed secret must still be redacted");

// broker: expandable for protected, refused for disallowed — same input, mixed ids
const protectedSecret = "fake_org_secret_token_abc123";
const protectedId = computeHmac(protectedSecret, testKey).slice(0, 8); // placeholder format
secretVault.set(protectedId, protectedSecret);
secretVault.set(disallowedId.slice(0, 8), disallowedSecret);
const denyIds = getDeniedIds(catAfter);
const disPlaceholderId = disallowedId.slice(0, 8);
const mixedInput = {
  content: `ALLOWED_USE=[REDACTED_SECRET:${protectedId}] BLOCKED_USE=[REDACTED_SECRET:${disPlaceholderId}]`,
};
expandInput(mixedInput, secretVault, denyIds);
assert.equal(
  mixedInput.content,
  `ALLOWED_USE=${protectedSecret} BLOCKED_USE=[REDACTED_SECRET:${disPlaceholderId}]`,
  "protected expands, disallowed stays placeholder",
);
secretVault.clear();

// 19. /snoop fix: reconciles hand-edited files (allowlist wins, no defaults, ids filled, idempotent)
const fixKey = getHmacKey(process.cwd());
const overlapFixValue = "overlap_fix_value_xyz";
const overlapFixId = computeHmac(overlapFixValue, fixKey);
saveCatalog(
  process.cwd(),
  [
    { value: DEFAULT_CATALOG[0].value!, label: "Default dup", status: "protected", source: "catalog", addedAt: "2025-01-01" },
    { value: overlapFixValue, label: "Overlap", status: "protected", source: "catalog", addedAt: "2025-01-01" },
    { value: "legacy_value_no_id", label: "Legacy", status: "protected", source: "catalog", addedAt: "2025-01-01" },
    { value: "legacy_value_no_id", label: "Legacy", status: "protected", source: "catalog", addedAt: "2025-01-01" },
  ],
);
saveAllowlist(process.cwd(), [
  { id: overlapFixId, label: "Overlap allowed", decision: "allowed", source: "pattern", addedAt: "2025-01-01" },
  { id: overlapFixId, label: "Overlap allowed dup", decision: "allowed", source: "pattern", addedAt: "2025-01-01" },
]);

const fixRes = fixLists(process.cwd(), fixKey);
assert.equal(fixRes.changed, true, "fix reports changes");
const fixedCat = JSON.parse(readFileSync(catalogPath, "utf8"));
assert(!fixedCat.some((e: any) => e.value === DEFAULT_CATALOG[0].value!), "default stripped from catalog file");
assert(!fixedCat.some((e: any) => e.value === overlapFixValue), "allowlisted value removed from catalog");
const legacy = fixedCat.find((e: any) => e.value === "legacy_value_no_id");
assert(legacy && typeof legacy.id === "string" && legacy.id.length === 12, "missing id filled in");
assert.equal(fixedCat.length, 1, "duplicates removed");
const fixedAllow = JSON.parse(readFileSync(allowlistPath, "utf8"));
assert.equal(fixedAllow.length, 1, "allowlist deduped");

const fixRes2 = fixLists(process.cwd(), fixKey);
assert.equal(fixRes2.changed, false, "fix is idempotent");

// 20. Vault pruning: placeholder left the active context -> entry removed
secretVault.clear();
const pv1 = "aaaa1111";
const pv2 = "bbbb2222";
secretVault.set(pv1, "secret-one");
secretVault.set(pv2, "secret-two");
const pruned = pruneVault([
  { role: "assistant", content: [{ type: "toolCall", id: "c1", name: "write", arguments: { content: `K=[REDACTED_SECRET:${pv1}]` } }] },
]);
assert.equal(pruned, 1, "placeholder absent from context is pruned");
assert.equal(secretVault.get(pv1), "secret-one", "placeholder present in context survives");
assert(!secretVault.has(pv2));
secretVault.clear();

// Redactor note is agent-facing and references the placeholder format
assert(REDACTOR_NOTE.includes("[REDACTED_SECRET:<id>]"));
assert(REDACTOR_NOTE.includes("Do NOT attempt"));

secretVault.clear();

// 21. Broker auto-expand gate: only classified, expandable ids skip confirmation
const expKey = getHmacKey(process.cwd());
const expCat = [
  { id: computeHmac("classified_expandable_secret", expKey), label: "Okay", status: "protected" as const, use: "expand" as const, source: "catalog", addedAt: "2025" },
  { id: computeHmac("classified_denied_secret", expKey), label: "Nope", status: "protected" as const, use: "deny" as const, source: "catalog", addedAt: "2025" },
];
const expIds = getExpandableIds(expCat);
const denIds = getDeniedIds(expCat);
const expOk = computeHmac("classified_expandable_secret", expKey).slice(0, 8);
const expNo = computeHmac("classified_denied_secret", expKey).slice(0, 8);

assert.deepEqual(placeholderIdsIn({ content: `a=[REDACTED_SECRET:${expOk}] b=[REDACTED_SECRET:${expNo}]` }), [expOk, expNo]);
assert.deepEqual(placeholderIdsIn({ content: "nothing here" }), []);
assert.equal(canAutoExpand({ content: `v=[REDACTED_SECRET:${expOk}]` }, expIds, denIds), true, "classified expandable id auto-expands");
assert.equal(canAutoExpand({ content: `v=[REDACTED_SECRET:${expNo}]` }, expIds, denIds), false, "disallowed id never auto-expands");
assert.equal(canAutoExpand({ content: "v=[REDACTED_SECRET:00000000]" }, expIds, denIds), false, "unclassified id needs confirmation");
assert.equal(canAutoExpand({ content: "no placeholders" }, expIds, denIds), true, "placeholder-free input passes");

restoreFiles();
console.log("All context-snooper tests passed!");
