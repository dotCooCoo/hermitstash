"use strict";
/**
 * b.gateContract.buildContentGate — the content-guard gate action-chain
 * (serve / audit-only / sanitize / refuse) every content guard composes.
 *
 * The disposition of each finding is what the operator's POLICY for that class
 * selected, NOT the finding's impact severity:
 *   reject → refuse · a mitigation (strip / prefix / redact) → sanitize ·
 *   audit → audit-only.
 * The guard declares the binding via spec.dispositionFor(issue, opts), routed
 * through b.gateContract.policyDisposition / b.gateContract.charThreatDisposition. `refuse`
 * wins over `sanitize` wins over `audit-only`. Operator-injected extraIssues
 * carry no guard sanitizer, so a refusal-severity hit can only refuse. There is
 * NO re-validation: a sanitize-disposition finding runs the guard's sanitizer
 * and the output is served (a mitigation may be in-place, not removal, so a
 * second detector pass would wrongly refuse it); a sanitizer that throws falls
 * through to refuse.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var gc      = require("../../lib/gate-contract");

// Synthetic content guard. Each marker token emits a finding; the governing
// "policy" is operator-set via opts.cfgPolicy, so the SAME finding refuses /
// sanitizes / audits purely by policy — proving disposition is read from policy
// and not from the (here deliberately critical) severity.
//   "CFG"  → configurable (governed by opts.cfgPolicy)
//   "DENY" → always-dangerous denylist (always refuse)
//   "OBS"  → observational (always audit)
function _validate(input) {
  var text = Buffer.isBuffer(input) ? input.toString("utf8") : input;
  var issues = [];
  if (text.indexOf("CFG")  !== -1) issues.push({ kind: "configurable", severity: "critical", ruleId: "x.cfg" });
  if (text.indexOf("DENY") !== -1) issues.push({ kind: "denylisted",   severity: "critical", ruleId: "x.deny" });
  if (text.indexOf("OBS")  !== -1) issues.push({ kind: "observe",      severity: "warn",     ruleId: "x.obs" });
  return { ok: issues.length === 0, issues: issues };
}
function _dispositionFor(issue, opts) {
  switch (issue.kind) {
    case "configurable": return gc.policyDisposition(opts.cfgPolicy);
    case "denylisted":   return "refuse";
    case "observe":      return "audit";
    default:             return null;
  }
}
// The sanitizer removes the "CFG" marker (the only mitigable class).
function _produceSanitized(input) {
  var text = Buffer.isBuffer(input) ? input.toString("utf8") : input;
  return text.split("CFG").join("");
}

function _gate(opts, extra) {
  return gc.buildContentGate(Object.assign({
    name:             "synthetic:test",
    opts:             opts,
    validate:         _validate,
    dispositionFor:   _dispositionFor,
    produceSanitized: function (t) { return _produceSanitized(t); },
  }, extra || {}));
}

async function run() {
  function act(gate, text) {
    return gate.check({ bytes: Buffer.from(text, "utf8") }).then(function (d) { return d.action; });
  }

  var strip  = _gate({ cfgPolicy: "strip" });
  var reject = _gate({ cfgPolicy: "reject" });
  var audit  = _gate({ cfgPolicy: "audit" });

  check("clean input → serve",                         (await act(strip, "hello world")) === "serve");
  check("observational-only → audit-only",             (await act(strip, "a OBS b")) === "audit-only");
  check("denylist finding → refuse (always)",          (await act(strip, "x DENY y")) === "refuse");

  // The SAME configurable finding, three policies — disposition follows policy.
  check("configurable under strip-policy → sanitize",  (await act(strip,  "a CFG b")) === "sanitize");
  check("configurable under reject-policy → refuse",   (await act(reject, "a CFG b")) === "refuse");
  check("configurable under audit-policy → audit-only",(await act(audit,  "a CFG b")) === "audit-only");

  // Precedence: refuse > sanitize > audit.
  check("denylist beside a sanitizable finding → refuse",
                                                       (await act(strip, "CFG DENY")) === "refuse");
  check("sanitizable beside an observational finding → sanitize",
                                                       (await act(strip, "CFG OBS")) === "sanitize");

  // The sanitize output is the repaired bytes (the CFG marker removed).
  var d = await strip.check({ bytes: Buffer.from("keep CFG keep", "utf8") });
  check("sanitize: output is a Buffer with the finding removed",
        d.action === "sanitize" && Buffer.isBuffer(d.sanitized) &&
        d.sanitized.toString("utf8").indexOf("CFG") === -1 &&
        d.sanitized.toString("utf8").indexOf("keep") !== -1);

  // No produceSanitized → a sanitize-disposition finding cannot be repaired → refuse.
  var noSan = gc.buildContentGate({ name: "n", opts: { cfgPolicy: "strip" },
    validate: _validate, dispositionFor: _dispositionFor });
  check("no produceSanitized: sanitizable finding → refuse",
        (await noSan.check({ bytes: Buffer.from("CFG", "utf8") })).action === "refuse");

  // A sanitizer that throws falls through to refuse.
  var throws = _gate({ cfgPolicy: "strip" }, { produceSanitized: function () { throw new Error("boom"); } });
  check("sanitizer throws → refuse",
        (await throws.check({ bytes: Buffer.from("CFG", "utf8") })).action === "refuse");

  // sanitizeBlockingKinds: skip the attempt for a class the sanitizer must not touch.
  var blocked = _gate({ cfgPolicy: "strip" }, { sanitizeBlockingKinds: ["configurable"] });
  check("blocking-kind present → refuse without sanitize attempt",
        (await blocked.check({ bytes: Buffer.from("CFG", "utf8") })).action === "refuse");

  // extraIssues: operator-injected detect-only findings refuse on a high hit
  // (the guard owns no sanitizer for them) regardless of the guard's own policy.
  var withExtra = _gate({ cfgPolicy: "strip" }, {
    extraIssues: function (subject) {
      var text = Buffer.isBuffer(subject) ? subject.toString("utf8") : subject;
      return text.indexOf("RULE") !== -1
        ? [{ kind: "operator.rule", severity: "high", ruleId: "operator.rule" }] : [];
    },
  });
  check("extraIssues high hit → refuse (no guard sanitizer for it)",
        (await withExtra.check({ bytes: Buffer.from("RULE", "utf8") })).action === "refuse");
  check("extraIssues with no hit → still serve",
        (await withExtra.check({ bytes: Buffer.from("clean", "utf8") })).action === "serve");

  // ctxField:"bytes" reads ctx.bytes raw (no utf8 round-trip in the contract).
  var bytesGate = _gate({ cfgPolicy: "strip" }, { ctxField: "bytes" });
  check("ctxField bytes: still drives the chain",
        (await bytesGate.check({ bytes: Buffer.from("a CFG b", "utf8") })).action === "sanitize");

  // policyDisposition unit.
  check("policyDisposition reject → refuse",     gc.policyDisposition("reject") === "refuse");
  check("policyDisposition strip → sanitize",    gc.policyDisposition("strip") === "sanitize");
  check("policyDisposition prefix-tab → sanitize", gc.policyDisposition("prefix-tab") === "sanitize");
  check("policyDisposition audit → audit",       gc.policyDisposition("audit") === "audit");
  check("policyDisposition audit-only → audit",  gc.policyDisposition("audit-only") === "audit");

  // severityDisposition unit: the non-sanitizing gate's serve/audit-only/refuse chain.
  check("severityDisposition no issues → serve",
        JSON.stringify(gc.severityDisposition([])) === JSON.stringify({ ok: true, action: "serve" }));
  check("severityDisposition low/medium only → audit-only",
        gc.severityDisposition([{ severity: "low" }, { severity: "medium" }]).action === "audit-only");
  check("severityDisposition any high → refuse",
        gc.severityDisposition([{ severity: "low" }, { severity: "high" }]).ok === false &&
        gc.severityDisposition([{ severity: "high" }]).action === "refuse");
  check("severityDisposition any critical → refuse",
        gc.severityDisposition([{ severity: "critical" }]).action === "refuse");
  check("severityDisposition carries issues on audit-only/refuse, omits on serve",
        gc.severityDisposition([{ severity: "low" }]).issues.length === 1 &&
        gc.severityDisposition([]).issues === undefined);

  // charThreatDisposition unit: shared bidi/null/control read their policies.
  check("charThreatDisposition bidi under strip → sanitize",
        gc.charThreatDisposition({ kind: "bidi-override" }, { bidiPolicy: "strip" }) === "sanitize");
  check("charThreatDisposition null under reject → refuse",
        gc.charThreatDisposition({ kind: "null-byte" }, { nullBytePolicy: "reject" }) === "refuse");
  check("charThreatDisposition unrelated kind → null",
        gc.charThreatDisposition({ kind: "configurable" }, {}) === null);

  // compliancePostures unit: the four-posture regulation-disposition policy.
  // hipaa/pci-dss/soc2 → strict tier, gdpr → balanced tier; snippet base / ÷2 / ×2.
  var PROFILES = {
    strict:   { bidiPolicy: "reject", maxBytes: 1000 },
    balanced: { bidiPolicy: "strip",  maxBytes: 2000 },
  };
  var cp = gc.compliancePostures(PROFILES, { base: 256 });
  check("compliancePostures hipaa/pci/soc2 use the strict tier",
        cp.hipaa.bidiPolicy === "reject" && cp["pci-dss"].bidiPolicy === "reject" && cp.soc2.bidiPolicy === "reject");
  check("compliancePostures gdpr uses the balanced tier (data-minimization strips)",
        cp.gdpr.bidiPolicy === "strip" && cp.gdpr.maxBytes === 2000);
  check("compliancePostures snippet budget scales base / ÷2 / ×2",
        cp.hipaa.forensicSnippetBytes === 256 && cp["pci-dss"].forensicSnippetBytes === 256 &&
        cp.gdpr.forensicSnippetBytes === 128 && cp.soc2.forensicSnippetBytes === 512);
  check("compliancePostures every posture is frozen", Object.isFrozen(cp) && Object.isFrozen(cp.gdpr));
  var cpOv = gc.compliancePostures(PROFILES, { base: 256, overlays: { gdpr: { bidiPolicy: "audit" } } });
  check("compliancePostures overlay merges last (per-posture intended delta)",
        cpOv.gdpr.bidiPolicy === "audit" && cpOv.gdpr.maxBytes === 2000);
  var threwBase = null;
  try { gc.compliancePostures(PROFILES, { base: 7 }); } catch (e) { threwBase = e; }
  check("compliancePostures throws on a non-even base (config-time)", threwBase !== null);
  var threwProf = null;
  try { gc.compliancePostures({ strict: {} }, { base: 256 }); } catch (e) { threwProf = e; }
  check("compliancePostures throws when profiles lack strict+balanced", threwProf !== null);

  // strictDefaults unit: strict profile + enforce mode + overlay.
  var sd = gc.strictDefaults({ strict: { bidiPolicy: "reject", maxBytes: 100 } });
  check("strictDefaults = strict profile + mode:enforce",
        sd.bidiPolicy === "reject" && sd.maxBytes === 100 && sd.mode === "enforce" && Object.isFrozen(sd));
  var sdo = gc.strictDefaults({ strict: { bidiPolicy: "reject" } }, { maxRuntimeMs: 9000 });
  check("strictDefaults overlay merges last", sdo.maxRuntimeMs === 9000 && sdo.mode === "enforce");
  check("strictDefaults overlay may override mode",
        gc.strictDefaults({ strict: {} }, { mode: "audit" }).mode === "audit");
  var sdThrew = null;
  try { gc.strictDefaults({ balanced: {} }); } catch (e) { sdThrew = e; }
  check("strictDefaults throws when profiles lack strict", sdThrew !== null);

  // detectStringInput unit: the whole string-detector preamble → { done, issues }.
  var dsiBad = gc.detectStringInput(12345, {}, { name: "cidr" });
  check("detectStringInput non-string → done + typed bad-input issue",
        dsiBad.done === true && dsiBad.issues[0].kind === "bad-input" &&
        dsiBad.issues[0].ruleId === "cidr.bad-input" && dsiBad.issues[0].snippet === "cidr is not a string");
  var dsiEmpty = gc.detectStringInput("", {}, { name: "cidr" });
  check("detectStringInput empty (issue mode) → done + <name>.empty issue",
        dsiEmpty.done === true && dsiEmpty.issues[0].kind === "empty" &&
        dsiEmpty.issues[0].ruleId === "cidr.empty" && dsiEmpty.issues[0].snippet === "cidr is empty");
  var dsiOk = gc.detectStringInput("", {}, { name: "shell", emptyMode: "ok" });
  check("detectStringInput emptyMode 'ok' → done + [] (empty is legal)",
        dsiOk.done === true && JSON.stringify(dsiOk.issues) === "[]");
  check("detectStringInput emptyMode 'skip' → not done on empty (detector owns empty)",
        gc.detectStringInput("", {}, { name: "domain", emptyMode: "skip" }).done === false);
  var dsiCap = gc.detectStringInput("aaaa", {}, { name: "cidr", cap: { bytes: 2 } });
  check("detectStringInput over byte cap → done + default <name>-cap issue",
        dsiCap.done === true && dsiCap.issues[0].kind === "cidr-cap" &&
        dsiCap.issues[0].ruleId === "cidr.cidr-cap" && dsiCap.issues[0].snippet === "cidr input exceeds maxBytes 2");
  var dsiCapOv = gc.detectStringInput("aaaa", {}, { name: "jsonpath", cap: { bytes: 2, kind: "pattern-cap", snippet: "jsonpath exceeds maxPatternBytes 2" } });
  check("detectStringInput cap.kind + cap.snippet override",
        dsiCapOv.issues[0].kind === "pattern-cap" && dsiCapOv.issues[0].ruleId === "jsonpath.pattern-cap" &&
        dsiCapOv.issues[0].snippet === "jsonpath exceeds maxPatternBytes 2");
  check("detectStringInput cap.snippet function receives (byteLen, bytes)",
        gc.detectStringInput("aaaa", {}, { name: "domain", cap: { bytes: 2, snippet: function (n, m) { return "domain " + n + " octets exceeds " + m; } } }).issues[0].snippet === "domain 4 octets exceeds 2");
  var dsiCont = gc.detectStringInput("hello", {}, { name: "cidr" });
  check("detectStringInput non-empty under cap → not done + codepoint-threat array",
        dsiCont.done === false && Array.isArray(dsiCont.issues));
  check("detectStringInput scanCodepoints:false → not done + [] (guard scans later / parses its own)",
        (function () { var r = gc.detectStringInput("hello", {}, { name: "json", scanCodepoints: false }); return r.done === false && JSON.stringify(r.issues) === "[]"; })());
  check("detectStringInput cap measures BYTES not chars (multibyte over byte cap caps)",
        gc.detectStringInput("é", {}, { name: "x", cap: { bytes: 1 } }).done === true &&
        gc.detectStringInput("é", {}, { name: "x", cap: { bytes: 1 } }).issues[0].kind === "x-cap");
  check("detectStringInput noun overrides the bad-input subject",
        gc.detectStringInput(1, {}, { name: "regex", noun: "regex pattern" }).issues[0].snippet === "regex pattern is not a string");
  var dsiThrew = null;
  try { gc.detectStringInput("x", {}, {}); } catch (e) { dsiThrew = e; }
  check("detectStringInput throws on missing cfg.name (config-time)", dsiThrew !== null);

  // ---- identifierFixtures: an identifier guard's INTEGRATION_FIXTURES from
  //      one benign + one hostile sample (byte forms derived, not re-typed).
  var idfx = gc.identifierFixtures("example.com", "192.168.1.1");
  check("identifierFixtures kind is identifier", idfx.kind === "identifier");
  check("identifierFixtures keeps the benign/hostile identifier strings",
        idfx.benignIdentifier === "example.com" && idfx.hostileIdentifier === "192.168.1.1");
  check("identifierFixtures derives byte forms as utf8 Buffers",
        Buffer.isBuffer(idfx.benignBytes) && idfx.benignBytes.equals(Buffer.from("example.com", "utf8")) &&
        Buffer.isBuffer(idfx.hostileBytes) && idfx.hostileBytes.equals(Buffer.from("192.168.1.1", "utf8")));
  check("identifierFixtures result is frozen", Object.isFrozen(idfx));
  var idfxAscii = gc.identifierFixtures("EHLO x", "A\r\n.\r\nB", "ascii");
  check("identifierFixtures encoding param drives the byte form (ascii)",
        idfxAscii.benignBytes.equals(Buffer.from("EHLO x", "ascii")) &&
        idfxAscii.hostileBytes.equals(Buffer.from("A\r\n.\r\nB", "ascii")));
  var idfxThrew = function (fn) { try { fn(); return false; } catch (_e) { return true; } };
  check("identifierFixtures throws on empty benign (config-time)",
        idfxThrew(function () { gc.identifierFixtures("", "h"); }));
  check("identifierFixtures throws on non-string hostile (config-time)",
        idfxThrew(function () { gc.identifierFixtures("b", 5); }));
  check("identifierFixtures throws on unknown encoding (config-time)",
        idfxThrew(function () { gc.identifierFixtures("b", "h", "utf-99"); }));

  // ---- markup URL-scheme constants (shared by guard-html / guard-svg).
  check("DANGEROUS_URL_SCHEMES denies the script + dangerous-resource schemes",
        gc.DANGEROUS_URL_SCHEMES.indexOf("javascript") !== -1 &&
        gc.DANGEROUS_URL_SCHEMES.indexOf("ecmascript") !== -1 &&
        gc.DANGEROUS_URL_SCHEMES.indexOf("data") !== -1 &&
        gc.DANGEROUS_URL_SCHEMES.indexOf("file") !== -1);
  check("DANGEROUS_URL_SCHEMES does not contain a safe scheme",
        gc.DANGEROUS_URL_SCHEMES.indexOf("https") === -1 &&
        gc.DANGEROUS_URL_SCHEMES.indexOf("mailto") === -1);
  check("DANGEROUS_URL_SCHEMES is frozen", Object.isFrozen(gc.DANGEROUS_URL_SCHEMES));
  check("SAFE_URL_SCHEMES is the strict allowlist base [http, https, mailto, tel]",
        JSON.stringify(gc.SAFE_URL_SCHEMES) === JSON.stringify(["http", "https", "mailto", "tel"]) &&
        Object.isFrozen(gc.SAFE_URL_SCHEMES));
  check("SAFE and DANGEROUS scheme sets are disjoint",
        gc.SAFE_URL_SCHEMES.every(function (s) { return gc.DANGEROUS_URL_SCHEMES.indexOf(s) === -1; }));

  // ---- resolveProfileName: profile-precedence name resolution, no throw.
  var POST = { hipaa: "strict", gdpr: "balanced" };
  check("resolveProfileName: explicit profile wins",
        gc.resolveProfileName({ profile: "permissive", posture: "hipaa" }, POST, "strict") === "permissive");
  check("resolveProfileName: posture maps to its tier when no profile",
        gc.resolveProfileName({ posture: "gdpr" }, POST, "strict") === "balanced");
  check("resolveProfileName: falls back to the default",
        gc.resolveProfileName({}, POST, "strict") === "strict");
  check("resolveProfileName: does not validate (returns an unknown name unchanged)",
        gc.resolveProfileName({ profile: "bogus" }, POST, "strict") === "bogus");
  check("resolveProfileName: tolerates null opts",
        gc.resolveProfileName(null, POST, "strict") === "strict");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("[gate-contract-content-gate] OK — " + helpers.getChecks() + " checks passed"); })
       .catch(function (e) { console.error("FAIL:", e.stack || e); process.exit(1); });
}
