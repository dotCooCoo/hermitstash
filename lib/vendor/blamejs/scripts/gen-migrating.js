// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// scripts/gen-migrating.js — generate MIGRATING.md from deprecate() calls
// across lib/. Walks the tree, finds every `deprecate.warn|wrap|alias`
// invocation, extracts the opts literal, groups by removeIn major.
//
// Re-run before each release; the file is committed so operators can
// read the diff against the prior tag.
//
// Limitation: opts must be an object literal (the common case in this
// codebase). Calls that pass a variable as opts won't be captured —
// the script logs them with a [gen-migrating] note and the entry is
// skipped. Switch to a module-hook capture if that ever becomes the
// dominant pattern.

var fs = require("node:fs");
var path = require("node:path");

var ROOT      = path.resolve(__dirname, "..");
var LIB_DIR   = path.join(ROOT, "lib");
var TARGET    = path.join(ROOT, "MIGRATING.md");

function _walk(dir, out) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    var full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name !== "vendor") _walk(full, out);
    } else if (e.isFile() && e.name.endsWith(".js")) {
      out.push(full);
    }
  });
  return out;
}

// Find the closing brace of an object literal that starts at index i
// (where src[i] === "{"). Tracks nesting + quoted strings + escapes.
// Returns the index AFTER the closing brace, or -1 if unterminated.
function _findObjectEnd(src, i) {
  var depth = 0;
  var inStr = null;
  var esc = false;
  for (; i < src.length; i++) {
    var c = src[i];
    if (esc) { esc = false; continue; }
    if (inStr) {
      if (c === "\\") esc = true;
      else if (c === inStr) inStr = null;
      continue;
    }
    if (c === "'" || c === "\"" || c === "`") { inStr = c; continue; }
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

function _evalOpts(src) {
  try { return Function("return " + src)(); }
  catch (_e) { return null; }
}

function _extractDeprecations(src, fileLabel) {
  var out = [];

  // .warn("name", { ... })
  for (var m of src.matchAll(/(?:^|[^.\w])deprecate\.warn\s*\(\s*"([^"]+)"\s*,\s*\{/g)) {
    var braceAt = m.index + m[0].length - 1;
    var end = _findObjectEnd(src, braceAt);
    if (end < 0) continue;
    var opts = _evalOpts(src.slice(braceAt, end));
    if (!opts) {
      process.stderr.write("[gen-migrating] " + fileLabel + ": could not parse opts for deprecate.warn(\"" + m[1] + "\")\n");
      continue;
    }
    out.push({ kind: "warn", name: m[1], opts: opts });
  }

  // .wrap(<fn>, "name", { ... })
  for (var w of src.matchAll(/(?:^|[^.\w])deprecate\.wrap\s*\(/g)) {
    var startW = w.index + w[0].length;
    var nameMatchW = src.slice(startW).match(/"([^"]+)"\s*,/);
    if (!nameMatchW) continue;
    var afterNameW = startW + nameMatchW.index + nameMatchW[0].length;
    var openBraceW = src.indexOf("{", afterNameW);
    if (openBraceW < 0) continue;
    var endW = _findObjectEnd(src, openBraceW);
    if (endW < 0) continue;
    var optsW = _evalOpts(src.slice(openBraceW, endW));
    if (!optsW) {
      process.stderr.write("[gen-migrating] " + fileLabel + ": could not parse opts for deprecate.wrap(\"" + nameMatchW[1] + "\")\n");
      continue;
    }
    out.push({ kind: "wrap", name: nameMatchW[1], opts: optsW });
  }

  // .alias(<obj>, "old", "new", { ... })
  for (var a of src.matchAll(/(?:^|[^.\w])deprecate\.alias\s*\(/g)) {
    var startA = a.index + a[0].length;
    var aliasMatchA = src.slice(startA).match(/"([^"]+)"\s*,\s*"([^"]+)"\s*,/);
    if (!aliasMatchA) continue;
    var afterAliasA = startA + aliasMatchA.index + aliasMatchA[0].length;
    var openBraceA = src.indexOf("{", afterAliasA);
    if (openBraceA < 0) continue;
    var endA = _findObjectEnd(src, openBraceA);
    if (endA < 0) continue;
    var optsA = _evalOpts(src.slice(openBraceA, endA));
    if (!optsA) {
      process.stderr.write("[gen-migrating] " + fileLabel + ": could not parse opts for deprecate.alias(\"" + aliasMatchA[1] + "\")\n");
      continue;
    }
    out.push({ kind: "alias", name: aliasMatchA[1], renamedTo: aliasMatchA[2], opts: optsA });
  }

  return out;
}

function _majorOf(version) {
  var m = String(version || "").match(/^(\d+)\.(\d+)/);
  if (!m) return null;
  return Number(m[1]) === 0 ? "v0.x" : "v" + m[1] + ".x";
}

function _gather() {
  var files = _walk(LIB_DIR, []);
  var entries = [];
  files.forEach(function (f) {
    var src = fs.readFileSync(f, "utf8");
    var rel = path.relative(ROOT, f).replace(/\\/g, "/");
    _extractDeprecations(src, rel).forEach(function (d) {
      if (!d.opts.since || !d.opts.removeIn) {
        process.stderr.write("[gen-migrating] " + rel + ": " + d.kind + " call for \"" + d.name + "\" missing since/removeIn — skipped\n");
        return;
      }
      entries.push({
        name:      d.name,
        kind:      d.kind,
        since:     d.opts.since,
        removeIn:  d.opts.removeIn,
        message:   d.opts.message || null,
        hint:      d.opts.hint || null,
        renamedTo: d.renamedTo || null,
        file:      rel,
      });
    });
  });
  return entries;
}

function _build() {
  var entries = _gather();
  var byRemove = new Map();
  entries.forEach(function (e) {
    var major = _majorOf(e.removeIn);
    if (!major) return;
    if (!byRemove.has(major)) byRemove.set(major, []);
    byRemove.get(major).push(e);
  });

  var lines = [];
  lines.push("# Migrating");
  lines.push("");
  lines.push("Operator-facing migration recipes per breaking change. The bulk of this file is auto-generated from `deprecate()`-marked surface in the framework — the running app warns about each (with `BLAMEJS_DEPRECATIONS=warn` set, or by default outside production) before the noted removal version. Re-run `node scripts/gen-migrating.js` before each release; the file is committed so operators can diff it against the prior tag.");
  lines.push("");
  lines.push("**Out-of-band breaking changes** (schema breaks, config-shape changes, on-disk format breaks) cannot be expressed as `deprecate()` calls because there's no in-process runtime to warn from. They're hardcoded in the OUT_OF_BAND_BREAKS table inside `scripts/gen-migrating.js` so the operator sees the full upgrade path here without needing to grep CHANGELOG.");
  lines.push("");

  if (entries.length === 0) {
    lines.push("## No active deprecations");
    lines.push("");
    lines.push("The framework has no `deprecate()`-marked surface awaiting removal.");
    lines.push("");
    _appendOutOfBand(lines);
    return lines.join("\n");
  }

  var majors = Array.from(byRemove.keys()).sort();
  majors.forEach(function (m) {
    lines.push("## Removed in " + m);
    lines.push("");
    var rows = byRemove.get(m).slice().sort(function (a, b) {
      if (a.since !== b.since) return a.since < b.since ? -1 : 1;
      return a.name < b.name ? -1 : 1;
    });
    rows.forEach(function (e) {
      lines.push("### `" + e.name + "`");
      lines.push("");
      lines.push("- **Since:** " + e.since);
      lines.push("- **Removed in:** " + e.removeIn);
      lines.push("- **Defined at:** [`" + e.file + "`](" + e.file + ")");
      if (e.kind === "alias" && e.renamedTo) {
        lines.push("- **Renamed to:** `" + e.renamedTo + "`");
      }
      if (e.message) {
        lines.push("");
        lines.push(e.message);
      }
      if (e.hint) {
        lines.push("");
        lines.push(e.hint);
      }
      lines.push("");
    });
  });

  _appendOutOfBand(lines);
  return lines.join("\n");
}

// OUT_OF_BAND_BREAKS — schema / on-disk / config-shape breaks that
// can't be expressed via `deprecate()` because there's no in-process
// runtime surface to warn from. Append as releases ship these.
//
// Each entry:
//   release:    git tag of the release that introduced the break
//   surface:    operator-visible API or on-disk artifact affected
//   summary:    one-line operator-facing description
//   migration:  multi-line markdown migration recipe
var OUT_OF_BAND_BREAKS = [
  {
    release:  "v0.9.15",
    surface:  "b.middleware.idempotencyKey.dbStore — table schema",
    summary:  "Single `v` JSON-envelope column split into discrete `fingerprint` / `status_code` / `headers` / `body` / `expires_at` columns; `headers` + `body` are sealed via `b.cryptoField.sealRow` when vault is initialized; `k` column carries the sha3-512 namespace-hash of the operator-supplied key.",
    migration: [
      "Operators with a v0.9.14 (or earlier) idempotency table on disk:",
      "",
      "```sql",
      "DROP TABLE <tableName>;   -- default: blamejs_idempotency_keys",
      "```",
      "",
      "Or pick a fresh `tableName` in v0.9.15+ `dbStore({ tableName: \"...\" })`. The init step (`init: true`, default) creates the new split-column schema. `CREATE TABLE IF NOT EXISTS` does NOT migrate column layout on an existing table, so the drop-and-recreate is required.",
      "",
      "Cached records in the existing table are not recoverable across the schema break — operators who care about replay continuity warm the new table by retrying the in-flight requests under the new dbStore.",
    ].join("\n"),
  },
  {
    release:  "v0.15.4",
    surface:  "b.middleware.dpop — replayStore now required at mount",
    summary:  "`b.middleware.dpop` now REQUIRES a `replayStore` at mount time and throws (`auth-dpop/replay-store-required`) if it is omitted or lacks `checkAndInsert`. Previously the jti-replay check was gated behind store presence, so omitting it silently mounted a DPoP gate with NO replay defense — a captured proof could be replayed indefinitely (RFC 9449 §11.1).",
    migration: [
      "Operators mounting `b.middleware.dpop` without a `replayStore`:",
      "",
      "```js",
      "b.middleware.dpop({",
      "  replayStore: b.nonceStore.create({ backend: \"memory\" }), // shared backend on multi-process",
      "  // ...other opts",
      "});",
      "```",
      "",
      "Use a process-shared `replayStore` backend (not `\"memory\"`) on a multi-process / multi-node deployment so a proof replayed against a different worker is still caught. The low-level `b.auth.dpop.verify` primitive keeps `replayStore` optional for advanced callers that track `jti` themselves.",
    ].join("\n"),
  },
  {
    release:  "v0.15.4",
    surface:  "b.session.rotate — { req } required for a fingerprint-bound session",
    summary:  "Rotating a session created with a device fingerprint (`{ req, fingerprintFields }`) now requires the same `{ req, fingerprintFields }` at `b.session.rotate()`; a bound session rotated without `req` throws (`ROTATE_FINGERPRINT_REQ_REQUIRED`). The fingerprint is keyed to the session id, so rotation must re-key it to the new id from the live request — previously rotation left the old-id-keyed hash in place, which made the next `verify` false-drift (logging the user out under strict operators) or silently break the binding. Unbound sessions are unaffected.",
    migration: [
      "Operators who rotate fingerprint-bound sessions (login / MFA / role-change transitions):",
      "",
      "```js",
      "// Pass the same { req, fingerprintFields } used at create():",
      "await b.session.rotate(oldToken, { req, fingerprintFields: [\"clientIp\", \"userAgent\"], reason: \"mfa\" });",
      "```",
      "",
      "If you rotate a bound session from a context without the request, you must supply `req` so the binding can follow to the new session id. Sessions created WITHOUT a fingerprint need no change.",
    ].join("\n"),
  },
  {
    release:  "v0.15.6",
    surface:  "b.auth.sdJwtVc — ES256 / ES384 signatures are now JOSE raw r||s, not DER",
    summary:  "`b.auth.sdJwtVc` now signs and verifies ES256 / ES384 with `dsaEncoding: \"ieee-p1363\"` (raw r||s), the encoding JOSE / JWS and EUDI wallets require. Previously it used node:crypto's default DER ECDSA encoding, so a credential this issuer signed was rejected by conformant verifiers and the library rejected conformant holders' key-binding JWTs. The signature bytes change shape (64 bytes for ES256, 96 for ES384, no leading `0x30` SEQUENCE tag).",
    migration: [
      "No code change is needed — interop with conformant JOSE / wallet verifiers now works where it previously failed. Two things to re-check if you integrated with the OLD output:",
      "",
      "- A previously-issued ES256 / ES384 SD-JWT-VC signed by an earlier version is DER-encoded; re-issue it (signatures are not portable across the encodings). Tokens are short-lived, so this clears on the next issuance cycle.",
      "- If you pinned, cached, or asserted on the raw signature bytes of this library's ES256 / ES384 output, update the fixture — the bytes are now `ieee-p1363`. EdDSA / ML-DSA signatures are unchanged.",
    ].join("\n"),
  },
  {
    release:  "v0.15.7",
    surface:  "b.auth.oauth verifyIdToken — azp (authorized party) is now enforced",
    summary:  "verifyIdToken now applies OIDC Core 3.1.3.7: a multi-audience ID token (aud is an array with more than one entry) MUST carry an azp claim, and a present azp MUST equal the configured client_id. A token whose azp is a different client, or a multi-audience token with no azp, now throws (auth-oauth/azp-mismatch / auth-oauth/azp-required). Previously only `aud contains client_id` was checked, so a token authorized for a different party but also listing this RP verified clean.",
    migration: [
      "No change for the common single-audience ID token with no azp. If your IdP issues multi-audience ID tokens, ensure it sets azp to your client_id (it should, per the spec) — otherwise verifyIdToken will now reject them. This is a security fix; a token that fails the new check was authorized for a different client.",
    ].join("\n"),
  },
  {
    release:  "v0.15.7",
    surface:  "b.safeUrl.canonicalize — IPv4-mapped hosts fold to IPv4",
    summary:  "b.safeUrl.canonicalize / b.ssrfGuard.canonicalizeHost now fold an IPv4-mapped IPv6 host (::ffff:1.2.3.4) to its embedded IPv4 dotted form, and strip every trailing dot from a host. In 0.15.6 it canonicalized to an IPv6 string and only one trailing dot was stripped. NAT64 / 6to4 hosts stay IPv6.",
    migration: [
      "No code change is needed — this makes a dual-stack / NAT64 peer unify with a dotted-IPv4 allow/deny entry as intended. If you persisted canonical host strings produced by 0.15.6 (e.g. as cache or dedup keys) and compare them against freshly-canonicalized hosts, recompute them: an IPv4-mapped host now yields the dotted IPv4 instead of the bracketed IPv6, and a multi-trailing-dot host yields the bare name.",
    ].join("\n"),
  },
  {
    release:  "v0.15.6",
    surface:  "b.auth.oauth verifyIdToken — skipExpCheck is restricted to logout tokens",
    summary:  "`verifyIdToken`'s `skipExpCheck` option now throws (`auth-oauth/skip-exp-check-not-allowed`) on any token that is not an OIDC Back-Channel-Logout token (no `http://schemas.openid.net/event/backchannel-logout` event claim), and enforces an `iat` freshness floor on logout tokens (`auth-oauth/logout-token-stale`). Previously any caller could pass `skipExpCheck: true` to verify an expired — or replayed — ID token. The option was undocumented and only used internally by the back-channel-logout path, which is unaffected.",
    migration: [
      "No change for normal ID-token verification or for the framework's back-channel-logout handling. If you called `verifyIdToken(token, { skipExpCheck: true })` directly on a non-logout token (an undocumented use), it now throws: drop the option so expiry is validated, or verify the token through the back-channel-logout path if it really is a logout token.",
    ].join("\n"),
  },
];

function _appendOutOfBand(lines) {
  if (!OUT_OF_BAND_BREAKS.length) return;
  lines.push("---");
  lines.push("");
  lines.push("## Out-of-band breaking changes");
  lines.push("");
  lines.push("Listed newest-first.");
  lines.push("");
  // Semver-aware sort — `v0.9.10` must sort newer than `v0.9.9` (a naive
  // lexicographic compare would order the digit `1` before `9` and mis-
  // place them). Strip the leading `v`, split on `.`, compare each
  // numeric component. Per Codex P2 on PR #48.
  function _semverCmp(a, b) {
    var as = String(a).replace(/^v/, "").split(".").map(Number);
    var bs = String(b).replace(/^v/, "").split(".").map(Number);
    for (var i = 0; i < Math.max(as.length, bs.length); i += 1) {
      var ai = i < as.length ? as[i] : 0;
      var bi = i < bs.length ? bs[i] : 0;
      if (ai !== bi) return ai - bi;
    }
    return 0;
  }
  var sorted = OUT_OF_BAND_BREAKS.slice().sort(function (a, b) {
    return _semverCmp(b.release, a.release);   // newest first
  });
  sorted.forEach(function (e) {
    lines.push("### " + e.release + " — `" + e.surface + "`");
    lines.push("");
    lines.push(e.summary);
    lines.push("");
    lines.push(e.migration);
    lines.push("");
  });
}

fs.writeFileSync(TARGET, _build(), "utf8");
process.stdout.write("[gen-migrating] wrote " + TARGET + "\n");
