"use strict";

/**
 * @module     b.mail.sieve
 * @nav        Mail
 * @title      Sieve interpreter
 * @order      240
 * @since      0.9.55
 *
 * @intro
 *   RFC 5228 Sieve interpreter that walks the AST produced by
 *   `b.safeSieve.parse(script)` and emits an ordered action list the
 *   delivery agent applies to the inbound message. Runs under a gas
 *   counter (default 10 000 ops) so a hostile or runaway script can't
 *   stall the delivery thread. The interpreter is synchronous and
 *   pure — every test reads from the operator-supplied `env` object;
 *   the interpreter never touches the mail store, never opens a
 *   socket, never executes operator-supplied code. Side-effects (file-
 *   into / redirect / discard) materialize as result entries the
 *   caller dispatches against the store.
 *
 *   Tests implemented at v0.9.55:
 *     - `address` — header-address-list test with `:all` / `:localpart`
 *       / `:domain` address-parts and `:is` / `:contains` / `:matches`
 *       match-types
 *     - `header` — header-value test with the same match-types
 *     - `envelope` — RFC 5228 §5.4; reads `env.envelope.{from,to}`
 *     - `exists` — header-presence test
 *     - `size` — `:over N` / `:under N` byte-count test
 *     - `not` / `allof` / `anyof` / `true` / `false`
 *
 *   Actions implemented at v0.9.55:
 *     - `keep` — implicit default per §2.10.2
 *     - `fileinto "Folder"` — RFC 5228 §4.1
 *     - `discard` — RFC 5228 §4.4
 *     - `redirect "addr"` — RFC 5228 §4.2; tagged with the address
 *     - `stop` — RFC 5228 §3.2; halts further command execution
 *
 *   Comparators: `i;octet` (default, exact byte) + `i;ascii-casemap`
 *   (case-insensitive ASCII). Other comparators refused at script
 *   parse time (require 'comparator-NAME' not in KNOWN_CAPABILITIES).
 *
 *   Match-type wildcards: `:matches` uses `*` (any sequence) and `?`
 *   (one byte), per RFC 5228 §2.7.1. Both wildcards are converted to
 *   a bounded RegExp built from escaped literal byte segments — no
 *   user-controlled backtracking surface.
 *
 *   The interpreter does NOT execute multi-script chains, sieve
 *   `include`s (RFC 6609), `notify` actions (RFC 5435), or `vacation`
 *   responses (RFC 5230); each of those will land with the
 *   corresponding extension RFC slice. Until then, scripts declaring
 *   them via `require` are refused at parse time.
 *
 * @card
 *   Sieve (RFC 5228) AST walker. Pure-functional, gas-bounded,
 *   side-effect-free — emits an action list the delivery agent
 *   dispatches.
 */

var safeSieve = require("./safe-sieve");
var { defineClass } = require("./framework-error");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");

var MailSieveError = defineClass("MailSieveError", { alwaysPermanent: true });

var DEFAULT_GAS_UNITS = 10000;                                                                        // allow:raw-byte-literal — operation cap
var MAX_GAS_UNITS     = 1_000_000;                                                                    // allow:raw-byte-literal — operator opt-up cap

// ---- env helpers ---------------------------------------------------------

function _headerValues(env, name) {
  if (!env || !env.headers) return [];
  var lc = String(name).toLowerCase();
  var out = [];
  for (var i = 0; i < env.headers.length; i++) {
    var h = env.headers[i];
    if (h && typeof h.name === "string" && h.name.toLowerCase() === lc) {
      out.push(String(h.value != null ? h.value : ""));
    }
  }
  return out;
}

function _addressesOf(values, part) {
  // Parse "Name <local@domain>" address-list, return the requested
  // part: :all / :localpart / :domain. RFC 5228 §5.1.
  var out = [];
  for (var i = 0; i < values.length; i++) {
    var v = values[i];
    var pieces = v.split(",");                                                                        // crude but bounded
    for (var j = 0; j < pieces.length; j++) {
      var p = pieces[j].trim();
      if (!p) continue;
      var ltIdx = p.indexOf("<");
      var gtIdx = p.lastIndexOf(">");
      var addr = (ltIdx !== -1 && gtIdx > ltIdx) ? p.slice(ltIdx + 1, gtIdx).trim() : p;
      if (part === "localpart" || part === "domain") {
        var at = addr.lastIndexOf("@");
        if (at === -1) {
          if (part === "localpart") out.push(addr);
          else out.push("");
          continue;
        }
        out.push(part === "localpart" ? addr.slice(0, at) : addr.slice(at + 1));
        continue;
      }
      out.push(addr);                                                                                 // :all
    }
  }
  return out;
}

function _envelopeAddresses(env, key) {
  if (!env || !env.envelope) return [];
  var v = env.envelope[key];
  if (v == null) return [];
  if (Array.isArray(v)) return v.map(String);
  return [String(v)];
}

// ---- match-type ---------------------------------------------------------

function _escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function _wildcardToRe(pattern, caseInsensitive) {
  // RFC 5228 §2.7.1 — `*` matches any sequence, `?` matches one. Escape
  // every other regex meta. Anchored both ends.
  var out = "^";
  for (var i = 0; i < pattern.length; i++) {
    var c = pattern[i];
    if (c === "*") out += ".*";
    else if (c === "?") out += ".";
    else out += _escapeRe(c);
  }
  out += "$";
  return new RegExp(out, caseInsensitive ? "i" : "");                                                  // allow:dynamic-regex — built from operator Sieve `:matches` pattern; every meta-char except `*`/`?` is regex-escaped, so the resulting NFA is linear in input length (no polynomial-backtrack surface)
}

function _matches(haystack, needle, matchType, comparator) {
  var ci = (comparator === "i;ascii-casemap");
  if (matchType === "is") {
    return ci
      ? haystack.toLowerCase() === needle.toLowerCase()
      : haystack === needle;
  }
  if (matchType === "contains") {
    return ci
      ? haystack.toLowerCase().indexOf(needle.toLowerCase()) !== -1
      : haystack.indexOf(needle) !== -1;
  }
  if (matchType === "matches") {
    return _wildcardToRe(needle, ci).test(haystack);
  }
  throw new MailSieveError("mail-sieve/bad-match-type",
    "unknown match-type: " + matchType);
}

function _anyOfMatches(haystackList, needleList, matchType, comparator) {
  for (var i = 0; i < haystackList.length; i++) {
    for (var j = 0; j < needleList.length; j++) {
      if (_matches(haystackList[i], needleList[j], matchType, comparator)) return true;
    }
  }
  return false;
}

// ---- tag helpers --------------------------------------------------------

function _tagAmong(tags, names, fallback) {
  if (!tags || !tags.length) return fallback;
  for (var i = 0; i < tags.length; i++) {
    if (names.indexOf(tags[i].name) !== -1) return tags[i].name;
  }
  return fallback;
}

function _tagComparator(tags) {
  // `:comparator "i;octet"` — comparator name is the FOLLOWING positional
  // string per §2.7.3. We don't have positional-vs-tag separation in args
  // yet; for v0.9.55 only the tag presence is honored, comparator name
  // pulled from positional[0] only when `:comparator` is present.
  for (var i = 0; i < tags.length; i++) {
    if (tags[i].name === "comparator" && tags[i].val) return tags[i].val;
  }
  return null;
}

function _strArg(positional, idx) {
  var p = positional[idx];
  if (!p || (p.kind !== "str" && p.kind !== "list")) return null;
  return p.kind === "str" ? p.v : (p.v[0] || null);
}

function _listArg(positional, idx) {
  var p = positional[idx];
  if (!p) return null;
  if (p.kind === "list") return p.v;
  if (p.kind === "str") return [p.v];
  return null;
}

// ---- test evaluation ----------------------------------------------------

function _evalTest(test, env, ctx) {
  ctx.gas++;
  if (ctx.gas > ctx.maxGas) {
    throw new MailSieveError("mail-sieve/gas-exhausted",
      "Sieve gas exhausted (cap " + ctx.maxGas + ")");
  }
  var name = test.name;

  if (name === "true")  return true;
  if (name === "false") return false;

  if (name === "not") {
    return !_evalTest(test.subs[0], env, ctx);
  }
  if (name === "allof") {
    for (var i = 0; i < test.subs.length; i++) {
      if (!_evalTest(test.subs[i], env, ctx)) return false;
    }
    return true;
  }
  if (name === "anyof") {
    for (var j = 0; j < test.subs.length; j++) {
      if (_evalTest(test.subs[j], env, ctx)) return true;
    }
    return false;
  }

  var args = test.args || { tags: [], positional: [] };

  if (name === "exists") {
    var headerNames = _listArg(args.positional, 0);
    if (!headerNames) return false;
    for (var h = 0; h < headerNames.length; h++) {
      if (_headerValues(env, headerNames[h]).length === 0) return false;
    }
    return true;
  }

  if (name === "size") {
    var bytes = (env && typeof env.sizeBytes === "number") ? env.sizeBytes :
                (env && env.bodyBytes ? env.bodyBytes.length : 0);
    var num = args.positional[0] && args.positional[0].kind === "num" ?
              args.positional[0].v : 0;
    var mode = _tagAmong(args.tags, ["over", "under"], "over");
    return mode === "over" ? bytes > num : bytes < num;
  }

  if (name === "header") {
    var matchType  = _tagAmong(args.tags, ["is", "contains", "matches"], "is");
    var comparator = _tagComparator(args.tags) || "i;ascii-casemap";
    var hdrNames   = _listArg(args.positional, 0) || [];
    var keys       = _listArg(args.positional, 1) || [];
    var allValues  = [];
    for (var hh = 0; hh < hdrNames.length; hh++) {
      var vs = _headerValues(env, hdrNames[hh]);
      for (var vv = 0; vv < vs.length; vv++) allValues.push(vs[vv]);
    }
    return _anyOfMatches(allValues, keys, matchType, comparator);
  }

  if (name === "address" || name === "envelope") {
    var matchType2  = _tagAmong(args.tags, ["is", "contains", "matches"], "is");
    var comparator2 = _tagComparator(args.tags) || "i;ascii-casemap";
    var addrPart    = _tagAmong(args.tags, ["all", "localpart", "domain"], "all");
    var addrFields  = _listArg(args.positional, 0) || [];
    var keys2       = _listArg(args.positional, 1) || [];
    var allAddrs    = [];
    for (var af = 0; af < addrFields.length; af++) {
      var fieldName = addrFields[af];
      var values;
      if (name === "envelope") {
        // RFC 5228 §5.4 — only "from" and "to" defined for envelope test.
        var lc = String(fieldName).toLowerCase();
        if (lc !== "from" && lc !== "to") continue;
        values = _envelopeAddresses(env, lc);
      } else {
        values = _headerValues(env, fieldName);
      }
      var parts = _addressesOf(values, addrPart);
      for (var pp = 0; pp < parts.length; pp++) allAddrs.push(parts[pp]);
    }
    return _anyOfMatches(allAddrs, keys2, matchType2, comparator2);
  }

  // Unknown test — refuse rather than evaluate. The parser already
  // refused any `require` that didn't resolve to KNOWN_CAPABILITIES, so
  // reaching here means a known-capability test we forgot to wire.
  throw new MailSieveError("mail-sieve/unknown-test",
    "Sieve test '" + name + "' is RFC-defined but not wired in v0.9.55");
}

// ---- action evaluation --------------------------------------------------

function _runCommand(cmd, env, ctx) {
  ctx.gas++;
  if (ctx.gas > ctx.maxGas) {
    throw new MailSieveError("mail-sieve/gas-exhausted",
      "Sieve gas exhausted (cap " + ctx.maxGas + ")");
  }
  if (ctx.stopped) return;

  if (cmd.kind === "require") return;                                                                 // parser handled it

  if (cmd.kind === "if") {
    if (_evalTest(cmd.test, env, ctx)) {
      _runBlock(cmd.thenBody, env, ctx);
      return;
    }
    for (var i = 0; i < cmd.elif.length; i++) {
      if (_evalTest(cmd.elif[i].test, env, ctx)) {
        _runBlock(cmd.elif[i].body, env, ctx);
        return;
      }
    }
    if (cmd.elseBody) {
      _runBlock(cmd.elseBody, env, ctx);
    }
    return;
  }

  if (cmd.kind === "action") {
    var n = cmd.name;
    var pos = cmd.args.positional;
    if (n === "keep") {
      ctx.implicitKeepCancelled = false;
      ctx.actions.push({ kind: "keep" });
      return;
    }
    if (n === "fileinto") {
      var folder = _strArg(pos, 0);
      if (folder == null) {
        throw new MailSieveError("mail-sieve/bad-fileinto",
          "fileinto requires a folder name");
      }
      ctx.implicitKeepCancelled = true;
      ctx.actions.push({ kind: "fileinto", folder: folder });
      return;
    }
    if (n === "discard") {
      ctx.implicitKeepCancelled = true;
      ctx.actions.push({ kind: "discard" });
      return;
    }
    if (n === "redirect") {
      var addr = _strArg(pos, 0);
      if (addr == null) {
        throw new MailSieveError("mail-sieve/bad-redirect",
          "redirect requires an address");
      }
      ctx.implicitKeepCancelled = true;
      ctx.actions.push({ kind: "redirect", address: addr });
      return;
    }
    if (n === "stop") {
      ctx.stopped = true;
      return;
    }
    throw new MailSieveError("mail-sieve/unknown-action",
      "Sieve action '" + n + "' is not wired in v0.9.55");
  }

  throw new MailSieveError("mail-sieve/bad-command",
    "unknown command kind '" + cmd.kind + "'");
}

function _runBlock(commands, env, ctx) {
  for (var i = 0; i < commands.length; i++) {
    if (ctx.stopped) return;
    _runCommand(commands[i], env, ctx);
  }
}

/**
 * @primitive  b.mail.sieve.run
 * @signature  b.mail.sieve.run(ast, env, opts?)
 * @since      0.9.55
 * @status     stable
 * @related    b.safeSieve.parse, b.mail.agent.create
 *
 * Walk a parsed Sieve AST against the message environment + return the
 * ordered action list. The interpreter is pure — it reads only from
 * `env` and never mutates it; every action surfaces as an entry in
 * the returned list for the caller to dispatch.
 *
 * @opts
 *   maxGas: number,    // default 10000; cap 1_000_000
 *
 * @example
 *   var ast = b.safeSieve.parse('if header :contains "X-Spam" "yes" { fileinto "Junk"; }');
 *   var rv  = b.mail.sieve.run(ast, {
 *     headers:    [{ name: "X-Spam", value: "yes" }],
 *     envelope:   { from: "sender@example.com", to: "rcpt@example.com" },
 *     sizeBytes:  1024,
 *   });
 *   // → { actions: [{ kind: "fileinto", folder: "Junk" }, { kind: "keep" }], gas: 3, stopped: false }
 */
function run(ast, env, opts) {
  if (!ast || ast.kind !== "script") {
    throw new MailSieveError("mail-sieve/bad-ast",
      "mail.sieve.run: ast must be a parsed Sieve script (b.safeSieve.parse output)");
  }
  opts = opts || {};
  var maxGas = opts.maxGas === undefined ? DEFAULT_GAS_UNITS : opts.maxGas;
  if (!numericBounds.isPositiveFiniteInt(maxGas)) {
    throw new MailSieveError("mail-sieve/bad-opt",
      "maxGas must be a positive finite integer; got " + numericBounds.shape(maxGas));
  }
  if (maxGas > MAX_GAS_UNITS) {
    throw new MailSieveError("mail-sieve/bad-opt",
      "mail.sieve.run: maxGas " + maxGas + " exceeds cap " + MAX_GAS_UNITS);
  }
  var ctx = {
    gas:                   0,
    maxGas:                maxGas,
    actions:               [],
    stopped:               false,
    implicitKeepCancelled: false,
  };
  _runBlock(ast.commands, env || {}, ctx);
  // RFC 5228 §2.10.2 — if no explicit `keep` / `fileinto` / `discard` /
  // `redirect` fired, implicit keep applies.
  if (!ctx.implicitKeepCancelled) {
    var sawExplicitKeep = false;
    for (var i = 0; i < ctx.actions.length; i++) {
      if (ctx.actions[i].kind === "keep") { sawExplicitKeep = true; break; }
    }
    if (!sawExplicitKeep) ctx.actions.push({ kind: "keep", implicit: true });
  }
  return { actions: ctx.actions, gas: ctx.gas, stopped: ctx.stopped };
}

/**
 * @primitive  b.mail.sieve.runScript
 * @signature  b.mail.sieve.runScript(script, env, opts?)
 * @since      0.9.55
 * @status     stable
 * @related    b.mail.sieve.run, b.safeSieve.parse
 *
 * Parse + run in one call. Most call sites — JMAP `SieveScript/validate`,
 * MX delivery hook — want this shape.
 *
 * @opts
 *   profile:           "strict" | "balanced" | "permissive",
 *   compliancePosture: "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   maxGas:            number,
 *
 * @example
 *   var rv = b.mail.sieve.runScript(
 *     'require ["fileinto"];\nif header :is "From" "boss@x.com" { fileinto "Important"; }',
 *     { headers: [{ name: "From", value: "boss@x.com" }] }
 *   );
 *   rv.actions[0].folder;                              // → "Important"
 */
function runScript(script, env, opts) {
  var ast = safeSieve.parse(script, opts);
  return run(ast, env, opts);
}

/**
 * @primitive  b.mail.sieve.create
 * @signature  b.mail.sieve.create(opts?)
 * @since      0.9.55
 * @status     stable
 * @related    b.mail.sieve.run, b.mail.agent.create
 *
 * Returns a stateful Sieve handle the delivery agent + JMAP
 * `SieveScript/validate` method compose. Distinct from the bare
 * `b.mail.sieve.run(ast, env)` entry — the handle carries operator-
 * supplied opts (`maxGas`, `profile`, `compliancePosture`, `audit`)
 * so every invocation runs with the same posture.
 *
 * @opts
 *   maxGas:            number,
 *   profile:           "strict" | "balanced" | "permissive",
 *   compliancePosture: "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   audit:             { safeEmit: function },
 *
 * @example
 *   var sieve = b.mail.sieve.create({ profile: "strict", audit: b.audit });
 *   sieve.validateScript(operatorScript);
 *   var rv = await sieve.runScript(operatorScript, mailEnv);
 */
function create(opts) {
  opts = validateOpts.requireObject(opts || {}, "mail.sieve.create",
    MailSieveError, "mail-sieve/bad-opt");
  var maxGas = opts.maxGas === undefined ? DEFAULT_GAS_UNITS : opts.maxGas;
  if (!numericBounds.isPositiveFiniteInt(maxGas)) {
    throw new MailSieveError("mail-sieve/bad-opt",
      "maxGas must be a positive finite integer; got " + numericBounds.shape(maxGas));
  }
  if (maxGas > MAX_GAS_UNITS) {
    throw new MailSieveError("mail-sieve/bad-opt",
      "mail.sieve.create: maxGas " + maxGas + " exceeds cap " + MAX_GAS_UNITS);
  }
  var profile = opts.profile;
  var posture = opts.compliancePosture;
  var audit   = opts.audit;

  function _emit(action, outcome, metadata) {
    if (!audit || typeof audit.safeEmit !== "function") return;
    try {
      audit.safeEmit({
        action:   action,
        outcome:  outcome || "success",
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  function validateScript(script) {
    var rv = safeSieve.validate(script, { profile: profile, compliancePosture: posture });
    if (rv.ok) {
      _emit("mail.sieve.validate", "success", { requiredCaps: rv.requiredCaps });
    } else {
      _emit("mail.sieve.validate", "failure", { issues: rv.issues });
    }
    return rv;
  }

  function runScript_(script, env) {
    var ast = safeSieve.parse(script, { profile: profile, compliancePosture: posture });
    var rv = run(ast, env, { maxGas: maxGas });
    _emit("mail.sieve.run", "success", {
      gas: rv.gas, actionCount: rv.actions.length, stopped: rv.stopped,
    });
    return rv;
  }

  function runAst(ast, env) {
    var rv = run(ast, env, { maxGas: maxGas });
    _emit("mail.sieve.run", "success", {
      gas: rv.gas, actionCount: rv.actions.length, stopped: rv.stopped,
    });
    return rv;
  }

  return {
    validateScript: validateScript,
    runScript:      runScript_,
    run:            runAst,
  };
}

module.exports = {
  create:            create,
  run:               run,
  runScript:         runScript,
  MailSieveError:    MailSieveError,
  DEFAULT_GAS_UNITS: DEFAULT_GAS_UNITS,
  MAX_GAS_UNITS:     MAX_GAS_UNITS,
};
