// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     b.safeSieve
 * @nav        Mail
 * @title      Sieve parser
 * @order      230
 * @since      0.9.55
 *
 * @intro
 *   Bounded RFC 5228 Sieve parser. Produces an AST that
 *   `b.mail.sieve.run` walks at delivery time + at `agent.sieve.put`
 *   pre-validation. Caps script bytes / nesting depth / string-list
 *   length / per-string bytes per profile so a hostile script can't
 *   exhaust the parser. Refuses C0 / DEL / NUL controls outside
 *   string literals, refuses bare LF / bare CR (Sieve uses CRLF line
 *   terminators per RFC 5228 §2.1), and refuses oversized scripts at
 *   the byte level before tokenization.
 *
 *   Grammar coverage:
 *     - `require ["module" ...]`
 *     - control: `if` / `elsif` / `else` with block-body
 *     - tests: `address` / `header` / `exists` / `size` / `envelope`
 *       (when `envelope` capability declared), plus `not` / `allof` /
 *       `anyof` / `true` / `false`
 *     - actions: `keep` / `fileinto` / `discard` / `redirect` / `stop`
 *     - match-types: `:is` (default) / `:contains` / `:matches`
 *     - comparators: `i;octet` (default) / `i;ascii-casemap`
 *     - address-parts: `:all` (default) / `:localpart` / `:domain`
 *     - string lists, quoted strings (`"..."` with backslash escapes),
 *       multi-line strings (`text:\r\n...\r\n.\r\n`)
 *     - comments: `#` line and `/* block * /`
 *
 *   Extensions deferred (RFC 5229 variables, 5230 vacation, 5231
 *   relational, 5232 imap4flags, 5233 subaddress, 5235 spamtest /
 *   virustest, 5260 date / index, 5293 editheader, 5429 reject /
 *   extlists, 5435 enotify, 5703 mime / replace / enclose /
 *   extracttext, 6009 ihave, 6131 mailboxid, 6134 extlists, 6558
 *   mailbox, 6609 include, 6785 imapsieve, 8580 fcc) — refused at
 *   `require` time so scripts depending on them fail fast rather than
 *   silently mis-execute. The framework will light these incrementally
 *   as the operator-roadmap calls for them; until then, ship the base
 *   grammar that covers ~80% of operator-written scripts.
 *
 * @card
 *   Bounded Sieve (RFC 5228) parser. Produces an AST the interpreter
 *   walks under a gas counter; the 17 extension RFCs are refused at
 *   `require` time until each lights up.
 */

var { defineClass } = require("./framework-error");
var gateContract = require("./gate-contract");

var SafeSieveError = defineClass("SafeSieveError", { alwaysPermanent: true });

var DEFAULTS = Object.freeze({
  maxScriptBytes:     65536,
  maxDepth:           32,
  maxIfChainLen:      32,
  maxStringListLen:   256,
  maxStringBytes:     4096,
  maxArgsPerCmd:      32,
  maxRequiredCaps:    32,
});

var PROFILES = Object.freeze({
  strict:     Object.assign({}, DEFAULTS),
  balanced:   Object.assign({}, DEFAULTS, {
    maxScriptBytes:  262144,
    maxDepth:        64,
    maxIfChainLen:   64,
    maxStringListLen: 1024,
    maxStringBytes:  16384,
    maxArgsPerCmd:   64,
  }),
  permissive: Object.assign({}, DEFAULTS, {
    maxScriptBytes:  1048576,
    maxDepth:        128,
    maxIfChainLen:   128,
    maxStringListLen: 4096,
    maxStringBytes:  65536,
    maxArgsPerCmd:   128,
  }),
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var KNOWN_CAPABILITIES = Object.freeze({
  "fileinto":     true,
  "envelope":     true,
  "encoded-character": true,
  "comparator-i;octet":         true,
  "comparator-i;ascii-casemap": true,
  "variables":    false,
  "vacation":     false,
  "relational":   false,
  "imap4flags":   false,
  "subaddress":   false,
  "spamtest":     false,
  "virustest":    false,
  "date":         false,
  "index":        false,
  "editheader":   false,
  "reject":       false,
  "ereject":      false,
  "enotify":      false,
  "mime":         false,
  "replace":      false,
  "enclose":      false,
  "extracttext":  false,
  "ihave":        false,
  "mailboxid":    false,
  "extlists":     false,
  "mailbox":      false,
  "include":      false,
  "imapsieve":    false,
  "fcc":          false,                                                                              // RFC 8580 // allow:raw-time-literal — RFC number, not time
});

function _resolveProfile(opts) {
  if (!opts) return "strict";
  if (typeof opts.profile === "string") return opts.profile;
  if (typeof opts.compliancePosture === "string") {
    return (Object.prototype.hasOwnProperty.call(COMPLIANCE_POSTURES, opts.compliancePosture) && COMPLIANCE_POSTURES[opts.compliancePosture]) || "strict";
  }
  return "strict";
}

function _resolveCaps(opts) {
  var name = _resolveProfile(opts);
  var caps = PROFILES[name];
  if (!caps) {
    throw new SafeSieveError("safe-sieve/bad-profile",
      "safeSieve: unknown profile '" + name + "' (expected strict|balanced|permissive)");
  }
  return caps;
}

function _isIdStart(c) {
  return (c >= 0x41 && c <= 0x5A) ||
         (c >= 0x61 && c <= 0x7A) ||
         c === 0x5F;
}
function _isIdCont(c) {
  return _isIdStart(c) ||
         (c >= 0x30 && c <= 0x39) ||
         c === 0x2D;
}
function _isDigit(c) { return c >= 0x30 && c <= 0x39; }

function _tokenize(script, caps) {
  var tokens = [];
  var i = 0;
  var n = script.length;
  var line = 1;
  var col = 1;

  function _error(msg, atI) {
    var l = line, c = col;
    if (atI !== undefined && atI !== i) {
      l = 1; c = 1;
      for (var k = 0; k < atI && k < n; k++) {
        if (script.charCodeAt(k) === 0x0A) { l++; c = 1; } else { c++; }
      }
    }
    throw new SafeSieveError("safe-sieve/parse-error",
      "safeSieve.parse: " + msg + " at line " + l + ":" + c);
  }

  function _advance(ch) {
    if (ch === 0x0A) { line++; col = 1; } else { col++; }
    i++;
  }

  while (i < n) {
    var c = script.charCodeAt(i);

    if (c === 0x20 || c === 0x09) { _advance(c); continue; }
    if (c === 0x0D) {
      if (i + 1 < n && script.charCodeAt(i + 1) === 0x0A) {
        i += 2; line++; col = 1; continue;
      }
      _error("bare CR (RFC 5228 §2.1 requires CRLF)");
    }
    if (c === 0x0A) { _advance(c); continue; }

    if (c < 0x20 && c !== 0x09 && c !== 0x0A && c !== 0x0D) {
      _error("control byte 0x" + c.toString(16) + " refused outside string literal");
    }
    if (c === 0x7F) _error("DEL byte refused outside string literal");

    if (c === 0x23) {
      while (i < n && script.charCodeAt(i) !== 0x0A) _advance(script.charCodeAt(i));
      continue;
    }
    if (c === 0x2F && i + 1 < n && script.charCodeAt(i + 1) === 0x2A) {
      i += 2; col += 2;
      while (i + 1 < n && !(script.charCodeAt(i) === 0x2A && script.charCodeAt(i + 1) === 0x2F)) {
        _advance(script.charCodeAt(i));
      }
      if (i + 1 >= n) _error("unterminated block comment");
      i += 2; col += 2;
      continue;
    }

    if (c === 0x7B) { tokens.push({ k: "lbr", line: line, col: col }); _advance(c); continue; }
    if (c === 0x7D) { tokens.push({ k: "rbr", line: line, col: col }); _advance(c); continue; }
    if (c === 0x5B) { tokens.push({ k: "lsb", line: line, col: col }); _advance(c); continue; }
    if (c === 0x5D) { tokens.push({ k: "rsb", line: line, col: col }); _advance(c); continue; }
    if (c === 0x28) { tokens.push({ k: "lp",  line: line, col: col }); _advance(c); continue; }
    if (c === 0x29) { tokens.push({ k: "rp",  line: line, col: col }); _advance(c); continue; }
    if (c === 0x2C) { tokens.push({ k: "comma", line: line, col: col }); _advance(c); continue; }
    if (c === 0x3B) { tokens.push({ k: "semi",  line: line, col: col }); _advance(c); continue; }

    if (c === 0x3A) {
      _advance(c);
      if (i >= n || !_isIdStart(script.charCodeAt(i))) _error("`:` not followed by identifier");
      var tagStart = i;
      while (i < n && _isIdCont(script.charCodeAt(i))) _advance(script.charCodeAt(i));
      tokens.push({ k: "tag", v: script.slice(tagStart, i), line: line, col: col });
      continue;
    }

    if (_isDigit(c)) {
      var nStart = i;
      while (i < n && _isDigit(script.charCodeAt(i))) _advance(script.charCodeAt(i));
      var num = parseInt(script.slice(nStart, i), 10);
      if (i < n) {
        var suf = script.charCodeAt(i);
        if (suf === 0x4B || suf === 0x6B) { num *= 1024; _advance(suf); }
        else if (suf === 0x4D || suf === 0x6D) { num *= 1024 * 1024; _advance(suf); }                 // allow:raw-byte-literal — M
        else if (suf === 0x47 || suf === 0x67) { num *= 1024 * 1024 * 1024; _advance(suf); }          // allow:raw-byte-literal — G
      }
      if (!Number.isFinite(num)) _error("number overflowed");
      tokens.push({ k: "num", v: num, line: line, col: col });
      continue;
    }

    if (_isIdStart(c)) {
      var idStart = i;
      while (i < n && _isIdCont(script.charCodeAt(i))) _advance(script.charCodeAt(i));
      var id = script.slice(idStart, i);
      if (id === "text" && i < n && script.charCodeAt(i) === 0x3A) {
        _advance(0x3A);
        if (i < n && script.charCodeAt(i) === 0x23) {
          while (i < n && script.charCodeAt(i) !== 0x0A) _advance(script.charCodeAt(i));
        }
        if (i + 1 >= n || script.charCodeAt(i) !== 0x0D || script.charCodeAt(i + 1) !== 0x0A) {
          _error("`text:` must be followed by CRLF");
        }
        i += 2; line++; col = 1;
        var bodyStart = i;
        while (i + 2 < n) {
          if (script.charCodeAt(i) === 0x0D &&
              script.charCodeAt(i + 1) === 0x0A &&
              script.charCodeAt(i + 2) === 0x2E &&
              i + 4 < n &&
              script.charCodeAt(i + 3) === 0x0D &&
              script.charCodeAt(i + 4) === 0x0A) {
            break;
          }
          if (script.charCodeAt(i) === 0x0A) { line++; col = 1; }
          i++;
        }
        if (i + 4 >= n) _error("unterminated multi-line string (missing CRLF.CRLF)");
        var raw = script.slice(bodyStart, i);
        i += 5; line++; col = 1;
        var body = raw.split("\r\n..").join("\r\n.");
        if (Buffer.byteLength(body, "utf8") > caps.maxStringBytes) {
          _error("multi-line string " + Buffer.byteLength(body, "utf8") +
                 " bytes exceeds maxStringBytes=" + caps.maxStringBytes);
        }
        tokens.push({ k: "str", v: body, line: line, col: col });
        continue;
      }
      tokens.push({ k: "id", v: id, line: line, col: col });
      continue;
    }

    if (c === 0x22) {
      _advance(c);
      var sStart = i;
      var out = "";
      while (i < n) {
        var ch = script.charCodeAt(i);
        if (ch === 0x22) {
          var lit = out + script.slice(sStart, i);
          _advance(ch);
          if (Buffer.byteLength(lit, "utf8") > caps.maxStringBytes) {
            _error("string literal " + Buffer.byteLength(lit, "utf8") +
                   " bytes exceeds maxStringBytes=" + caps.maxStringBytes);
          }
          tokens.push({ k: "str", v: lit, line: line, col: col });
          break;
        }
        if (ch === 0x5C) {
          out += script.slice(sStart, i);
          _advance(ch);
          if (i >= n) _error("unterminated string escape");
          var esc = script.charCodeAt(i);
          if (esc === 0x22) { out += '"'; _advance(esc); }
          else if (esc === 0x5C) { out += "\\"; _advance(esc); }
          else { out += "\\" + script[i]; _advance(esc); }
          sStart = i;
          continue;
        }
        if (ch === 0x00) _error("NUL byte inside string literal");
        if (ch === 0x0A) { line++; col = 1; }
        _advance(ch);
      }
      if (i > n) _error("unterminated string literal");
      continue;
    }

    _error("unexpected byte 0x" + c.toString(16));
  }

  tokens.push({ k: "eof", line: line, col: col });
  return tokens;
}

function _parseScript(tokens, caps, requiredCaps) {
  var pos = 0;
  var depth = 0;

  function peek(ahead) { return tokens[pos + (ahead || 0)]; }
  function consume(kind) {
    var t = tokens[pos];
    if (t.k !== kind) {
      throw new SafeSieveError("safe-sieve/parse-error",
        "safeSieve.parse: expected " + kind + " but got " + t.k +
        (t.v ? " '" + t.v + "'" : "") + " at line " + t.line + ":" + t.col);
    }
    pos++;
    return t;
  }
  function match(kind, v) {
    var t = tokens[pos];
    if (!t || t.k !== kind) return false;
    if (v !== undefined && t.v !== v) return false;
    return true;
  }

  function _parseStringList() {
    if (match("str")) {
      var t = consume("str");
      return [t.v];
    }
    consume("lsb");
    var out = [];
    if (!match("rsb")) {
      out.push(consume("str").v);
      while (match("comma")) {
        consume("comma");
        if (out.length >= caps.maxStringListLen) {
          throw new SafeSieveError("safe-sieve/parse-error",
            "safeSieve.parse: string list exceeds maxStringListLen=" + caps.maxStringListLen);
        }
        out.push(consume("str").v);
      }
    }
    consume("rsb");
    return out;
  }

  function _parseArgs() {
    var tags = [];
    var positional = [];
    var argCount = 0;
    while (true) {
      var t = peek();
      if (argCount++ > caps.maxArgsPerCmd) {
        throw new SafeSieveError("safe-sieve/parse-error",
          "safeSieve.parse: too many args (cap " + caps.maxArgsPerCmd + ")");
      }
      if (t.k === "tag") {
        consume("tag");
        if (t.v === "comparator") {
          var cv = peek();
          if (cv.k !== "str") {
            throw new SafeSieveError("safe-sieve/parse-error",
              "safeSieve.parse: :comparator must be followed by a comparator-name string");
          }
          consume("str");
          var compCap = "comparator-" + cv.v;
          if (!Object.prototype.hasOwnProperty.call(KNOWN_CAPABILITIES, compCap)) {
            throw new SafeSieveError("safe-sieve/unknown-capability",
              "safeSieve.parse: unknown comparator \"" + cv.v + "\"");
          }
          if (KNOWN_CAPABILITIES[compCap] === false) {
            throw new SafeSieveError("safe-sieve/unimplemented-capability",
              "safeSieve.parse: unimplemented comparator \"" + cv.v + "\"");
          }
          tags.push({ name: t.v, val: cv.v });
        } else {
          tags.push({ name: t.v });
        }
        continue;
      }
      if (t.k === "num") {
        consume("num");
        positional.push({ kind: "num", v: t.v });
        continue;
      }
      if (t.k === "str") {
        consume("str");
        positional.push({ kind: "str", v: t.v });
        continue;
      }
      if (t.k === "lsb") {
        var list = _parseStringList();
        positional.push({ kind: "list", v: list });
        continue;
      }
      break;
    }
    return { tags: tags, positional: positional };
  }

  function _parseTest() {
    var t = consume("id");
    var name = t.v;
    if (name === "anyof" || name === "allof") {
      consume("lp");
      var subs = [_parseTest()];
      while (match("comma")) {
        consume("comma");
        if (subs.length >= caps.maxArgsPerCmd) {
          throw new SafeSieveError("safe-sieve/parse-error",
            "safeSieve.parse: too many sub-tests in " + name);
        }
        subs.push(_parseTest());
      }
      consume("rp");
      return { kind: "test", name: name, subs: subs };
    }
    if (name === "not") {
      var inner = _parseTest();
      return { kind: "test", name: "not", subs: [inner] };
    }
    if (name === "true" || name === "false") {
      return { kind: "test", name: name };
    }
    var args = _parseArgs();
    return { kind: "test", name: name, args: args };
  }

  function _parseBlock() {
    consume("lbr");
    depth++;
    if (depth > caps.maxDepth) {
      throw new SafeSieveError("safe-sieve/parse-error",
        "safeSieve.parse: block nesting exceeds maxDepth=" + caps.maxDepth);
    }
    var cmds = [];
    while (!match("rbr") && !match("eof")) {
      cmds.push(_parseCommand());
    }
    consume("rbr");
    depth--;
    return cmds;
  }

  function _parseCommand() {
    var t = consume("id");
    var name = t.v;

    if (name === "require") {
      var caps2 = _parseStringList();
      consume("semi");
      if (caps2.length + requiredCaps.length > caps.maxRequiredCaps) {
        throw new SafeSieveError("safe-sieve/parse-error",
          "safeSieve.parse: too many required capabilities (cap " +
          caps.maxRequiredCaps + ")");
      }
      for (var i = 0; i < caps2.length; i++) {
        var capName = caps2[i];
        if (!Object.prototype.hasOwnProperty.call(KNOWN_CAPABILITIES, capName)) {
          throw new SafeSieveError("safe-sieve/unknown-capability",
            "safeSieve.parse: unknown capability '" + capName + "' at require");
        }
        if (KNOWN_CAPABILITIES[capName] === false) {
          throw new SafeSieveError("safe-sieve/unimplemented-capability",
            "safeSieve.parse: capability '" + capName + "' is RFC-defined but " +
            "not implemented in v0.9.55 — script refused per RFC 5228 §3.2");
        }
        requiredCaps.push(capName);
      }
      return { kind: "require", caps: caps2 };
    }

    if (name === "if") {
      var test = _parseTest();
      var thenBlock = _parseBlock();
      var elif = [];
      var elseBlock = null;
      while (match("id", "elsif")) {
        if (elif.length >= caps.maxIfChainLen) {
          throw new SafeSieveError("safe-sieve/parse-error",
            "safeSieve.parse: elsif chain exceeds maxIfChainLen=" + caps.maxIfChainLen);
        }
        consume("id");
        var elifTest = _parseTest();
        var elifBlock = _parseBlock();
        elif.push({ test: elifTest, body: elifBlock });
      }
      if (match("id", "else")) {
        consume("id");
        elseBlock = _parseBlock();
      }
      return { kind: "if", test: test, thenBody: thenBlock, elif: elif, elseBody: elseBlock };
    }

    var args = _parseArgs();
    consume("semi");
    return { kind: "action", name: name, args: args };
  }

  var commands = [];
  while (!match("eof")) {
    commands.push(_parseCommand());
  }
  return { kind: "script", commands: commands, requiredCaps: requiredCaps.slice() };
}

/**
 * @primitive  b.safeSieve.parse
 * @signature  b.safeSieve.parse(script, opts?)
 * @since      0.9.55
 * @status     stable
 * @related    b.safeSieve.validate, b.mail.sieve.run, b.guardMailSieve.validate
 *
 * Parse a Sieve script (RFC 5228) and return an AST. Refuses oversized
 * scripts, control bytes, unknown capabilities, and RFC-defined-but-
 * not-implemented capabilities at `require` time. The returned AST is
 * the input to `b.mail.sieve.run(ast, env)`.
 *
 * @opts
 *   profile:           "strict" | "balanced" | "permissive",
 *   compliancePosture: "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   var ast = b.safeSieve.parse('require ["fileinto"];\r\n' +
 *     'if header :contains "Subject" "[bug]" {\r\n' +
 *     '  fileinto "bugs";\r\n' +
 *     '}\r\n');
 *   // → { kind: "script", commands: [...], requiredCaps: ["fileinto"] }
 */
function parse(script, opts) {
  if (typeof script !== "string") {
    throw new SafeSieveError("safe-sieve/bad-input",
      "safeSieve.parse: script must be a string");
  }
  var caps = _resolveCaps(opts);
  var byteLen = Buffer.byteLength(script, "utf8");
  if (byteLen > caps.maxScriptBytes) {
    throw new SafeSieveError("safe-sieve/script-too-large",
      "safeSieve.parse: script " + byteLen + " bytes exceeds maxScriptBytes=" +
      caps.maxScriptBytes);
  }
  var norm = script;
  if (script.indexOf("\r") === -1) {
    norm = script.split("\n").join("\r\n");
  }
  var tokens = _tokenize(norm, caps);
  var requiredCaps = [];
  return _parseScript(tokens, caps, requiredCaps);
}

/**
 * @primitive  b.safeSieve.validate
 * @signature  b.safeSieve.validate(script, opts?)
 * @since      0.9.55
 * @status     stable
 * @related    b.safeSieve.parse
 *
 * Parse-only validation — returns `{ ok, requiredCaps, issues }`
 * shape mirroring the rest of the guard family. Operator-facing
 * primitives that want a JMAP-style `SieveScript/validate` response
 * (RFC 9661 — JMAP for Sieve Scripts) compose this and surface `issues` directly.
 *
 * @opts
 *   profile:           "strict" | "balanced" | "permissive",
 *   compliancePosture: "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   var v = b.safeSieve.validate('require ["fileinto"];\r\nkeep;\r\n');
 *   v.ok;                                              // → true
 *   v.requiredCaps;                                    // → ["fileinto"]
 */
function validate(script, opts) {
  try {
    var ast = parse(script, opts);
    return { ok: true, requiredCaps: ast.requiredCaps, issues: [] };
  } catch (e) {
    return {
      ok: false,
      requiredCaps: [],
      issues: [{
        kind:     "parse-error",
        severity: "high",
        ruleId:   e.code || "safe-sieve/parse-error",
        snippet:  e.message,
      }],
    };
  }
}

module.exports = gateContract.defineParser({
  name:       "sieve",
  entry:      parse,
  entryName:  "parse",
  errorClass: SafeSieveError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    validate:           validate,
    KNOWN_CAPABILITIES: KNOWN_CAPABILITIES,
    _tokenize:          _tokenize,
    _resolveCaps:       _resolveCaps,
  },
});
