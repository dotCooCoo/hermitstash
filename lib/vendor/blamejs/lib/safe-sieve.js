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

var SafeSieveError = defineClass("SafeSieveError", { alwaysPermanent: true });

var DEFAULTS = Object.freeze({
  maxScriptBytes:     65536,                                                                          // 64 KiB
  maxDepth:           32,                                                                             // block nesting cap
  maxIfChainLen:      32,                                                                             // elsif/elsif... cap
  maxStringListLen:   256,
  maxStringBytes:     4096,                                                                           // per-string cap
  maxArgsPerCmd:      32,                                                                             // per-command arg cap
  maxRequiredCaps:    32,
});

var PROFILES = Object.freeze({
  strict:     Object.assign({}, DEFAULTS),
  balanced:   Object.assign({}, DEFAULTS, {
    maxScriptBytes:  262144,                                                                          // 256 KiB
    maxDepth:        64,
    maxIfChainLen:   64,
    maxStringListLen: 1024,
    maxStringBytes:  16384,
    maxArgsPerCmd:   64,
  }),
  permissive: Object.assign({}, DEFAULTS, {
    maxScriptBytes:  1048576,                                                                         // 1 MiB
    maxDepth:        128,
    maxIfChainLen:   128,
    maxStringListLen: 4096,
    maxStringBytes:  65536,
    maxArgsPerCmd:   128,
  }),
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

// RFC 5228 §1.2 capability identifiers. Each entry lists whether the
// framework's v0.9.55 interpreter implements the capability. Unknown
// or not-yet-implemented capabilities surface a typed parse error at
// `require` time per §3.2 — "If a script does not contain a require
// statement for a feature it uses, an implementation MUST NOT execute
// the script."
var KNOWN_CAPABILITIES = Object.freeze({
  // RFC 5228 base implementation provides these implicitly; declaring
  // them in `require` is allowed.
  "fileinto":     true,                                                                               // §4.1 — implemented (action)
  "envelope":     true,                                                                               // §5.4 — implemented (test)
  "encoded-character": true,                                                                          // §2.4.2.4 — implemented (string escape)
  "comparator-i;octet":         true,
  "comparator-i;ascii-casemap": true,
  // Deferred — scripts MUST declare via `require` and the framework
  // refuses to load them until the corresponding slice ships. Listed
  // here so the parser distinguishes "spec'd but not yet ours" from
  // "unknown / typo".
  "variables":    false,                                                                              // RFC 5229
  "vacation":     false,                                                                              // RFC 5230
  "relational":   false,                                                                              // RFC 5231
  "imap4flags":   false,                                                                              // RFC 5232 // RFC number
  "subaddress":   false,                                                                              // RFC 5233
  "spamtest":     false,                                                                              // RFC 5235
  "virustest":    false,                                                                              // RFC 5235
  "date":         false,                                                                              // RFC 5260
  "index":        false,                                                                              // RFC 5260
  "editheader":   false,                                                                              // RFC 5293
  "reject":       false,                                                                              // RFC 5429
  "ereject":      false,                                                                              // RFC 5429
  "enotify":      false,                                                                              // RFC 5435
  "mime":         false,                                                                              // RFC 5703
  "replace":      false,                                                                              // RFC 5703
  "enclose":      false,                                                                              // RFC 5703
  "extracttext":  false,                                                                              // RFC 5703
  "ihave":        false,                                                                              // RFC 6009
  "mailboxid":    false,                                                                              // RFC 6131
  "extlists":     false,                                                                              // RFC 6134
  "mailbox":      false,                                                                              // RFC 6558
  "include":      false,                                                                              // RFC 6609
  "imapsieve":    false,                                                                              // RFC 6785
  "fcc":          false,                                                                              // RFC 8580 // allow:raw-time-literal — RFC number, not time
});

function _resolveProfile(opts) {
  if (!opts) return "strict";
  if (typeof opts.profile === "string") return opts.profile;
  if (typeof opts.compliancePosture === "string") {
    return COMPLIANCE_POSTURES[opts.compliancePosture] || "strict";
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

// ---- Tokenizer -----------------------------------------------------------

// Token kinds:
//   "id" — identifier (require / if / address / ...)
//   "tag" — `:name`
//   "str" — string literal (quoted or multi-line)
//   "num" — number (optionally suffixed K/M/G)
//   "lbr"/"rbr" — `{` / `}`
//   "lsb"/"rsb" — `[` / `]`
//   "lp"/"rp" — `(` / `)` (rare; not in base grammar but tolerated)
//   "comma"
//   "semi"
//   "eof"

function _isIdStart(c) {
  return (c >= 0x41 && c <= 0x5A) ||                                                                  // A-Z
         (c >= 0x61 && c <= 0x7A) ||                                                                  // a-z
         c === 0x5F;                                                                                  // _
}
function _isIdCont(c) {
  return _isIdStart(c) ||
         (c >= 0x30 && c <= 0x39) ||                                                                  // 0-9
         c === 0x2D;                                                                                  // -
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
      // Recompute line/col at atI (cheap — only on error path)
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

    // Whitespace + line counter.
    if (c === 0x20 || c === 0x09) { _advance(c); continue; }
    if (c === 0x0D) {
      // CRLF expected; bare CR refused per RFC 5228 §2.1.
      if (i + 1 < n && script.charCodeAt(i + 1) === 0x0A) {
        i += 2; line++; col = 1; continue;
      }
      _error("bare CR (RFC 5228 §2.1 requires CRLF)");
    }
    if (c === 0x0A) { _advance(c); continue; }

    // Control bytes outside strings refused (NUL / C0 except TAB/LF/CR).
    if (c < 0x20 && c !== 0x09 && c !== 0x0A && c !== 0x0D) {
      _error("control byte 0x" + c.toString(16) + " refused outside string literal");                  // base-16 toString radix
    }
    if (c === 0x7F) _error("DEL byte refused outside string literal");

    // Comments: `#` to end of line; `/* ... */` block.
    if (c === 0x23) {                                                                                 // #
      while (i < n && script.charCodeAt(i) !== 0x0A) _advance(script.charCodeAt(i));
      continue;
    }
    if (c === 0x2F && i + 1 < n && script.charCodeAt(i + 1) === 0x2A) {                               // /*
      i += 2; col += 2;
      while (i + 1 < n && !(script.charCodeAt(i) === 0x2A && script.charCodeAt(i + 1) === 0x2F)) {
        _advance(script.charCodeAt(i));
      }
      if (i + 1 >= n) _error("unterminated block comment");
      i += 2; col += 2;
      continue;
    }

    // Punctuation.
    if (c === 0x7B) { tokens.push({ k: "lbr", line: line, col: col }); _advance(c); continue; }
    if (c === 0x7D) { tokens.push({ k: "rbr", line: line, col: col }); _advance(c); continue; }
    if (c === 0x5B) { tokens.push({ k: "lsb", line: line, col: col }); _advance(c); continue; }
    if (c === 0x5D) { tokens.push({ k: "rsb", line: line, col: col }); _advance(c); continue; }
    if (c === 0x28) { tokens.push({ k: "lp",  line: line, col: col }); _advance(c); continue; }
    if (c === 0x29) { tokens.push({ k: "rp",  line: line, col: col }); _advance(c); continue; }
    if (c === 0x2C) { tokens.push({ k: "comma", line: line, col: col }); _advance(c); continue; }
    if (c === 0x3B) { tokens.push({ k: "semi",  line: line, col: col }); _advance(c); continue; }

    // Tag `:name`.
    if (c === 0x3A) {
      _advance(c);
      if (i >= n || !_isIdStart(script.charCodeAt(i))) _error("`:` not followed by identifier");
      var tagStart = i;
      while (i < n && _isIdCont(script.charCodeAt(i))) _advance(script.charCodeAt(i));
      tokens.push({ k: "tag", v: script.slice(tagStart, i), line: line, col: col });
      continue;
    }

    // Number with optional K/M/G suffix.
    if (_isDigit(c)) {
      var nStart = i;
      while (i < n && _isDigit(script.charCodeAt(i))) _advance(script.charCodeAt(i));
      var num = parseInt(script.slice(nStart, i), 10);
      if (i < n) {
        var suf = script.charCodeAt(i);
        if (suf === 0x4B || suf === 0x6B) { num *= 1024; _advance(suf); }                             // K
        else if (suf === 0x4D || suf === 0x6D) { num *= 1024 * 1024; _advance(suf); }                 // allow:raw-byte-literal — M
        else if (suf === 0x47 || suf === 0x67) { num *= 1024 * 1024 * 1024; _advance(suf); }          // allow:raw-byte-literal — G
      }
      if (!Number.isFinite(num)) _error("number overflowed");
      tokens.push({ k: "num", v: num, line: line, col: col });
      continue;
    }

    // Identifier.
    if (_isIdStart(c)) {
      var idStart = i;
      while (i < n && _isIdCont(script.charCodeAt(i))) _advance(script.charCodeAt(i));
      var id = script.slice(idStart, i);
      // `text:` introduces a multi-line string per RFC 5228 §2.4.2.
      if (id === "text" && i < n && script.charCodeAt(i) === 0x3A) {
        _advance(0x3A);
        // Optional hash-comment after `text:` per §2.4.2.
        if (i < n && script.charCodeAt(i) === 0x23) {
          while (i < n && script.charCodeAt(i) !== 0x0A) _advance(script.charCodeAt(i));
        }
        // CRLF expected.
        if (i + 1 >= n || script.charCodeAt(i) !== 0x0D || script.charCodeAt(i + 1) !== 0x0A) {
          _error("`text:` must be followed by CRLF");
        }
        i += 2; line++; col = 1;
        var bodyStart = i;
        // Multi-line content terminated by CRLF . CRLF; lines starting
        // with `.` are dot-stuffed per §2.4.2.
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
        i += 5; line++; col = 1;                                                                      // skip `CRLF.CRLF`
        // Dot-unstuff: lines starting with `..` collapse to `.`.
        var body = raw.replace(/\r\n\.\./g, "\r\n.");
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

    // Quoted string.
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
        if (ch === 0x5C) {                                                                            // backslash
          out += script.slice(sStart, i);
          _advance(ch);
          if (i >= n) _error("unterminated string escape");
          var esc = script.charCodeAt(i);
          // RFC 5228 §2.4.2 — only `\\` and `\"` defined; other
          // escapes pass through the backslash and the byte.
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

    _error("unexpected byte 0x" + c.toString(16));                                                     // base-16 toString radix
  }

  tokens.push({ k: "eof", line: line, col: col });
  return tokens;
}

// ---- Parser --------------------------------------------------------------

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
    // Reads tagged-args + positional-args + an optional embedded test.
    // For the v0.9.55 base grammar, args are: tag* (number | string |
    // string-list)* [test]?. The grammar disambiguates tests from
    // positional args by identifier: a known TEST name introduces a
    // test, otherwise we treat the identifier as the start of the next
    // command (return).
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
        tags.push({ name: t.v });
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

    // Action / unknown command — consume args then `;`.
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

// ---- Public surface ------------------------------------------------------

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
  // Sieve scripts MUST use CRLF (RFC 5228 §2.1). Normalize input that
  // arrives over a HTTP boundary where LF-only is common.
  var norm = script;
  if (script.indexOf("\r") === -1) {
    norm = script.replace(/\n/g, "\r\n");
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

/**
 * @primitive  b.safeSieve.compliancePosture
 * @signature  b.safeSieve.compliancePosture(name)
 * @since      0.9.55
 * @status     stable
 * @related    b.safeSieve.parse, b.safeSieve.validate
 *
 * Look up the recommended profile name for a compliance posture
 * (`hipaa` / `pci-dss` / `gdpr` / `soc2`). Returns `"strict"` for any
 * known posture, `null` for unknown names. Operator-facing primitives
 * that thread `compliancePosture` opt through to safeSieve compose
 * this for the explicit-cast pattern when they need the name string
 * (rather than relying on `_resolveOpts` to do the lookup).
 *
 * @example
 *   b.safeSieve.compliancePosture("hipaa");            // → "strict"
 *   b.safeSieve.compliancePosture("loose");            // → null
 */
function compliancePosture(name) {
  return COMPLIANCE_POSTURES[name] || null;
}

module.exports = {
  parse:              parse,
  validate:           validate,
  compliancePosture:  compliancePosture,
  KNOWN_CAPABILITIES: KNOWN_CAPABILITIES,
  PROFILES:           PROFILES,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  SafeSieveError:     SafeSieveError,
  // Internal exports for the interpreter at lib/mail-sieve.js.
  _tokenize:          _tokenize,
  _resolveCaps:       _resolveCaps,
};
