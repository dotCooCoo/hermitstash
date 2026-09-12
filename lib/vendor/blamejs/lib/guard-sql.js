// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.guardSql
 * @nav        Guards
 * @title      Guard SQL
 * @order      460
 *
 * @intro
 *   Raw-SQL content-safety primitive. Gates the residual SQL surface
 *   the `b.sql` builder cannot structurally protect — the operator
 *   escape hatches that take a SQL string verbatim: `whereRaw` /
 *   `setRaw` / `fromRaw` fragments, operator-supplied single-statement
 *   SQL, and migration scripts. Everything `b.sql` composes by
 *   construction (column-membership gate, `?`-placeholder binding,
 *   dialect-final quoting) is already injection-safe; this guard
 *   defends only the bytes a human handed the framework as opaque SQL.
 *
 *   ## Tokenizer-first, never regex-over-raw
 *
 *   Every detector runs on a NORMALIZED token stream, not the raw
 *   string. Naive regex over raw SQL is bypassable in three ways this
 *   guard closes:
 *
 *     1. Comment splitting — `LOAD/**` + `**`/`_FILE` reads as
 *        `LOAD_FILE` to MySQL but `LOAD` `_FILE` to a raw-regex scan.
 *        The normalizer strips comments and collapses the residue so
 *        the keyword detector sees the post-comment token.
 *     2. String-literal smuggling — a keyword inside `'pg_read_file'`
 *        is data, not a call; the normalizer masks literal + dollar-
 *        quoted (`$tag$...$tag$`) spans so a detector never fires on
 *        bytes the engine treats as a value.
 *     3. Encoding bypass — invalid / non-shortest UTF-8 lets a multi-
 *        byte sequence decode to an ASCII metacharacter past a byte-
 *        level filter (the libpq client-encoding class, CVE-2025-1094,
 *        CVSS 8.1, actively exploited via BeyondTrust, public PoC).
 *        The encoding gate refuses the bytes before any token scan.
 *
 *   Pipeline: (1) encoding gate → (2) normalizer (comment strip +
 *   literal/dollar-quote mask + intra-keyword-comment collapse) →
 *   (3) keyword + structural detectors on the normalized stream.
 *
 *   ## Context modes
 *
 *   The same byte string means different things depending on where it
 *   was handed in, so the gate takes a `ctx.mode`:
 *
 *     - `fragment` (default; `whereRaw` / `setRaw` / `fromRaw`) — the
 *       bytes must be a single value expression. A top-level `;`, any
 *       statement-introducing verb, an embedded string literal, or any
 *       dangerous token refuses. This is the strictest context because
 *       the fragment lands inside a query the framework built.
 *     - `operator-sql` — one complete statement. Stacked statements
 *       refuse; the verb may be any single read or write.
 *     - `migration` — a multi-statement DDL script. Multiple statements
 *       and comments are permitted (and audited); each statement is
 *       re-classified and only the DDL-verb allowlist (`CREATE` /
 *       `ALTER` / `CREATE INDEX` / `DROP`) plus reads pass. The OS-reach
 *       floor (file / exec / FDW / privilege-pivot / extension /
 *       attach) still refuses — a migration never needs `COPY ...
 *       PROGRAM` or `load_extension`.
 *
 *   ## Universal refuse floor (every profile, like the always-throw
 *   classes in guard-filename)
 *
 *   These classes refuse under every profile including `permissive` —
 *   they are structurally unambiguous OS-reach / data-exfiltration /
 *   statement-smuggling, and no profile downgrades them:
 *
 *     - Stacked top-level `;` (a second statement past the first).
 *     - Comment smuggling — an unterminated `/*` and the MySQL
 *       executable-comment form `/*!...`.
 *     - Embedded string literal in `fragment` mode.
 *     - Postgres OS reach — `COPY ... PROGRAM`, `COPY TO/FROM <file>`,
 *       `lo_import` / `lo_export` / `lo_get` / `lo_put` / `loread` /
 *       `lowrite`, `pg_read_file` / `pg_read_binary_file` /
 *       `pg_ls_*` / `pg_stat_file`, adminpack `pg_file_write` /
 *       `pg_file_unlink` / `pg_file_rename`, `dblink*` /
 *       `postgres_fdw` / `CREATE SERVER` / `CREATE SUBSCRIPTION`,
 *       `CREATE EXTENSION`, `CREATE [OR REPLACE] FUNCTION ... LANGUAGE`
 *       (plperlu / plpython3u / c), `DO` blocks, `SET ROLE` / `SET
 *       SESSION AUTHORIZATION` / `SET search_path`, `ALTER SYSTEM`.
 *     - SQLite OS reach — `ATTACH` / `DETACH DATABASE`,
 *       `load_extension`, `PRAGMA writable_schema`, `PRAGMA
 *       trusted_schema=ON`, `PRAGMA key` / `PRAGMA rekey`,
 *       `fts3_tokenizer`, `writefile` / `readfile` / `edit`, writes to
 *       `sqlite_master` / `sqlite_*`.
 *     - MySQL OS reach — `LOAD_FILE`, `INTO OUTFILE` / `INTO DUMPFILE`,
 *       `LOAD DATA [LOCAL] INFILE`, `CREATE FUNCTION ... SONAME`,
 *       `sys_exec` / `sys_eval` / `do_system`, `SET GLOBAL` of a
 *       sensitive variable (`general_log` / `local_infile` /
 *       `log_bin_trust_function_creators` / `secure_file_priv`).
 *     - Cross-dialect — time-based blind probes (`SLEEP` / `pg_sleep` /
 *       `WAITFOR DELAY` / `BENCHMARK` / `GET_LOCK`) and a set-operation
 *       (`UNION` / `INTERSECT` / `EXCEPT`) inside a predicate fragment.
 *
 *   ## Profiles
 *
 *   `strict` (default for request-path `whereRaw`) refuses the whole
 *   floor plus non-UTF-8 plus schema-recon reads
 *   (`information_schema` / `performance_schema` / `mysql.` /
 *   `pg_catalog` writes). `balanced` refuses the RCE / file / exec /
 *   FDW / privilege-pivot / stacked / embedded-literal / comment /
 *   invalid-encoding classes and audits schema-recon + time-based.
 *   `permissive` audits the keyword families but STILL hard-refuses the
 *   stacked-statement, invalid-encoding, and irreducible OS-reach floor
 *   — the structurally-unambiguous classes never relax.
 *
 *   ## Compliance postures + audit
 *
 *   `hipaa` / `pci-dss` / `gdpr` / `soc2` all map to the `strict`
 *   floor. Every decision emits a signed audit entry (PCI-DSS 10.2 /
 *   SOC 2 CC7 evidence). Under `gdpr` the audited fragment body is
 *   replaced with a salted hash fingerprint — a raw `whereRaw`
 *   predicate may carry personal data, so the audit records a stable
 *   identifier without the plaintext.
 *
 *   ## Threat grounding
 *
 *   Encoding-bypass: CVE-2025-1094 (PostgreSQL libpq, CVSS 8.1, KEV /
 *   actively exploited via BeyondTrust, public PoC). SQLite memory
 *   corruption reachable from crafted SQL: CVE-2025-6965 (CVSS 9.8,
 *   active) — the connection-hardening notes pin `node:sqlite`
 *   >= 3.50.2. MySQL `LOCAL INFILE` client-side file read:
 *   CVE-2025-62611. Injection leading to compromise, CISA KEV:
 *   CVE-2025-25181. The file / exec / FDW / extension constructs this
 *   guard refuses are by-design-dangerous SQL features, not patchable
 *   product defects — the defense is refusing them at the raw-SQL
 *   boundary, never accepting them from operator-supplied SQL.
 *
 *   Source file is pure ASCII; every attack character (dollar markers,
 *   multibyte encoding-bypass bytes, control bytes) is composed from
 *   numeric codepoints, never embedded as a literal.
 *
 * @card
 *   Raw-SQL content-safety primitive. Tokenizer-first defense for the
 *   `whereRaw` / operator-SQL / migration surface b.sql cannot guard by
 *   construction — refuses stacked statements, comment smuggling,
 *   invalid encoding (CVE-2025-1094), and the file / exec / FDW /
 *   privilege-pivot OS-reach floor across Postgres / SQLite / MySQL.
 */

var gateContract = require("./gate-contract");
var codepointClass = require("./codepoint-class");
var safeSql      = require("./safe-sql");
var C            = require("./constants");
var bCrypto      = require("./crypto");
var lazyRequire  = require("./lazy-require");
var { GuardSqlError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var _err = GuardSqlError.factory;

var CONTEXT_MODES = Object.freeze(["fragment", "operator-sql", "migration"]);
var DEFAULT_CONTEXT_MODE = "fragment";

var STATEMENT_VERBS = Object.freeze({
  SELECT: true, INSERT: true, UPDATE: true, DELETE: true, MERGE: true,
  UPSERT: true, REPLACE: true, CREATE: true, ALTER: true, DROP: true,
  TRUNCATE: true, GRANT: true, REVOKE: true, WITH: true, VALUES: true,
  TABLE: true, COPY: true, CALL: true, EXECUTE: true, DO: true,
  ATTACH: true, DETACH: true, PRAGMA: true, SET: true, RESET: true,
  BEGIN: true, COMMIT: true, ROLLBACK: true, SAVEPOINT: true, VACUUM: true,
  ANALYZE: true, REINDEX: true, EXPLAIN: true, SHOW: true, USE: true,
  DESCRIBE: true, LOAD: true,
});

var LEADING_VERB_FLOOR = Object.freeze({
  DO: true, CALL: true, EXECUTE: true,
});

var MIGRATION_DDL_VERBS = Object.freeze({
  CREATE: true, ALTER: true, DROP: true, RENAME: true, COMMENT: true,
  TRUNCATE: true,
});

var MIGRATION_READ_VERBS = Object.freeze({
  SELECT: true, VALUES: true, TABLE: true, WITH: true,
  SET: true, RESET: true, BEGIN: true, START: true, COMMIT: true,
  ROLLBACK: true, SAVEPOINT: true, RELEASE: true,
  INSERT: true, UPDATE: true, DELETE: true, MERGE: true, UPSERT: true,
  REPLACE: true,
});

var CP_DOLLAR     = 0x24;
var CP_SQUOTE     = 0x27;
var CP_DQUOTE     = 0x22;
var CP_BACKTICK   = 0x60;
var CP_SEMI       = 0x3B;
var CP_HASH       = 0x23;
var CP_BACKSLASH  = 0x5C;
var CP_BANG       = 0x21;
var CP_DASH       = 0x2D;
var CP_SLASH      = 0x2F;
var DOLLAR        = String.fromCharCode(CP_DOLLAR);
var SQUOTE        = String.fromCharCode(CP_SQUOTE);
var DQUOTE        = String.fromCharCode(CP_DQUOTE);

var MASK_SPACE = " ";

function _re(source) {
  // eslint-disable-next-line blamejs/no-regex-in-content-safety
  return new RegExp(source, "i");                                               // allow:dynamic-regex — compile-time ASCII literal table, every span bounded
}


var DETECTORS = [
  { code: "sql.copy-program", severity: "critical", kind: "copy-program",
    family: "floor", dialect: "postgres",
    re: _re("\\bCOPY\\b[\\s\\S]{0,4000}?\\bPROGRAM\\b"),
    reason: "COPY ... PROGRAM executes a shell command (Postgres RCE)" },
  { code: "sql.file-access", severity: "critical", kind: "copy-file",
    family: "floor", dialect: "postgres",
    re: _re("\\bCOPY\\b[\\s\\S]{0,4000}?\\b(?:TO|FROM)\\b(?!\\s+(?:STDIN|STDOUT)\\b)\\s+"),
    reason: "COPY TO/FROM <file> reads or writes a server-side file" },
  { code: "sql.file-access", severity: "critical", kind: "large-object",
    family: "floor", dialect: "postgres",
    re: _re("\\b(?:lo_import|lo_export|lo_get|lo_put|loread|lowrite)\\s*\\("),
    reason: "large-object file primitive (Postgres server-side file I/O)" },
  { code: "sql.file-access", severity: "critical", kind: "pg-read-file",
    family: "floor", dialect: "postgres",
    re: _re("\\b(?:pg_read_file|pg_read_binary_file|pg_stat_file)\\s*\\("),
    reason: "pg_read_file / pg_stat_file reads a server-side file" },
  { code: "sql.file-access", severity: "critical", kind: "pg-ls",
    family: "floor", dialect: "postgres",
    re: _re("\\bpg_ls_[a-z_]+\\s*\\("),
    reason: "pg_ls_* enumerates server-side directories" },
  { code: "sql.file-access", severity: "critical", kind: "adminpack",
    family: "floor", dialect: "postgres",
    re: _re("\\bpg_file_(?:write|unlink|rename)\\s*\\("),
    reason: "adminpack pg_file_* writes / renames / unlinks server files" },
  { code: "sql.outbound-fdw", severity: "critical", kind: "dblink",
    family: "floor", dialect: "postgres",
    re: _re("\\bdblink[a-z_]*\\s*\\("),
    reason: "dblink opens an outbound connection (data exfil / SSRF)" },
  { code: "sql.outbound-fdw", severity: "critical", kind: "fdw",
    family: "floor", dialect: "postgres",
    re: _re("\\b(?:postgres_fdw|CREATE\\s+SERVER|CREATE\\s+SUBSCRIPTION)\\b"),
    reason: "foreign-data-wrapper / subscription opens an outbound channel" },
  { code: "sql.load-extension", severity: "critical", kind: "create-extension",
    family: "floor", dialect: "postgres",
    re: _re("\\bCREATE\\s+EXTENSION\\b"),
    reason: "CREATE EXTENSION loads server-side code" },
  { code: "sql.load-extension", severity: "critical", kind: "create-language-fn",
    family: "floor", dialect: "postgres",
    re: _re("\\bCREATE\\s+(?:OR\\s+REPLACE\\s+)?FUNCTION\\b[\\s\\S]{0,4000}?\\bLANGUAGE\\s+(?:plperlu|plpython3?u|c)\\b"),
    reason: "CREATE FUNCTION in an untrusted procedural language (RCE)" },
  { code: "sql.privilege-pivot", severity: "critical", kind: "do-block",
    family: "floor", dialect: "postgres",
    re: _re("\\bDO\\s+(?:LANGUAGE\\s+[a-z0-9_]+\\s+)?(?:\\$|'|\\bBEGIN\\b)"),
    reason: "DO block runs an anonymous procedural-language body" },
  { code: "sql.privilege-pivot", severity: "critical", kind: "set-role",
    family: "floor", dialect: "postgres",
    re: _re("\\bSET\\s+(?:LOCAL\\s+|SESSION\\s+)?ROLE\\b"),
    reason: "SET ROLE pivots to another database role" },
  { code: "sql.privilege-pivot", severity: "critical", kind: "set-session-auth",
    family: "floor", dialect: "postgres",
    re: _re("\\bSET\\s+SESSION\\s+AUTHORIZATION\\b"),
    reason: "SET SESSION AUTHORIZATION pivots the session identity" },
  { code: "sql.privilege-pivot", severity: "critical", kind: "set-search-path",
    family: "floor", dialect: "postgres",
    re: _re("\\bSET\\s+(?:LOCAL\\s+|SESSION\\s+)?search_path\\b"),
    reason: "SET search_path redirects unqualified name resolution (hijack)" },
  { code: "sql.privilege-pivot", severity: "critical", kind: "alter-system",
    family: "floor", dialect: "postgres",
    re: _re("\\bALTER\\s+SYSTEM\\b"),
    reason: "ALTER SYSTEM rewrites server configuration" },

  { code: "sql.attach", severity: "critical", kind: "attach-db",
    family: "floor", dialect: "sqlite",
    re: _re("\\b(?:ATTACH|DETACH)\\s+(?:DATABASE\\b)?"),
    reason: "ATTACH / DETACH DATABASE mounts an external database file" },
  { code: "sql.load-extension", severity: "critical", kind: "sqlite-load-extension",
    family: "floor", dialect: "sqlite",
    re: _re("\\bload_extension\\s*\\("),
    reason: "load_extension() loads a shared library (RCE)" },
  { code: "sql.privilege-pivot", severity: "critical", kind: "writable-schema",
    family: "floor", dialect: "sqlite",
    re: _re("\\bPRAGMA\\s+writable_schema\\b"),
    reason: "PRAGMA writable_schema lets a write corrupt the schema table" },
  { code: "sql.privilege-pivot", severity: "critical", kind: "trusted-schema",
    family: "floor", dialect: "sqlite",
    re: _re("\\bPRAGMA\\s+trusted_schema\\s*(?:=\\s*)?(?:on|1|true)\\b"),
    reason: "PRAGMA trusted_schema=ON re-enables unsafe schema functions" },
  { code: "sql.privilege-pivot", severity: "critical", kind: "sqlite-key",
    family: "floor", dialect: "sqlite",
    re: _re("\\bPRAGMA\\s+(?:re)?key\\b"),
    reason: "PRAGMA key / rekey changes the database encryption key" },
  { code: "sql.file-access", severity: "critical", kind: "fts3-tokenizer",
    family: "floor", dialect: "sqlite",
    re: _re("\\bfts3_tokenizer\\s*\\("),
    reason: "fts3_tokenizer() is a known SQLite memory-corruption vector" },
  { code: "sql.file-access", severity: "critical", kind: "sqlite-fileio",
    family: "floor", dialect: "sqlite",
    re: _re("\\b(?:writefile|readfile|edit)\\s*\\("),
    reason: "writefile / readfile / edit perform host file I/O" },
  { code: "sql.privilege-pivot", severity: "critical", kind: "sqlite-master-write",
    family: "floor", dialect: "sqlite",
    re: _re("\\b(?:INSERT|UPDATE|DELETE|REPLACE)\\b[\\s\\S]{0,4000}?\\bsqlite_(?:master|schema|sequence|stat[0-9]?)\\b"),
    reason: "write to sqlite_master / sqlite_* internal table" },

  { code: "sql.file-access", severity: "critical", kind: "mysql-load-file",
    family: "floor", dialect: "mysql",
    re: _re("\\bLOAD_FILE\\s*\\("),
    reason: "LOAD_FILE() reads a server-side file" },
  { code: "sql.file-access", severity: "critical", kind: "into-outfile",
    family: "floor", dialect: "mysql",
    re: _re("\\bINTO\\s+(?:OUTFILE|DUMPFILE)\\b"),
    reason: "INTO OUTFILE / DUMPFILE writes a server-side file" },
  { code: "sql.file-access", severity: "critical", kind: "load-data-infile",
    family: "floor", dialect: "mysql",
    re: _re("\\bLOAD\\s+DATA\\b(?:\\s+LOCAL)?\\s+INFILE\\b"),
    reason: "LOAD DATA [LOCAL] INFILE reads a client / server file (CVE-2025-62611)" },
  { code: "sql.load-extension", severity: "critical", kind: "create-fn-soname",
    family: "floor", dialect: "mysql",
    re: _re("\\bCREATE\\s+(?:AGGREGATE\\s+)?FUNCTION\\b[\\s\\S]{0,2000}?\\bSONAME\\b"),
    reason: "CREATE FUNCTION ... SONAME loads a UDF shared library (RCE)" },
  { code: "sql.privilege-pivot", severity: "critical", kind: "mysql-sys-exec",
    family: "floor", dialect: "mysql",
    re: _re("\\b(?:sys_exec|sys_eval|do_system)\\s*\\("),
    reason: "sys_exec / sys_eval / do_system run an OS command (UDF RCE)" },
  { code: "sql.privilege-pivot", severity: "critical", kind: "set-global-sensitive",
    family: "floor", dialect: "mysql",
    re: _re("\\bSET\\s+GLOBAL\\s+(?:general_log|local_infile|log_bin_trust_function_creators|secure_file_priv)\\b"),
    reason: "SET GLOBAL of a sensitive variable enables file / log / UDF abuse" },

  { code: "sql.time-dos", severity: "high", kind: "time-sleep",
    family: "timing", dialect: "cross",
    re: _re("\\b(?:SLEEP|pg_sleep|BENCHMARK|GET_LOCK)\\s*\\("),
    reason: "time-based blind probe / DoS (SLEEP / pg_sleep / BENCHMARK / GET_LOCK)" },
  { code: "sql.time-dos", severity: "high", kind: "time-waitfor",
    family: "timing", dialect: "mssql",
    re: _re("\\bWAITFOR\\s+DELAY\\b"),
    reason: "WAITFOR DELAY time-based blind probe" },

  { code: "sql.privilege-pivot", severity: "high", kind: "schema-recon",
    family: "recon", dialect: "cross",
    re: _re("\\b(?:information_schema|performance_schema|pg_catalog|sys)\\s*\\.|\\bmysql\\s*\\.\\s*[a-z_]+"),
    reason: "schema / catalog enumeration (recon)" },
];

var SETOP_RE = _re("\\b(?:UNION(?:\\s+ALL)?|INTERSECT|EXCEPT)\\b");

var PROFILES = Object.freeze({
  strict: {
    floor:    "refuse",
    comment:  "refuse",
    recon:    "refuse",
    timing:   "refuse",
    setop:    "refuse",
    stacked:  "refuse",
    encoding: "refuse",
    allowComments: false,
    allowMultiStatement: false,
  },
  balanced: {
    floor:    "refuse",
    comment:  "refuse",
    recon:    "audit",
    timing:   "audit",
    setop:    "audit",
    stacked:  "refuse",
    encoding: "refuse",
    allowComments: false,
    allowMultiStatement: false,
  },
  permissive: {
    floor:    "refuse",
    comment:  "audit",
    recon:    "audit",
    timing:   "audit",
    setop:    "audit",
    stacked:  "refuse",
    encoding: "refuse",
    allowComments: true,
    allowMultiStatement: false,
  },
});

var POLICY_ENUM = gateContract.policyVocabulary(
  ["floor", "comment", "recon", "timing", "setop"],
  ["refuse", "audit"],
  {
    stacked:             ["refuse"],
    encoding:            ["refuse"],
    allowMultiStatement: [false],
  });

var RETIRED_OPTS = Object.freeze({
  rceFile:   "the OS-reach floor detectors are governed by `floor`",
  fdw:       "the OS-reach floor detectors are governed by `floor`",
  literal:   "an embedded literal is governed by `allowLiterals`",
  privPivot: "the OS-reach floor detectors are governed by `floor`",
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  contextMode:  DEFAULT_CONTEXT_MODE,
  maxBytes:     C.BYTES.bytes(1048576),
  maxRuntimeMs: C.TIME.seconds(5),
  gdprRedact:   false,
});

var INT_OPTS = ["maxBytes"];

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     Object.assign({}, PROFILES.strict),
  "pci-dss": Object.assign({}, PROFILES.strict),
  gdpr:      Object.assign({}, PROFILES.strict, { gdprRedact: true }),
  soc2:      Object.assign({}, PROFILES.strict),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardSqlError,
    errCodePrefix:      "sql",
    intOpts:            INT_OPTS,
    enumOpts:           POLICY_ENUM,
    retiredOpts:        RETIRED_OPTS,
    nonNegativeOpts:    gateContract.capKeysOf(DEFAULTS),
  });
}

function _resolveContextMode(opts, ctxMode) {
  var mode = ctxMode || (opts && opts.contextMode) || DEFAULT_CONTEXT_MODE;
  if (CONTEXT_MODES.indexOf(mode) === -1) {
    throw _err("sql/bad-opt",
      "guardSql: contextMode must be one of " + CONTEXT_MODES.join("/") +
      ", got " + JSON.stringify(mode));
  }
  return mode;
}

function _encodingIssue(input) {
  var buf;
  if (Buffer.isBuffer(input)) {
    buf = input;
  } else if (typeof input === "string") {
    buf = Buffer.from(input, "utf8");
  } else {
    return _bad("input is not a string or Buffer");
  }

  for (var i = 0; i < buf.length; i += 1) {
    var b0 = buf[i];
    if (b0 < 0x80) continue;
    if (b0 === 0xC0 || b0 === 0xC1 || b0 >= 0xF5) {
      return _bad("non-shortest / out-of-range UTF-8 lead byte 0x" + b0.toString(16));
    }
    var need, lo, hi;
    if (b0 >= 0xF0) { need = 3; lo = (b0 === 0xF0) ? 0x90 : 0x80; hi = (b0 === 0xF4) ? 0x8F : 0xBF; }
    else if (b0 >= 0xE0) { need = 2; lo = (b0 === 0xE0) ? 0xA0 : ((b0 === 0xED) ? 0x80 : 0x80); hi = (b0 === 0xED) ? 0x9F : 0xBF; }
    else if (b0 >= 0xC2) { need = 1; lo = 0x80; hi = 0xBF; }
    else { return _bad("stray continuation byte 0x" + b0.toString(16)); }
    if (i + need >= buf.length) return _bad("truncated multibyte UTF-8 sequence");
    var c1 = buf[i + 1];
    if (c1 < lo || c1 > hi) return _bad("invalid UTF-8 continuation byte 0x" + c1.toString(16));
    for (var k = 2; k <= need; k += 1) {
      var ck = buf[i + k];
      if (ck < 0x80 || ck > 0xBF) return _bad("invalid UTF-8 continuation byte 0x" + ck.toString(16));
    }
    i += need;
  }

  var REPLACEMENT_CHAR = String.fromCharCode(0xFFFD);
  var decoded = buf.toString("utf8");
  if (decoded.indexOf(REPLACEMENT_CHAR) !== -1) {
    return _bad("decoded SQL contains the Unicode replacement character (lossy decode)");
  }
  return null;

  function _bad(detail) {
    return {
      code: "sql.invalid-encoding", severity: "critical",
      kind: "invalid-encoding", ruleId: "sql.invalid-encoding",
      snippet: "SQL bytes fail UTF-8 validation (" + detail +
               ") — encoding-bypass defense (CVE-2025-1094 class)",
    };
  }
}

function _isIdentByte(ch) {
  return (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") ||
         (ch >= "0" && ch <= "9") || ch === "_" || ch === DOLLAR;
}

function _normalize(text) {
  var n = text.length;
  var out = [];
  var signals = {
    hadComment:           false,
    hadExecutableComment: false,
    unterminatedComment:  false,
    hadLiteral:           false,
    unterminatedLiteral:  false,
    ambiguousLiteralEscape: false,
    ambiguousComment:     false,
  };
  var i = 0;
  while (i < n) {
    var ch = text.charAt(i);
    var cc = text.charCodeAt(i);
    var next = i + 1 < n ? text.charAt(i + 1) : "";

    if (cc === CP_DASH && next === "-") {
      signals.hadComment = true;
      if (!_endsCommentIntro(text, i + 2)) signals.ambiguousComment = true;
      _collapseOrSpace(out, text, i);
      var nl = text.indexOf("\n", i + 2);
      i = nl === -1 ? n : nl + 1;
      continue;
    }
    if (cc === CP_HASH) {
      signals.hadComment = true;
      signals.ambiguousComment = true;
      _collapseOrSpace(out, text, i);
      var nl2 = text.indexOf("\n", i + 1);
      i = nl2 === -1 ? n : nl2 + 1;
      continue;
    }
    if (cc === CP_SLASH && next === "*") {
      signals.hadComment = true;
      if (i + 2 < n && text.charCodeAt(i + 2) === CP_BANG) {
        signals.hadExecutableComment = true;
      }
      var end = text.indexOf("*/", i + 2);
      if (end === -1) {
        signals.unterminatedComment = true;
        i = n;
        continue;
      }
      _collapseOrSpace(out, text, i, end + 2);
      i = end + 2;
      continue;
    }
    if (cc === CP_SQUOTE) {
      signals.hadLiteral = true;
      out.push(MASK_SPACE);
      i += 1;
      while (i < n) {
        if (text.charCodeAt(i) === CP_BACKSLASH &&
            _oddBackslashRunBefore(text, i, CP_SQUOTE)) {
          signals.ambiguousLiteralEscape = true;
        }
        if (text.charCodeAt(i) === CP_SQUOTE) {
          if (i + 1 < n && text.charCodeAt(i + 1) === CP_SQUOTE) {
            out.push(MASK_SPACE); out.push(MASK_SPACE); i += 2; continue;
          }
          out.push(MASK_SPACE); i += 1; break;
        }
        out.push(MASK_SPACE); i += 1;
        if (i >= n) { signals.unterminatedLiteral = true; }
      }
      continue;
    }
    if (cc === CP_DQUOTE) {
      out.push(MASK_SPACE);
      i += 1;
      while (i < n) {
        if (text.charCodeAt(i) === CP_BACKSLASH &&
            _oddBackslashRunBefore(text, i, CP_DQUOTE)) {
          signals.ambiguousLiteralEscape = true;
        }
        if (text.charCodeAt(i) === CP_DQUOTE) {
          if (i + 1 < n && text.charCodeAt(i + 1) === CP_DQUOTE) {
            out.push(MASK_SPACE); out.push(MASK_SPACE); i += 2; continue;
          }
          out.push(MASK_SPACE); i += 1; break;
        }
        out.push(MASK_SPACE); i += 1;
      }
      continue;
    }
    if (cc === CP_BACKTICK) {
      out.push(MASK_SPACE);
      i += 1;
      while (i < n) {
        if (text.charCodeAt(i) === CP_BACKTICK) { out.push(MASK_SPACE); i += 1; break; }
        out.push(MASK_SPACE); i += 1;
      }
      continue;
    }
    if (cc === CP_DOLLAR) {
      var tagEnd = i + 1;
      while (tagEnd < n && _isWordByte(text.charAt(tagEnd))) tagEnd += 1;
      if (tagEnd < n && text.charCodeAt(tagEnd) === CP_DOLLAR) {
        var tag = text.slice(i, tagEnd + 1);
        var closeTag = text.indexOf(tag, tagEnd + 1);
        if (closeTag === -1) {
          signals.hadLiteral = true;
          signals.unterminatedLiteral = true;
          i = n;
          continue;
        }
        signals.hadLiteral = true;
        var maskLen = (closeTag + tag.length) - i;
        for (var m = 0; m < maskLen; m += 1) out.push(MASK_SPACE);
        i = closeTag + tag.length;
        continue;
      }
      out.push(ch);
      i += 1;
      continue;
    }
    out.push(ch);
    i += 1;
  }
  return { normalized: out.join(""), signals: signals };
}

function _isWordByte(ch) {
  return (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") ||
         (ch >= "0" && ch <= "9") || ch === "_";
}

function _oddBackslashRunBefore(text, at, quoteCode) {
  if (text.charCodeAt(at - 1) === CP_BACKSLASH) return false;
  var end = at;
  while (end < text.length && text.charCodeAt(end) === CP_BACKSLASH) end += 1;
  if (text.charCodeAt(end) !== quoteCode) return false;
  return ((end - at) % 2) === 1;
}

function _endsCommentIntro(text, at) {
  if (at >= text.length) return true;
  var c = text.charCodeAt(at);
  return c === 0x20 || c === 0x09 || c === 0x0A || c === 0x0D || c === 0x0C ||
         c === 0x0B;
}

function _collapseOrSpace(out, text, start, end) {
  var prev = out.length > 0 ? out[out.length - 1] : "";
  var prevByte = prev.length > 0 ? prev.charAt(prev.length - 1) : "";
  var afterIdx = typeof end === "number" ? end : start;
  var nextByte = afterIdx < text.length ? text.charAt(afterIdx) : "";
  if (prevByte && nextByte && _isIdentByte(prevByte) && _isIdentByte(nextByte)) {
    return;
  }
  out.push(MASK_SPACE);
}

function _stackedStatementIssue(normalized) {
  var n = normalized.length;
  var firstSemi = -1;
  for (var i = 0; i < n; i += 1) {
    if (normalized.charCodeAt(i) !== CP_SEMI) continue;
    firstSemi = i;
    break;
  }
  if (firstSemi === -1) return null;
  for (var j = firstSemi + 1; j < n; j += 1) {
    var ch = normalized.charAt(j);
    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") continue;
    return {
      code: "sql.stacked", severity: "critical", kind: "stacked-statement",
      ruleId: "sql.stacked",
      snippet: "stacked statement after top-level ';' — only one statement permitted",
    };
  }
  return null;
}

function _leadingVerb(normalized) {
  var n = normalized.length;
  var i = 0;
  while (i < n) {
    var cc = normalized.charCodeAt(i);
    if (cc === 0x20 || cc === 0x09 || cc === 0x0A || cc === 0x0D ||
        cc === 0x0B || cc === 0x0C || cc === 0x28) { i += 1; continue; }
    break;
  }
  var start = i;
  while (i < n && _isWordByte(normalized.charAt(i))) i += 1;
  return normalized.slice(start, i).toUpperCase();
}

function _splitStatements(normalized) {
  var parts = [];
  var n = normalized.length;
  var start = 0;
  for (var i = 0; i < n; i += 1) {
    if (normalized.charCodeAt(i) === CP_SEMI) {
      parts.push(normalized.slice(start, i));
      start = i + 1;
    }
  }
  if (start < n) parts.push(normalized.slice(start));
  return parts.filter(function (s) { return s.trim().length > 0; });
}

function _decideDetector(det, profile) {
  var fam = det.family;
  if (fam === "recon") return profile.recon;
  if (fam === "timing") return profile.timing;
  return profile.floor;
}

function _runDetectors(normalized, profile) {
  var issues = [];
  for (var i = 0; i < DETECTORS.length; i += 1) {
    var det = DETECTORS[i];
    if (det.re.test(normalized)) {
      var action = _decideDetector(det, profile);
      issues.push({
        code:     det.code,
        kind:     det.kind,
        ruleId:   det.code,
        severity: action === "refuse" ? det.severity : "warn",
        action:   action,
        dialect:  det.dialect,
        snippet:  det.reason,
      });
    }
  }
  return issues;
}

function _inspect(input, opts, contextMode) {
  var issues = [];

  var encIssue = _encodingIssue(input);
  if (encIssue) {
    issues.push(encIssue);
    return issues;
  }

  var text = Buffer.isBuffer(input) ? input.toString("utf8") : String(input);

  var byteLen = Buffer.byteLength(text, "utf8");
  if (opts.maxBytes && byteLen > opts.maxBytes) {
    issues.push({
      code: "sql.refuse", severity: "high", kind: "oversize",
      ruleId: "sql.oversize",
      snippet: "raw SQL " + byteLen + " bytes exceeds maxBytes " + opts.maxBytes,
    });
  }

  var norm = _normalize(text);
  var normalized = norm.normalized;
  var sig = norm.signals;

  if (sig.unterminatedComment) {
    issues.push({
      code: "sql.stacked", severity: "critical", kind: "unterminated-comment",
      ruleId: "sql.unterminated-comment",
      snippet: "unterminated /* block comment (comment-smuggling defense)",
    });
  }
  if (sig.hadExecutableComment) {
    issues.push({
      code: "sql.stacked", severity: "critical", kind: "executable-comment",
      ruleId: "sql.executable-comment",
      snippet: "MySQL executable comment /*! ... */ (version-gated injection vector)",
    });
  }
  if (sig.unterminatedLiteral) {
    issues.push({
      code: "sql.embedded-literal", severity: "critical", kind: "unterminated-literal",
      ruleId: "sql.unterminated-literal",
      snippet: "unterminated string literal / dollar-quote",
    });
  }
  if (sig.ambiguousLiteralEscape) {
    issues.push({
      code: "sql.embedded-literal", severity: "critical",
      kind: "ambiguous-literal-escape",
      ruleId: "sql.ambiguous-literal-escape",
      snippet: "backslash before a quote inside a string literal: the literal " +
               "ends at a different character on MySQL than on SQLite / PostgreSQL",
    });
  }
  if (sig.ambiguousComment) {
    issues.push({
      code: "sql.comment", severity: "critical",
      kind: "ambiguous-comment",
      ruleId: "sql.ambiguous-comment",
      snippet: "comment syntax the engines read differently (`#`, or `--` " +
               "with no following whitespace): use `-- ` or `/* */`",
    });
  }
  if (sig.hadComment && !sig.unterminatedComment && !sig.hadExecutableComment) {
    var commentAction = (contextMode === "migration" || opts.allowComments)
      ? "audit" : opts.comment;
    if (commentAction === "refuse") {
      issues.push({
        code: "sql.stacked", severity: "critical", kind: "comment",
        ruleId: "sql.comment",
        snippet: "SQL comment in raw fragment (comment-smuggling surface)",
      });
    } else {
      issues.push({
        code: "sql.stacked", severity: "warn", kind: "comment", action: "audit",
        ruleId: "sql.comment",
        snippet: "SQL comment present (audited)",
      });
    }
  }

  _identifierHygieneIssues(text)
    .forEach(function (issue) { issues.push(issue); });

  if (contextMode !== "migration") {
    var stackedIssue = _stackedStatementIssue(normalized);
    if (stackedIssue) issues.push(stackedIssue);
  }

  _runDetectors(normalized, opts)
    .forEach(function (issue) { issues.push(issue); });

  var verbStmts = (contextMode === "migration")
    ? _splitStatements(normalized) : [normalized];
  for (var vi = 0; vi < verbStmts.length; vi += 1) {
    var lv = _leadingVerb(verbStmts[vi]);
    if (LEADING_VERB_FLOOR[lv] === true) {
      issues.push({
        code: "sql.privilege-pivot", severity: "critical", kind: "procedural-exec",
        ruleId: "sql.procedural-exec",
        snippet: "statement leads with procedural-execution verb " +
                 JSON.stringify(lv) + " (DO / CALL / EXECUTE run code / routines)",
      });
    }
  }

  if (SETOP_RE.test(normalized)) {                                          // allow:regex-no-length-cap - normalized bounded by opts.maxBytes (1 MiB) at entry; SETOP_RE is a linear alternation
    if (contextMode === "fragment") {
      issues.push({
        code: "sql.union-exfil", severity: "critical", kind: "setop-in-fragment",
        ruleId: "sql.union-exfil",
        snippet: "UNION / INTERSECT / EXCEPT inside a value-expression fragment (exfil shape)",
      });
    } else {
      var setopAction = opts.setop;
      issues.push({
        code: "sql.union-exfil",
        severity: setopAction === "refuse" ? "high" : "warn",
        action: setopAction,
        kind: "setop", ruleId: "sql.union-exfil",
        snippet: "set operation (UNION / INTERSECT / EXCEPT)",
      });
    }
  }

  if (contextMode === "fragment") {
    _inspectFragment(text, normalized, opts, issues);
  } else if (contextMode === "operator-sql") {
    _inspectOperatorSql(normalized, issues);
  } else if (contextMode === "migration") {
    _inspectMigration(normalized, opts, issues);
  }

  return issues;
}

function _inspectFragment(rawText, normalized, opts, issues) {
  var verb = _leadingVerb(normalized);
  if (verb && STATEMENT_VERBS[verb] === true) {
    issues.push({
      code: "sql.refuse", severity: "critical", kind: "verb-in-fragment",
      ruleId: "sql.verb-in-fragment",
      snippet: "statement verb " + JSON.stringify(verb) +
               " in a value-expression fragment (whereRaw must be an expression)",
    });
  }
  if (!opts.allowLiterals && _hasEmbeddedStringLiteral(rawText)) {
    issues.push({
      code: "sql.embedded-literal", severity: "critical", kind: "embedded-literal",
      ruleId: "sql.embedded-literal",
      snippet: "raw fragment embeds a string literal ('...') — bind every value " +
               "with a ? placeholder, or pass allowLiterals:true for a static literal",
    });
  }
  if (normalized.indexOf(";") !== -1) {
    issues.push({
      code: "sql.refuse", severity: "critical", kind: "semicolon-in-fragment",
      ruleId: "sql.semicolon-in-fragment",
      snippet: "top-level ';' in a value-expression fragment — a fragment must be a single expression",
    });
  }
}

function _inspectOperatorSql(normalized, issues) {
  var verb = _leadingVerb(normalized);
  if (!verb) {
    issues.push({
      code: "sql.refuse", severity: "warn", kind: "no-verb", action: "audit",
      ruleId: "sql.no-verb",
      snippet: "operator-sql has no resolvable leading verb",
    });
  }
}

function _inspectMigration(normalized, opts, issues) {
  var statements = _splitStatements(normalized);
  for (var i = 0; i < statements.length; i += 1) {
    var verb = _leadingVerb(statements[i]);
    if (!verb) continue;
    if (MIGRATION_DDL_VERBS[verb] === true) continue;
    if (MIGRATION_READ_VERBS[verb] === true) continue;
    issues.push({
      code: "sql.refuse", severity: "critical", kind: "migration-verb",
      ruleId: "sql.migration-verb",
      snippet: "statement verb " + JSON.stringify(verb) +
               " not in the migration DDL allowlist (CREATE / ALTER / DROP / reads)",
    });
  }
}

function _hasEmbeddedStringLiteral(sql) {
  var i = 0;
  var len = sql.length;
  while (i < len) {
    var ch = sql.charAt(i);
    var next = i + 1 < len ? sql.charAt(i + 1) : "";
    if (ch === DQUOTE) {
      i += 1;
      while (i < len) {
        if (sql.charAt(i) === DQUOTE) {
          if (sql.charAt(i + 1) === DQUOTE) { i += 2; continue; }
          i += 1; break;
        }
        i += 1;
      }
      continue;
    }
    if (ch === "-" && next === "-") {
      while (i < len && sql.charAt(i) !== "\n") i += 1;
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < len && !(sql.charAt(i) === "*" && sql.charAt(i + 1) === "/")) i += 1;
      i += 2;
      continue;
    }
    if (ch === SQUOTE) return true;
    if (ch === "$") {
      var j = i + 1;
      while (j < len) {
        var tch = sql.charAt(j);
        if (!((tch >= "a" && tch <= "z") || (tch >= "A" && tch <= "Z") ||
              (tch >= "0" && tch <= "9") || tch === "_")) break;
        j += 1;
      }
      if (j < len && sql.charAt(j) === "$") return true;
    }
    i += 1;
  }
  return false;
}

function _identifierHygieneIssues(sql) {
  var issues = [];
  var i = 0;
  var len = sql.length;
  while (i < len) {
    var ch = sql.charCodeAt(i);
    if (ch === CP_SQUOTE) {
      i += 1;
      while (i < len) {
        if (sql.charCodeAt(i) === CP_SQUOTE) {
          if (i + 1 < len && sql.charCodeAt(i + 1) === CP_SQUOTE) { i += 2; continue; }
          i += 1; break;
        }
        i += 1;
      }
      continue;
    }
    if (ch === CP_DQUOTE) {
      var start = i + 1;
      var j = start;
      while (j < len) {
        if (sql.charCodeAt(j) === CP_DQUOTE) {
          if (j + 1 < len && sql.charCodeAt(j + 1) === CP_DQUOTE) { j += 2; continue; }
          break;
        }
        j += 1;
      }
      var ident = sql.slice(start, j);
      var bad = _identifierHazard(ident);
      if (bad) {
        issues.push({
          code: "sql.refuse", severity: "critical", kind: "identifier-hazard",
          ruleId: "sql.identifier-hazard",
          snippet: "quoted identifier " + bad + " (CVE-2025-8715 class)",
        });
      }
      i = j + 1;
      continue;
    }
    i += 1;
  }
  return issues;
}

function _identifierHazard(ident) {
  if (ident.indexOf("\n") !== -1 || ident.indexOf("\r") !== -1) {
    return "contains a newline";
  }
  if (ident.charAt(0) === "\\") {
    return "starts with a backslash";
  }
  for (var k = 0; k < ident.length; k += 1) {
    var c = ident.charCodeAt(k);
    if (codepointClass.isForbiddenControlChar(c, { forbidTab: true })) {
      return c === 0 ? "contains a null byte"
                     : "contains a control byte 0x" + c.toString(16);
    }
  }
  try {
    safeSql.validateIdentifier(ident, { allowReserved: true, allowSqliteInternal: true });
  } catch (e) {
    if (e instanceof safeSql.SafeSqlError &&
        (e.code === "sql/too-long" || e.code === "sql/null-byte")) {
      return "rejected by safeSql.validateIdentifier (" + e.code + ")";
    }
  }
  return null;
}

/**
 * @primitive  b.guardSql.validate
 * @signature  b.guardSql.validate(input, opts?)
 * @since      0.14.29
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardSql.gate, b.guardSql.sanitize, b.safeSql.validateIdentifier
 *
 * Inspect a raw SQL string or Buffer and return `{ ok, issues }`. Each
 * issue carries `{ code, kind, ruleId, severity, snippet }` with
 * severity in `"warn"|"high"|"critical"`. `ok` is `true` only when no
 * issue is `high` or `critical`. Pure inspection — never throws on input.
 *
 * The inspection runs three stages: a UTF-8 encoding gate (defends the
 * libpq client-encoding bypass class, CVE-2025-1094), a comment-and-
 * literal normalizer, and keyword + structural detectors on the
 * normalized stream. The detected classes are stacked statements,
 * comment smuggling, embedded string literals (fragment mode), the
 * Postgres / SQLite / MySQL file / exec / FDW / extension / privilege-
 * pivot constructs, time-based probes, schema recon, and set operations
 * inside a predicate.
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   contextMode:       "fragment"|"operator-sql"|"migration",   // default "fragment"
 *   allowLiterals:     boolean,    // permit a static '...' literal in a fragment
 *   maxBytes:          number,     // raw-SQL byte cap (default 1 MiB)
 *   floor:             "refuse"|"audit",   // the OS-reach floor detectors
 *   recon:             "refuse"|"audit",
 *   timing:            "refuse"|"audit",
 *   comment:           "refuse"|"audit",
 *   setop:             "refuse"|"audit",
 *   allowComments:     boolean,
 *   stacked:           "refuse",   // fixed; a stacked statement always refuses
 *   encoding:          "refuse",   // fixed; invalid encoding always refuses
 *   allowMultiStatement: false,    // fixed; this guard permits one statement
 *
 * @example
 *   var rv = b.guardSql.validate("id = ? AND tenant = ?", { profile: "strict" });
 *   rv.ok;                                                // → true
 *
 *   var bad = b.guardSql.validate("1; DROP TABLE users", { profile: "strict" });
 *   bad.ok;                                               // → false
 *   bad.issues.some(function (i) { return i.kind === "stacked-statement"; });  // → true
 */
function validate(input, opts) {
  opts = _resolveOpts(opts);
  var contextMode = _resolveContextMode(opts);
  return gateContract.runIssueValidator(input, opts,
    function (subject, o) { return _inspect(subject, o, contextMode); }, "bytes");
}

/**
 * @primitive  b.guardSql.sanitize
 * @signature  b.guardSql.sanitize(input, opts?)
 * @since      0.14.29
 * @status     stable
 * @related    b.guardSql.validate, b.guardSql.gate
 *
 * Return the comment-stripped, literal-masked NORMALIZED form of a raw
 * SQL string — the internal representation the detectors run on, not a
 * "made-safe" query. Hostile SQL is unrepairable: there is no
 * transform that turns `COPY ... PROGRAM` or a stacked `;DROP` into a
 * safe statement, so `sanitize` never serves its output as a query.
 * Throws `GuardSqlError` when the input refuses under the resolved
 * profile (invalid encoding, the OS-reach floor, stacked statements),
 * mirroring the entries-class guards whose hostile input has no
 * sanitize action.
 *
 * Use it to inspect what the tokenizer saw (debugging a false-positive
 * detector, building a redacted audit fingerprint) — not to feed the
 * result back to a driver.
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   contextMode:       "fragment"|"operator-sql"|"migration",
 *
 * @example
 *   var normalized = b.guardSql.sanitize(
 *     "id = ? -- note\n AND active = ?",
 *     { profile: "permissive" });
 *   // → "id = ?  AND active = ?"  (comment stripped)
 *
 *   try {
 *     b.guardSql.sanitize("SELECT pg_read_file('/etc/passwd')");
 *   } catch (e) {
 *     e.code;                                             // → "sql.file-access"
 *   }
 */
function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  var contextMode = _resolveContextMode(opts);
  if (typeof input !== "string" && !Buffer.isBuffer(input)) {
    throw _err("sql/bad-input", "sanitize requires string or Buffer input");
  }
  var issues = _inspect(input, opts, contextMode);
  var refusal = _firstRefusal(issues);
  if (refusal) {
    throw _err(refusal.code, "guardSql.sanitize: " + refusal.snippet);
  }
  var text = Buffer.isBuffer(input) ? input.toString("utf8") : String(input);
  return _normalize(text).normalized;
}

function _firstRefusal(issues) {
  for (var i = 0; i < issues.length; i += 1) {
    var it = issues[i];
    if (it.action === "audit") continue;
    if (it.severity === "critical" || it.severity === "high") return it;
  }
  return null;
}

/**
 * @primitive  b.guardSql.gate
 * @signature  b.guardSql.gate(opts?)
 * @since      0.14.29
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardSql.validate, b.guardSql.sanitize, b.gateContract.buildGuardGate
 *
 * Build a `b.gateContract` gate that consumes `ctx.sql` (or
 * `ctx.bytes`). Action chain: `serve` (no SQL or clean) → `audit-only`
 * (warn-level issues, every reject-class off) → `refuse` (any
 * critical / high issue, or an explicit refuse action). There is no
 * `sanitize` action — hostile SQL is unrepairable, so a refusal is the
 * only safe non-serve outcome. The gate honors `ctx.mode` (one of the
 * context modes) over the opts default, so one gate instance can guard
 * a `fragment` whereRaw and an `operator-sql` path with the right
 * strictness per call.
 *
 * Every decision emits a signed audit entry; under the `gdpr` posture
 * the audited SQL is replaced with a salted hash fingerprint (a
 * `whereRaw` predicate may carry personal data).
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   contextMode:       "fragment"|"operator-sql"|"migration",
 *   name:              string,    // gate identity for audit / observability
 *
 * @example
 *   var sqlGate = b.guardSql.gate({ profile: "strict" });
 *   var verdict = await sqlGate.check({ sql: "id = ?", mode: "fragment" });
 *   verdict.action;                                       // → "serve"
 *
 *   var blocked = await sqlGate.check({ sql: "1; DROP TABLE users" });
 *   blocked.action;                                       // → "refuse"
 */
function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardSql:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var sql = ctx && (ctx.sql || ctx.bytes || "");
      if (!sql || (typeof sql !== "string" && !Buffer.isBuffer(sql))) {
        return { ok: true, action: "serve" };
      }
      var contextMode = _resolveContextMode(opts, ctx && ctx.mode);
      var issues = _inspect(sql, opts, contextMode);

      _emitDecisionAudit(sql, issues, opts, contextMode, ctx);

      var refusal = _firstRefusal(issues);
      if (refusal) {
        return { ok: false, action: "refuse", issues: issues };
      }
      if (issues.length > 0) {
        return { ok: true, action: "audit-only", issues: issues };
      }
      return { ok: true, action: "serve" };
    });
}

// Emits a signed audit entry for a gate decision. Drop-silent.
function _emitDecisionAudit(sql, issues, opts, contextMode, ctx) {
  try {
    var refused = _firstRefusal(issues) !== null;
    var text = Buffer.isBuffer(sql) ? sql.toString("utf8") : String(sql);
    var body = opts.gdprRedact ? _fingerprint(text) : _truncateForAudit(text);
    audit().namespaced("guardSql.gate")(
      refused ? "refused" : (issues.length > 0 ? "audited" : "served"),
      refused ? "denied" : "success",
      {
        contextMode: contextMode,
        profile:     opts.profile || "strict",
        route:       ctx && ctx.route,
        sql:         body,
        sqlRedacted: !!opts.gdprRedact,
        issues:      gateContract.summarizeIssues(issues),
      },
      { actor: ctx && ctx.actor }
    );
  } catch (_e) { /* drop-silent — audit sinks must never crash the producer */ }
}

function _fingerprint(text) {
  return "sha3:" + bCrypto.sha3Hash(Buffer.from(text, "utf8"), "hex").slice(0, 16);
}

var AUDIT_SNIPPET_CHARS = 200;
function _truncateForAudit(text) {
  return text.length > AUDIT_SNIPPET_CHARS
    ? text.slice(0, AUDIT_SNIPPET_CHARS) + "...(truncated)" : text;
}

var INTEGRATION_FIXTURES = Object.freeze({
  kind:        "sql",
  benignSql:   "id = ? AND status = ?",
  hostileSql:  "id = 1; DROP TABLE users",
});

module.exports = gateContract.defineGuard({
  name:        "sql",
  kind:        "sql",
  enumOpts:    POLICY_ENUM,
  retiredOpts: RETIRED_OPTS,
  errorClass:  GuardSqlError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  validate:    validate,
  sanitize:    sanitize,
  intOpts:     INT_OPTS,
  gate:        gate,
  extra: {
    MIME_TYPES:    Object.freeze(["application/sql"]),
    EXTENSIONS:    Object.freeze([".sql"]),
    CONTEXT_MODES: CONTEXT_MODES,
    DETECTORS:     Object.freeze(DETECTORS.slice()),
    RETIRED_OPTS:  RETIRED_OPTS,
  },
});
