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

// ---- Context modes ----

// fragment   — whereRaw / setRaw / fromRaw value expression. Strictest.
// operator-sql — one complete statement.
// migration  — multi-statement DDL script (each statement re-classified).
var CONTEXT_MODES = Object.freeze(["fragment", "operator-sql", "migration"]);
var DEFAULT_CONTEXT_MODE = "fragment";

// ---- Statement verbs that introduce a statement (refused inside a
// fragment, which must be a bare value expression). ----
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

// Statement verbs that are a floor refusal when they LEAD a statement,
// regardless of profile or context. A procedural-execution verb (DO
// anonymous block, CALL / EXECUTE a stored routine) runs code through
// the raw-SQL surface — operator SQL never legitimately does this, and
// the DO body is masked by the dollar-quote normalizer so a token-level
// detector cannot see into it. The leading-verb scan is the reliable
// catch for the whole class.
var LEADING_VERB_FLOOR = Object.freeze({
  DO: true, CALL: true, EXECUTE: true,
});

// Migration DDL-verb allowlist — the only statement verbs a migration
// script may use (plus reads, classified separately). CREATE INDEX is a
// CREATE; the OS-reach floor still strips CREATE EXTENSION / SERVER /
// SUBSCRIPTION / FUNCTION-LANGUAGE out of the CREATE family.
var MIGRATION_DDL_VERBS = Object.freeze({
  CREATE: true, ALTER: true, DROP: true, RENAME: true, COMMENT: true,
  TRUNCATE: true,
});

// Read-class verbs a migration script may also run (a migration often
// SELECTs to backfill). Mirrors external-db's READ classification.
var MIGRATION_READ_VERBS = Object.freeze({
  SELECT: true, VALUES: true, TABLE: true, WITH: true,
  SET: true, RESET: true, BEGIN: true, START: true, COMMIT: true,
  ROLLBACK: true, SAVEPOINT: true, RELEASE: true,
  INSERT: true, UPDATE: true, DELETE: true, MERGE: true, UPSERT: true,
  REPLACE: true,
});

// ---- Numeric codepoints for the attack/marker bytes (source stays
// pure ASCII — no attack character appears as a literal). ----
var CP_DOLLAR     = 0x24;   // $   — Postgres dollar-quote marker
var CP_SQUOTE     = 0x27;   // '   — string-literal quote
var CP_DQUOTE     = 0x22;   // "   — double-quoted identifier
var CP_BACKTICK   = 0x60;   // `   — MySQL backtick identifier
var CP_SEMI       = 0x3B;   // ;   — statement separator
var CP_HASH       = 0x23;   // #   — MySQL line comment
var CP_BANG       = 0x21;   // !   — MySQL executable-comment marker
var CP_DASH       = 0x2D;   // -   — line-comment lead char
var CP_SLASH      = 0x2F;   // /   — block-comment lead char
var DOLLAR        = String.fromCharCode(CP_DOLLAR);
var SQUOTE        = String.fromCharCode(CP_SQUOTE);
var DQUOTE        = String.fromCharCode(CP_DQUOTE);

// A single space the normalizer leaves where it removes a comment, so
// adjacent tokens don't fuse (`a/* */b` -> `a b`), while an intra-
// keyword comment in a token (`LOAD/**/_FILE`) is handled by the
// secondary collapse below.
var MASK_SPACE = " ";

// ---- Dangerous-construct detector table ----
//
// Each entry: { code, severity, kind, re, classes }. `re` runs against
// the NORMALIZED stream (comments stripped, literal/dollar-quote spans
// masked, lower/upper-insensitive). `classes` declares which families
// each profile decides on. Regexes are word-boundary + whitespace-
// tolerant; they never run on raw bytes.
//
// Family taxonomy (used by the profile decision):
//   floor       — refuse at EVERY profile (irreducible OS-reach /
//                 statement-smuggling).
//   rce-file    — file read/write, code exec, FDW, extension, priv-
//                 pivot. strict + balanced refuse; permissive audits
//                 (except the floor subset, which the floor list covers).
//   recon       — schema-enumeration reads. strict refuses; balanced /
//                 permissive audit.
//   timing      — time-based blind probes. strict refuses; balanced /
//                 permissive audit.
//   exfil       — UNION/INTERSECT/EXCEPT inside a predicate. floor in
//                 fragment mode (a value expression has no set op).

function _re(source) {
  // Construct each detector regex from an ASCII source string so the
  // source file embeds no attack-character literals. Case-insensitive;
  // detectors are intentionally global-free (first match is enough).
  return new RegExp(source, "i");                                       // allow:dynamic-regex — detector source is a compile-time ASCII literal table below
}

// \b word-boundary + optional whitespace/paren tolerance baked into
// each source string. `[\s]` spans the comment-collapsed single spaces.
var DETECTORS = [
  // ---- Postgres OS reach ----
  { code: "sql.copy-program", severity: "critical", kind: "copy-program",
    family: "floor", dialect: "postgres",
    re: _re("\\bCOPY\\b[\\s\\S]{0,4000}?\\bPROGRAM\\b"),
    reason: "COPY ... PROGRAM executes a shell command (Postgres RCE)" },
  { code: "sql.file-access", severity: "critical", kind: "copy-file",
    family: "floor", dialect: "postgres",
    re: _re("\\bCOPY\\b[\\s\\S]{0,4000}?\\b(?:TO|FROM)\\b\\s+(?!STDIN\\b|STDOUT\\b)"),
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

  // ---- SQLite OS reach ----
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
    re: _re("\\bPRAGMA\\s+trusted_schema\\s*=?\\s*(?:on|1|true)\\b"),
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

  // ---- MySQL OS reach ----
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

  // ---- Cross-dialect timing probes ----
  { code: "sql.time-dos", severity: "high", kind: "time-sleep",
    family: "timing", dialect: "cross",
    re: _re("\\b(?:SLEEP|pg_sleep|BENCHMARK|GET_LOCK)\\s*\\("),
    reason: "time-based blind probe / DoS (SLEEP / pg_sleep / BENCHMARK / GET_LOCK)" },
  { code: "sql.time-dos", severity: "high", kind: "time-waitfor",
    family: "timing", dialect: "mssql",
    re: _re("\\bWAITFOR\\s+DELAY\\b"),
    reason: "WAITFOR DELAY time-based blind probe" },

  // ---- Schema recon ----
  { code: "sql.privilege-pivot", severity: "high", kind: "schema-recon",
    family: "recon", dialect: "cross",
    re: _re("\\b(?:information_schema|performance_schema|pg_catalog|sys)\\s*\\.|\\bmysql\\s*\\.\\s*[a-z_]+"),
    reason: "schema / catalog enumeration (recon)" },
];

// UNION/INTERSECT/EXCEPT set operation — handled as its own detector
// because it is the floor only in fragment mode (a value expression has
// no business carrying a set operation) and exfil-class otherwise.
var SETOP_RE = _re("\\b(?:UNION(?:\\s+ALL)?|INTERSECT|EXCEPT)\\b");

// ---- Profile presets ----
//
// Each profile declares the ACTION for every dangerous family:
//   refuse     — flip ok:false, action:refuse.
//   audit      — keep ok:true, surface the issue, emit audit.
//   serve      — ignore (no profile uses this for a dangerous family;
//                a clean stream serves implicitly).
// The floor families are NEVER serve/audit at any profile — every
// profile sets them to "refuse" (encoded explicitly so the table is
// self-documenting and the validator can't silently drop one).

var PROFILES = Object.freeze({
  strict: {
    floor:    "refuse",
    rceFile:  "refuse",
    fdw:      "refuse",
    privPivot:"refuse",
    stacked:  "refuse",
    comment:  "refuse",
    literal:  "refuse",
    encoding: "refuse",
    recon:    "refuse",
    timing:   "refuse",
    setop:    "refuse",
    allowComments: false,
    allowMultiStatement: false,
  },
  balanced: {
    floor:    "refuse",
    rceFile:  "refuse",
    fdw:      "refuse",
    privPivot:"refuse",
    stacked:  "refuse",
    comment:  "refuse",
    literal:  "refuse",
    encoding: "refuse",
    recon:    "audit",
    timing:   "audit",
    setop:    "audit",
    allowComments: false,
    allowMultiStatement: false,
  },
  permissive: {
    // permissive audits the keyword families but STILL hard-refuses the
    // structurally-unambiguous classes (floor + stacked + invalid
    // encoding). The OS-reach floor never relaxes.
    floor:    "refuse",
    rceFile:  "audit",
    fdw:      "audit",
    privPivot:"audit",
    stacked:  "refuse",
    comment:  "audit",
    literal:  "audit",
    encoding: "refuse",
    recon:    "audit",
    timing:   "audit",
    setop:    "audit",
    allowComments: true,
    allowMultiStatement: false,
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  contextMode:  DEFAULT_CONTEXT_MODE,
  maxBytes:     C.BYTES.bytes(1048576),                                 // 1 MiB raw-SQL cap
  maxRuntimeMs: C.TIME.seconds(5),
  // gdprRedact controls whether the audited fragment body is replaced
  // by a salted hash fingerprint (set by the gdpr posture overlay).
  gdprRedact:   false,
});

// All four postures map to the strict floor — a regulated deployment
// gets the tightest raw-SQL gate regardless of which framework it cites.
// gdpr additionally redacts the fragment body in the audit trail
// (a whereRaw predicate may carry personal data).
var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     Object.assign({}, PROFILES.strict),
  "pci-dss": Object.assign({}, PROFILES.strict),
  gdpr:      Object.assign({}, PROFILES.strict, { gdprRedact: true }),
  soc2:      Object.assign({}, PROFILES.strict),
});

// ---- Opts resolution ----

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardSqlError,
    errCodePrefix:      "sql",
  });
}

function _resolveContextMode(opts, ctxMode) {
  var mode = ctxMode || (opts && opts.contextMode) || DEFAULT_CONTEXT_MODE;
  if (CONTEXT_MODES.indexOf(mode) === -1) {
    throw _err("sql.bad-opt",
      "guardSql: contextMode must be one of " + CONTEXT_MODES.join("/") +
      ", got " + JSON.stringify(mode));
  }
  return mode;
}

// ---- Stage 1: encoding gate ----
//
// Reject bytes that fail UTF-8 validation (the libpq client-encoding
// bypass class, CVE-2025-1094) and bytes that decode to a valid string
// but contain a non-shortest / surrogate / invalid-continuation
// sequence. A byte sequence that round-trips through Buffer.toString
// with a replacement char (U+FFFD) lost information — refuse rather
// than scan a lossy decode. High-bit bytes are refused in the ASCII SQL
// context: a SQL keyword / metacharacter is always 7-bit, so any
// high-bit byte outside a (masked) literal is either an encoding-bypass
// attempt or belongs inside a string the operator should bind, not
// embed.

function _encodingIssue(input) {
  var buf;
  if (Buffer.isBuffer(input)) {
    buf = input;
  } else if (typeof input === "string") {
    buf = Buffer.from(input, "utf8");
  } else {
    // Refuse non-string / non-Buffer explicitly — never String()-coerce a
    // number/object/null into bytes (that silently fabricates input and
    // hides a caller-shape bug). The guard inspects SQL TEXT only.
    return _bad("input is not a string or Buffer");
  }

  // Non-shortest / invalid lead+continuation scan (mirrors the
  // guard-filename overlong-UTF-8 byte walk, extended to the full
  // invalid-sequence class the libpq bypass relies on).
  for (var i = 0; i < buf.length; i += 1) {
    var b0 = buf[i];
    if (b0 < 0x80) continue;                                            // ASCII — always fine
    // 0xC0 / 0xC1 can only encode an overlong ASCII byte; 0xF5..0xFF
    // are above the Unicode max code point. Both are always invalid.
    if (b0 === 0xC0 || b0 === 0xC1 || b0 >= 0xF5) {
      return _bad("non-shortest / out-of-range UTF-8 lead byte 0x" + b0.toString(16));
    }
    var need, lo, hi;
    if (b0 >= 0xF0) { need = 3; lo = (b0 === 0xF0) ? 0x90 : 0x80; hi = (b0 === 0xF4) ? 0x8F : 0xBF; }
    else if (b0 >= 0xE0) { need = 2; lo = (b0 === 0xE0) ? 0xA0 : ((b0 === 0xED) ? 0x80 : 0x80); hi = (b0 === 0xED) ? 0x9F : 0xBF; }
    else if (b0 >= 0xC2) { need = 1; lo = 0x80; hi = 0xBF; }
    else { return _bad("stray continuation byte 0x" + b0.toString(16)); }
    if (i + need >= buf.length) return _bad("truncated multibyte UTF-8 sequence");
    // First continuation byte has the range bounds (catches non-shortest
    // E0/F0 and the surrogate range ED); the rest are plain 0x80..0xBF.
    var c1 = buf[i + 1];
    if (c1 < lo || c1 > hi) return _bad("invalid UTF-8 continuation byte 0x" + c1.toString(16));
    for (var k = 2; k <= need; k += 1) {
      var ck = buf[i + k];
      if (ck < 0x80 || ck > 0xBF) return _bad("invalid UTF-8 continuation byte 0x" + ck.toString(16));
    }
    i += need;
  }

  // Replacement-char belt-and-suspenders: a clean decode never emits
  // U+FFFD unless the operator literally typed one (rare in SQL); the
  // byte walk above is the authoritative check, this just catches a
  // decode that lost information through some path the walk missed.
  // The marker codepoint is composed numerically so the source file
  // embeds no non-ASCII attack/marker character as a literal.
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

// ---- Stage 2: normalizer ----
//
// Produce a token stream the detectors run on:
//   - Strip -- line comments, # MySQL line comments, /* */ block
//     comments. An unterminated /* and the executable /*! form are
//     flagged before stripping (returned as signals).
//   - Mask string-literal ('...'), double-quoted-identifier ("..."),
//     backtick-identifier (`...`), and Postgres dollar-quote
//     ($tag$...$tag$) spans to spaces so a keyword inside data never
//     fires a detector.
//   - Collapse an intra-keyword comment: `LOAD/**/_FILE` -> `LOAD_FILE`
//     by removing the comment with NO separating space when both
//     neighbors are identifier characters (so the engine's own token
//     fusion is reproduced for the detector).
//
// Returns { normalized, signals } where signals carries the comment /
// literal flags the detectors / floor need.

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
  };
  var i = 0;
  while (i < n) {
    var ch = text.charAt(i);
    var cc = text.charCodeAt(i);
    var next = i + 1 < n ? text.charAt(i + 1) : "";

    // -- line comment.
    if (cc === CP_DASH && next === "-") {
      signals.hadComment = true;
      _collapseOrSpace(out, text, i);
      var nl = text.indexOf("\n", i + 2);
      i = nl === -1 ? n : nl + 1;
      continue;
    }
    // # MySQL line comment.
    if (cc === CP_HASH) {
      signals.hadComment = true;
      _collapseOrSpace(out, text, i);
      var nl2 = text.indexOf("\n", i + 1);
      i = nl2 === -1 ? n : nl2 + 1;
      continue;
    }
    // /* block comment (incl. executable /*! ... */).
    if (cc === CP_SLASH && next === "*") {
      signals.hadComment = true;
      if (i + 2 < n && text.charCodeAt(i + 2) === CP_BANG) {
        signals.hadExecutableComment = true;
      }
      var end = text.indexOf("*/", i + 2);
      if (end === -1) {
        signals.unterminatedComment = true;
        i = n;                                                          // consume rest; floor refuses on the signal
        continue;
      }
      _collapseOrSpace(out, text, i, end + 2);
      i = end + 2;
      continue;
    }
    // ' string literal — mask body to spaces.
    if (cc === CP_SQUOTE) {
      signals.hadLiteral = true;
      out.push(MASK_SPACE);
      i += 1;
      while (i < n) {
        if (text.charCodeAt(i) === CP_SQUOTE) {
          if (i + 1 < n && text.charCodeAt(i + 1) === CP_SQUOTE) {      // '' escaped quote
            out.push(MASK_SPACE); out.push(MASK_SPACE); i += 2; continue;
          }
          out.push(MASK_SPACE); i += 1; break;
        }
        out.push(MASK_SPACE); i += 1;
        if (i >= n) { signals.unterminatedLiteral = true; }
      }
      continue;
    }
    // " double-quoted identifier — mask to spaces (identifier, not a
    // keyword; masking prevents a keyword-shaped column name firing).
    if (cc === CP_DQUOTE) {
      out.push(MASK_SPACE);
      i += 1;
      while (i < n) {
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
    // ` backtick identifier (MySQL) — mask to spaces.
    if (cc === CP_BACKTICK) {
      out.push(MASK_SPACE);
      i += 1;
      while (i < n) {
        if (text.charCodeAt(i) === CP_BACKTICK) { out.push(MASK_SPACE); i += 1; break; }
        out.push(MASK_SPACE); i += 1;
      }
      continue;
    }
    // $tag$ dollar-quote — mask body. A bare $N placeholder ($1, $$) is
    // NOT a dollar-quote unless a closing $tag$ exists.
    if (cc === CP_DOLLAR) {
      var tagEnd = i + 1;
      while (tagEnd < n && _isWordByte(text.charAt(tagEnd))) tagEnd += 1;
      if (tagEnd < n && text.charCodeAt(tagEnd) === CP_DOLLAR) {
        var tag = text.slice(i, tagEnd + 1);
        var closeTag = text.indexOf(tag, tagEnd + 1);
        if (closeTag === -1) {
          // Unterminated dollar-quote — treat as an unterminated literal
          // (floor refuses).
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
      // Bare $ (placeholder marker / stray) — keep it so detectors that
      // care about $ (DO $$) still see it; it's a single ASCII byte.
      out.push(ch);
      i += 1;
      continue;
    }
    out.push(ch);
    i += 1;
  }
  return { normalized: out.join(""), signals: signals };
}

// Word byte for the dollar-quote tag (letters / digits / underscore,
// NOT the dollar itself).
function _isWordByte(ch) {
  return (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") ||
         (ch >= "0" && ch <= "9") || ch === "_";
}

// When removing a comment, fuse the neighbors with NO space if both
// sides are identifier bytes (reproduce the engine's token fusion:
// `LOAD/**/_FILE` -> `LOAD_FILE`), otherwise emit a single space so
// unrelated tokens don't merge. `end` defaults to one-past for line
// comments where the caller advances separately.
function _collapseOrSpace(out, text, start, end) {
  var prev = out.length > 0 ? out[out.length - 1] : "";
  var prevByte = prev.length > 0 ? prev.charAt(prev.length - 1) : "";
  var afterIdx = typeof end === "number" ? end : start;               // line comments: neighbor checked at strip site
  var nextByte = afterIdx < text.length ? text.charAt(afterIdx) : "";
  if (prevByte && nextByte && _isIdentByte(prevByte) && _isIdentByte(nextByte)) {
    // Fuse — emit nothing (the two identifier runs join).
    return;
  }
  out.push(MASK_SPACE);
}

// ---- Stage 3: structural scans on the normalized stream ----

// Top-level statement-separator scan: count `;` that are NOT the final
// trailing terminator. The normalizer already masked literals/comments,
// so every `;` in the normalized stream is a real separator.
function _stackedStatementIssue(normalized) {
  var n = normalized.length;
  var firstSemi = -1;
  for (var i = 0; i < n; i += 1) {
    if (normalized.charCodeAt(i) !== CP_SEMI) continue;
    firstSemi = i;
    break;
  }
  if (firstSemi === -1) return null;
  // Anything other than whitespace after the first top-level `;` is a
  // second statement.
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

// Leading verb of the normalized stream (skips leading whitespace).
function _leadingVerb(normalized) {
  var n = normalized.length;
  var i = 0;
  while (i < n) {
    var ch = normalized.charAt(i);
    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n" ||
        ch === "(" ) { i += 1; continue; }
    break;
  }
  var start = i;
  while (i < n && _isWordByte(normalized.charAt(i))) i += 1;
  return normalized.slice(start, i).toUpperCase();
}

// Split the normalized stream into top-level statements on `;`. Used by
// migration mode to re-classify each statement. The normalizer already
// masked literals/comments so splitting on `;` is safe.
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

// ---- Detector application ----

function _profileActionFor(family, profile) {
  switch (family) {
  case "floor":    return profile.floor;
  case "rce-file": return profile.rceFile;
  case "fdw":      return profile.fdw;
  case "recon":    return profile.recon;
  case "timing":   return profile.timing;
  case "exfil":    return profile.setop;
  default:         return "refuse";
  }
}

// Map a detector's declared family onto the profile decision. The floor
// family is always refuse; the rce-file / fdw / priv-pivot constructs
// listed under "floor" stay floor (irreducible), while the recon /
// timing families soften per profile.
function _decideDetector(det, profile) {
  // The DETECTORS table marks the irreducible OS-reach constructs
  // family:"floor" directly, so this honors that. recon / timing have
  // their own family.
  var fam = det.family;
  if (fam === "floor") return profile.floor;          // always "refuse"
  if (fam === "recon") return profile.recon;
  if (fam === "timing") return profile.timing;
  return profile.privPivot;                            // defensive default
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

// ---- Core inspection ----
//
// Runs the three stages and returns a structured issues array. Pure —
// never throws on input shape (the gate / validate wrappers decide how
// to surface refusals).

function _inspect(input, opts, contextMode) {
  var issues = [];

  // Stage 1 — encoding gate (on raw bytes, before any decode-dependent
  // scan). Always refuse a bad encoding regardless of profile when the
  // profile sets encoding:"refuse" (every shipped profile does).
  var encIssue = _encodingIssue(input);
  if (encIssue) {
    // Invalid encoding is structurally unambiguous — refuse at every
    // profile (encoding:"refuse" in strict/balanced/permissive).
    issues.push(encIssue);
    // A lossy/invalid decode can't be safely scanned further; return now.
    return issues;
  }

  var text = Buffer.isBuffer(input) ? input.toString("utf8") : String(input);

  // Size cap (post-decode char length is a fine proxy; the byte cap is
  // the operator-facing number).
  var byteLen = Buffer.byteLength(text, "utf8");
  if (opts.maxBytes && byteLen > opts.maxBytes) {
    issues.push({
      code: "sql.refuse", severity: "high", kind: "oversize",
      ruleId: "sql.oversize",
      snippet: "raw SQL " + byteLen + " bytes exceeds maxBytes " + opts.maxBytes,
    });
  }

  // Stage 2 — normalize.
  var norm = _normalize(text);
  var normalized = norm.normalized;
  var sig = norm.signals;

  // Comment-smuggling floor: unterminated /* and executable /*! refuse
  // at every profile.
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
  // Ordinary comments under strict/balanced (comment:"refuse") refuse;
  // permissive (comment:"audit") + migration (allowComments) surface
  // as a warn.
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

  // Quoted-identifier hygiene — a double-quoted identifier carrying a
  // newline or leading backslash is the CVE-2025-8715 class (a crafted
  // identifier breaks out of a downstream psql / pg_dump restore line).
  // Each quoted-identifier span delegates to safeSql.validateIdentifier
  // so the refusal shares the framework's single identifier-shape
  // authority rather than a second copy of the rules.
  issues.push.apply(issues, _identifierHygieneIssues(text));

  // Stage 3 — structural + keyword detectors on the normalized stream.

  // Stacked statements — floor under every profile EXCEPT migration
  // (which permits multiple statements but still classifies each).
  if (contextMode !== "migration") {
    var stackedIssue = _stackedStatementIssue(normalized);
    if (stackedIssue) issues.push(stackedIssue);
  }

  // Keyword detectors (file / exec / fdw / priv-pivot / recon / timing).
  issues.push.apply(issues, _runDetectors(normalized, opts));

  // Leading-verb floor — a statement that LEADS with a procedural-
  // execution verb (DO anonymous block, CALL / EXECUTE a routine) is a
  // floor refusal at every profile: operator SQL never legitimately
  // runs an anonymous code body or invokes a stored routine through the
  // raw-SQL surface, and the DO body is masked by the dollar-quote
  // normalizer so a token detector can't see into it. Checked per
  // top-level statement so a migration's second `CALL` is caught too.
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

  // Set-operation handling — floor in fragment mode, exfil-family
  // (profile-decided) otherwise.
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

  // Context-mode structural rules.
  if (contextMode === "fragment") {
    _inspectFragment(text, normalized, opts, issues);
  } else if (contextMode === "operator-sql") {
    _inspectOperatorSql(normalized, issues);
  } else if (contextMode === "migration") {
    _inspectMigration(normalized, opts, issues);
  }

  return issues;
}

// Fragment mode — the bytes must be a bare value expression: no
// statement-introducing verb, no embedded string literal (delegated to
// the db-query raw-scanner shape via _assertNoEmbeddedLiteral), no
// top-level semicolon (already covered by the stacked scan).
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
  // Embedded string literal — a fragment is a STATIC template; every
  // value binds through a ? placeholder. An embedded '...' is the
  // signature of operator input concatenated into the builder (CWE-89).
  // Operators with a deliberate static literal pass allowLiterals.
  if (!opts.allowLiterals && _hasEmbeddedStringLiteral(rawText)) {
    issues.push({
      code: "sql.embedded-literal", severity: "critical", kind: "embedded-literal",
      ruleId: "sql.embedded-literal",
      snippet: "raw fragment embeds a string literal ('...') — bind every value " +
               "with a ? placeholder, or pass allowLiterals:true for a static literal",
    });
  }
}

// operator-sql mode — exactly one statement (stacked scan already
// enforces single-statement). No additional structural rule beyond the
// floor + keyword detectors; classification is informational here.
function _inspectOperatorSql(normalized, issues) {
  var verb = _leadingVerb(normalized);
  // No verb at all (empty / parenthesized-only) is not inherently
  // unsafe, but an unresolvable statement on the operator path is
  // surfaced as info so the audit trail is complete.
  if (!verb) {
    issues.push({
      code: "sql.refuse", severity: "warn", kind: "no-verb", action: "audit",
      ruleId: "sql.no-verb",
      snippet: "operator-sql has no resolvable leading verb",
    });
  }
}

// migration mode — multiple statements + comments permitted (audited);
// each statement re-classified. Only DDL verbs + reads pass; an
// unmapped / write-with-side-effect verb that is not a plain DML or DDL
// refuses. The OS-reach floor was already applied across the whole
// stream by the keyword detectors.
function _inspectMigration(normalized, opts, issues) {
  var statements = _splitStatements(normalized);
  for (var i = 0; i < statements.length; i += 1) {
    var verb = _leadingVerb(statements[i]);
    if (!verb) continue;                                              // blank / comment-only fragment
    if (MIGRATION_DDL_VERBS[verb] === true) continue;                // allowed DDL
    if (MIGRATION_READ_VERBS[verb] === true) continue;               // read / DML / tx
    // CREATE INDEX is a CREATE (already allowed); a verb outside both
    // allowlists in a migration is refused (e.g. ATTACH, PRAGMA,
    // CALL, DO, COPY, GRANT, SET ROLE — most are also floor-caught,
    // this catches the residue).
    issues.push({
      code: "sql.refuse", severity: "critical", kind: "migration-verb",
      ruleId: "sql.migration-verb",
      snippet: "statement verb " + JSON.stringify(verb) +
               " not in the migration DDL allowlist (CREATE / ALTER / DROP / reads)",
    });
  }
}

// Embedded-string-literal scan — the db-query `_assertRawNoStringLiteral`
// shape (quote / comment-aware), returning a boolean instead of
// throwing so the fragment inspector can fold it into the issues array.
// Shares the scanning shape with the db-query raw-scanner; both refuse a
// single-quoted literal in a fragment that should be a static template.
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
    i += 1;
  }
  return false;
}

// Quoted-identifier hygiene scan — pull every double-quoted identifier
// span and refuse the CVE-2025-8715 class: a newline / carriage return
// (breaks out of a downstream psql restore line) or a leading backslash
// (escape-sequence smuggling). A null byte in an identifier is also
// refused. Returns an issues array. Spans are extracted with the same
// quote-aware walk the normalizer uses, so a `"` inside a string
// literal is never mistaken for an identifier delimiter.
function _identifierHygieneIssues(sql) {
  var issues = [];
  var i = 0;
  var len = sql.length;
  while (i < len) {
    var ch = sql.charCodeAt(i);
    // Skip string literals so a `"` inside '...' is data, not an ident
    // delimiter.
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

// Classify a quoted-identifier body. Newline / CR / leading backslash /
// null byte are the CVE-2025-8715 break-out shapes. The framework's
// identifier-shape authority (safeSql.validateIdentifier) is the source
// of truth for what a clean identifier is — a body that contains a
// control byte fails it, so this routes the control-byte verdict
// through safeSql rather than maintaining a second copy of the rule.
function _identifierHazard(ident) {
  if (ident.indexOf("\n") !== -1 || ident.indexOf("\r") !== -1) {
    return "contains a newline";
  }
  if (ident.charAt(0) === "\\") {
    return "starts with a backslash";
  }
  // Any C0 control / DEL byte in a quoted identifier is a break-out
  // hazard. The null byte is the sharpest case (it terminates a C
  // string in a downstream client), so call it out explicitly; the
  // rest are reported by code point.
  for (var k = 0; k < ident.length; k += 1) {
    var c = ident.charCodeAt(k);
    if (codepointClass.isForbiddenControlChar(c, { forbidTab: true })) {
      return c === 0 ? "contains a null byte"
                     : "contains a control byte 0x" + c.toString(16);
    }
  }
  // Delegate the residual identifier-shape verdict to the framework's
  // single identifier authority. A quoted identifier may legitimately
  // be a reserved word or contain spaces / mixed case, so allow those;
  // safeSql still refuses an over-length name or one with an embedded
  // null, keeping one source of truth for the shape rules rather than a
  // second copy here. A thrown SafeSqlError means the identifier is the
  // CVE-2025-8715 break-out shape under safeSql's rules.
  try {
    safeSql.validateIdentifier(ident, { allowReserved: true, allowSqliteInternal: true });
  } catch (e) {
    if (e instanceof safeSql.SafeSqlError &&
        (e.code === "sql/too-long" || e.code === "sql/null-byte")) {
      return "rejected by safeSql.validateIdentifier (" + e.code + ")";
    }
    // Other safeSql verdicts (bad-shape from a legitimate dotted /
    // spaced / punctuated quoted identifier) are NOT a break-out hazard
    // — a quoted identifier deliberately escapes the bare-identifier
    // shape. Only the control-byte + over-length + null classes above
    // are the CVE break-out surface.
  }
  return null;
}

// ---- Public surface ----

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
  // "bytes" contract — accept string/Buffer and pass it RAW: _inspect runs an
  // encoding gate on raw bytes before any decode, so coercing to text first
  // would hide the very bytes it checks. The closure binds contextMode.
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
    throw _err("sql.bad-input", "sanitize requires string or Buffer input");
  }
  var issues = _inspect(input, opts, contextMode);
  var refusal = _firstRefusal(issues);
  if (refusal) {
    throw _err(refusal.code, "guardSql.sanitize: " + refusal.snippet);
  }
  var text = Buffer.isBuffer(input) ? input.toString("utf8") : String(input);
  return _normalize(text).normalized;
}

// Return the first issue that flips the result to refuse (critical /
// high severity, or an explicit action:"refuse"), or null.
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

      // Signed audit on every decision (PCI-DSS 10.2 / SOC 2 CC7). Under
      // gdpr the SQL body is replaced with a salted hash fingerprint.
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

// Emit a signed audit entry for a gate decision. Drop-silent inside the
// try/catch — an audit-sink failure must never crash the request whose
// SQL triggered it (hot-path observability discipline).
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

// Salted hash fingerprint of a SQL body for the gdpr audit path — a
// stable identifier that never carries the plaintext predicate (which
// may contain personal data). SHA3 via the framework crypto primitive;
// 16 hex chars (64 bits) is ample for correlation.
function _fingerprint(text) {
  return "sha3:" + bCrypto.sha3Hash(Buffer.from(text, "utf8"), "hex").slice(0, 16);
}

var AUDIT_SNIPPET_CHARS = 200;
function _truncateForAudit(text) {
  return text.length > AUDIT_SNIPPET_CHARS
    ? text.slice(0, AUDIT_SNIPPET_CHARS) + "...(truncated)" : text;
}

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below — their wiki sections render from the
// single-sourced @abiTemplate blocks in gate-contract.js.

// ---- adaptive integration-test fixtures (consumed by layer-5 host harness) ----
var INTEGRATION_FIXTURES = Object.freeze({
  kind:        "sql",
  // Benign: a parameterized predicate fragment — every value bound,
  // no statement verb (the default fragment-mode shape, e.g. whereRaw).
  benignSql:   "id = ? AND status = ?",
  // Hostile: a stacked statement (CWE-89 class) — refused at every
  // profile by the irreducible floor.
  hostileSql:  "id = 1; DROP TABLE users",
});

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / INTEGRATION_FIXTURES), buildProfile /
// compliancePosture / loadRulePack wiring, plus the per-guard inspection
// surface (validate / sanitize / bespoke gate) and SQL extras
// (CONTEXT_MODES / DETECTORS) passed through verbatim. The custom KIND
// ("sql") is accepted because the bespoke gate reads its own ctx fields
// (ctx.sql / ctx.bytes).
//
// Raw SQL is a non-content axis (operators apply it to whereRaw /
// operator-SQL / migration strings, not to a request body routed by
// Content-Type), so guard-sql is a STANDALONE primitive — it does NOT
// register into b.guardAll's content-type-routed dispatch. The
// MIME_TYPES / EXTENSIONS exports describe the media class (so a host
// that DOES carry SQL as an upload can find this guard by type) but the
// registration in lib/guard-all.js is STANDALONE_GUARDS, and the
// integration harness routes it through the ctx.sql dispatcher. They
// ride in `extra` (not the factory's content-kind MIME/EXTENSIONS path,
// which keys off KIND === "content").
module.exports = gateContract.defineGuard({
  name:        "sql",
  kind:        "sql",                                          // raw-SQL guard (consumes ctx.sql)
  errorClass:  GuardSqlError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  validate:    validate,
  sanitize:    sanitize,
  gate:        gate,
  extra: {
    MIME_TYPES:    Object.freeze(["application/sql"]),
    EXTENSIONS:    Object.freeze([".sql"]),
    CONTEXT_MODES: CONTEXT_MODES,
    DETECTORS:     Object.freeze(DETECTORS.slice()),
  },
});
