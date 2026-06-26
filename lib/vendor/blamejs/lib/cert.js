"use strict";
/**
 * @module b.cert
 * @nav    Production
 * @title  Certificates
 * @order  130
 *
 * @intro
 *   Turnkey TLS-certificate manager. Wraps `b.acme.create` (RFC 8555
 *   client + RFC 9773 ARI renewal-window respect), sealed persistence
 *   via `b.vault.seal`, the renewal scheduler from `b.safeAsync.repeating`,
 *   OCSP-stapling via `b.network.tls.ocsp`, and the operator's choice
 *   of ACME challenge solver (HTTP-01 / DNS-01 / TLS-ALPN-01).
 *
 *   The operator passes a declarative manifest of certificates +
 *   storage + an ACME directory URL + per-challenge solver callbacks;
 *   the manager handles ordering, finalization, retrieval, periodic
 *   renewal, key rotation on renew, OCSP refresh, and sealed-disk
 *   persistence of every artifact.
 *
 *   Composes:
 *     - `b.acme.create`         → ACME orders, JWS, ARI fetch
 *     - `b.vault.seal`          → sealed-disk persistence of certs + keys + account material
 *     - `b.safeAsync.repeating` → renewal scheduler with drop-silent error path
 *     - `b.network.tls.ocsp`    → fetches + caches a validated OCSP response per cert for server-side stapling
 *     - `b.audit`               → cert.* lifecycle audit chain
 *     - `b.compliance`          → validates the declared posture names; storage-confidentiality postures hold because keys/certs are always sealed at rest
 *
 *   Does NOT ship the challenge-solver implementations (HTTP-01 server,
 *   DNS provider integrations, TLS-ALPN-01 socket). Those are operator-
 *   side adapters — the manager calls operator-provided
 *   `provision(challengeParams)` / `cleanup(challengeParams)` callbacks
 *   for whatever solver the operator wires.
 *
 *   Key escrow: when `keyEscrow: { recipient }` is set, the renewed
 *   private key is also encrypted to the recipient's public key via
 *   `b.crypto.encryptEnvelope` and persisted alongside the sealed key.
 *   The recipient is operator-controlled (typically an offline
 *   break-glass key); the escrow copy is for legitimate key-recovery
 *   under break-glass policy, NOT for routine access.
 *
 * @card
 *   ACME-driven cert lifecycle: auto-renew + key rotation + OCSP stapling + sealed persistence.
 */

var nodeCrypto    = require("node:crypto");
var nodeFs        = require("node:fs");
var nodePath      = require("node:path");
var EventEmitter  = require("node:events").EventEmitter;
var validateOpts  = require("./validate-opts");
var lazyRequire   = require("./lazy-require");
var safeAsync     = require("./safe-async");
var atomicFile    = require("./atomic-file");
var safeJson      = require("./safe-json");
var { defineClass } = require("./framework-error");
var C             = require("./constants");
var { boot }      = require("./log");

var acme          = lazyRequire(function () { return require("./acme"); });
var vault         = lazyRequire(function () { return require("./vault"); });
var audit         = lazyRequire(function () { return require("./audit"); });
var networkTls    = lazyRequire(function () { return require("./network-tls"); });
var compliance    = lazyRequire(function () { return require("./compliance"); });
var bCrypto       = lazyRequire(function () { return require("./crypto"); });

var CertError = defineClass("CertError");
var log = boot("cert");

var DEFAULT_RENEW_INTERVAL_MS    = C.TIME.hours(6);
var DEFAULT_MIN_DAYS_BEFORE_EXPIRY = 14;
var DEFAULT_OCSP_REFRESH_MS      = C.TIME.hours(12);
var MAX_DOMAINS_PER_CERT         = 100;                                              // operator-facing manifest size cap, not a byte count (RFC 6066 SNI permits more)
var MAX_CERTS_PER_MANAGER        = 1000;                                             // operator-facing manifest size cap, not a byte count

function _positiveFiniteOrDefault(value, defaultValue, label, code) {
  if (value === undefined || value === null) return defaultValue;
  if (typeof value !== "number" || !isFinite(value) || value <= 0) {
    throw new CertError(code, label + " must be a positive finite number (got " + value + ")");
  }
  return value;
}

// ---- Storage backend ----

// Sealed-disk storage: each artifact (cert PEM, key PEM, ACME account
// JWK, OCSP response) is sealed via b.vault.seal and written atomically
// to a per-cert subdirectory under storage.rootDir.
//
// Layout:
//   <rootDir>/account/jwk.json.sealed     — sealed ACME account key
//   <rootDir>/account/jwk.json.escrow     — optional break-glass copy (if keyEscrow set)
//   <rootDir>/<certName>/cert.pem.sealed  — sealed certificate chain (CA + leaf)
//   <rootDir>/<certName>/key.pem.sealed   — sealed leaf private key
//   <rootDir>/<certName>/key.pem.escrow   — optional break-glass copy
//   <rootDir>/<certName>/ocsp.der.sealed  — sealed cached OCSP response (refreshed periodically)
//   <rootDir>/<certName>/meta.json        — plaintext metadata (expiresAt, fingerprint, last-renewed-at)
function _createSealedDiskStorage(opts) {
  validateOpts.requireNonEmptyString(opts.rootDir,
    "cert.storage: rootDir (sealed-disk root directory) is required",
    CertError, "cert/bad-storage-root");
  var rootDir = nodePath.resolve(opts.rootDir);
  var vaultStore = opts.vault || vault().getDefaultStore();
  validateOpts.requireMethods(vaultStore, ["seal", "unseal"],
    "cert.storage: vault (typically b.vault.getDefaultStore())", CertError, "cert/bad-storage-vault");

  function _ensureDir(dir) { atomicFile.ensureDir(dir); }
  function _certDir(name)  { return nodePath.join(rootDir, name); }
  function _accountDir()    { return nodePath.join(rootDir, "account"); }

  return {
    type: "sealed-disk",
    rootDir: rootDir,

    async writeSealed(relPath, contents) {
      // Sealed artifacts always carry the `.sealed` suffix so a
      // directory listing instantly distinguishes encrypted material
      // from plaintext meta.json. relPath is the logical name (e.g.
      // "main/cert.pem"); the on-disk path is "main/cert.pem.sealed".
      var p = nodePath.join(rootDir, relPath + ".sealed");
      _ensureDir(nodePath.dirname(p));
      var sealed = vaultStore.seal(Buffer.from(contents));
      atomicFile.writeSync(p, sealed, { mode: 0o600 });
    },

    async readSealed(relPath) {
      var p = nodePath.join(rootDir, relPath + ".sealed");
      if (!nodeFs.existsSync(p)) return null;
      // Cap + fd-bound (sealed cert/key envelope is well under 256 KiB). NO
      // refuseSymlink: the sealed store may be operator-mounted.
      var sealed = atomicFile.fdSafeReadSync(p, { maxBytes: C.BYTES.kib(256) });
      var plain = vaultStore.unseal(sealed);
      return Buffer.isBuffer(plain) ? plain : Buffer.from(plain);
    },

    async writeMeta(certName, meta) {
      var p = nodePath.join(_certDir(certName), "meta.json");
      _ensureDir(_certDir(certName));
      atomicFile.writeSync(p, JSON.stringify(meta, null, 2) + "\n", { mode: 0o644 });
    },

    async readMeta(certName) {
      var p = nodePath.join(_certDir(certName), "meta.json");
      if (!nodeFs.existsSync(p)) return null;
      try { return safeJson.parse(atomicFile.fdSafeReadSync(p, { maxBytes: C.BYTES.kib(16), encoding: "utf8" }), { maxBytes: C.BYTES.kib(16) }); }
      catch (e) {
        // meta.json is a derived index (expiry + fingerprint), not a
        // source of truth — the sealed cert is. A corrupt meta must not
        // block renewal: treat it as absent so _ensureCert re-derives it
        // from a fresh issue rather than throwing out of start().
        log.warn("cert: meta.json for '" + certName + "' unreadable (" +
          e.message + ") — treating as absent, will re-derive");
        return null;
      }
    },

    async writeEscrow(relPath, plaintextKeyPem, recipientPub) {
      // Encrypt-to-recipient via b.crypto.encryptEnvelope. Recipient is
      // an X25519 / ML-KEM hybrid pubkey held offline by the operator
      // for break-glass key recovery.
      var envelope = bCrypto().encryptEnvelope(Buffer.from(plaintextKeyPem), recipientPub);
      var p = nodePath.join(rootDir, relPath);
      _ensureDir(nodePath.dirname(p));
      atomicFile.writeSync(p, JSON.stringify(envelope) + "\n", { mode: 0o600 });
    },
  };
}

// ---- Cert manager factory ----

/**
 * @primitive b.cert.create
 * @signature b.cert.create(opts)
 * @since     0.11.22
 * @status    stable
 * @related   b.acme.create
 *
 * Build a turnkey cert-management handle. Composes `b.acme.create` for
 * the ACME protocol layer, `b.vault.seal` for sealed-disk persistence,
 * `b.safeAsync.repeating` for the renewal scheduler, and
 * `b.network.tls.ocsp` for stapling.
 *
 * The handle exposes:
 *   - `start()`           — ensures every manifest cert exists (issues if absent); starts the renewal scheduler.
 *   - `stop()`            — halts the renewal scheduler; releases sealed handles.
 *   - `getContext(name)`  — returns `{ cert, key, ca, expiresAt, fingerprintSha256 }` (PEM strings + meta) for the named cert.
 *   - `sniCallback`       — function (servername, cb) suitable for `https.createServer({ SNICallback })` — looks up by SNI hostname, falls back to the first registered cert.
 *   - `refresh(name)`     — force-renew the named cert NOW (operator override).
 *   - `on(event, fn)`     — `cert.issued` / `cert.renewed` / `cert.renew-failed` / `cert.ocsp-refreshed`.
 *
 * @opts
 *   storage: {
 *     type:    "sealed-disk",         // only backend in v1 — operator-supplied storage extensible via the same shape
 *     rootDir: string,                // required — directory under which sealed artifacts land
 *     vault:   b.vault.Store,         // optional — defaults to b.vault.getDefaultStore()
 *   },
 *   acme: {
 *     directory:    string,           // required — RFC 8555 directory URL (https://)
 *     contactEmail: string,           // optional — mailto: contact registered on account
 *     accountKey:   { privatePem, publicPem } | "auto",   // "auto" → generate + persist on first start; sealed via storage.vault
 *     timeoutMs:    number,           // optional — per-HTTP-call timeout; defaults from b.acme.create
 *     ariCompliant: boolean,          // optional, default true — RFC 9773 ARI renewalInfo respect
 *   },
 *   certs: Array<{
 *     name:      string,              // required — unique manifest identifier; used as subdirectory + lookup key
 *     domains:   Array<string>,       // required — first entry is the CN subject; rest are SANs
 *     keyAlg:    "ecdsa-p256" | "ecdsa-p384" | "rsa-2048" | "rsa-3072" | "rsa-4096", // default "ecdsa-p256"
 *     challenge: {
 *       type:      "http-01" | "dns-01" | "tls-alpn-01",
 *       provision: async function (params) { ... },     // required — operator wires the solver
 *       cleanup:   async function (params) { ... },     // required — runs after authorization completes
 *     },
 *     keyEscrow: {                    // optional — break-glass-only key recovery
 *       recipient: Buffer | string,   // X25519 / ML-KEM hybrid public key (b.crypto.encryptEnvelope recipient)
 *     },
 *   }>,
 *   renew: {
 *     intervalMs:          number,    // default 6h — poll cadence
 *     minDaysBeforeExpiry: number,    // default 14 — renew if <N days remaining (or ARI says renew sooner)
 *     ariCompliant:        boolean,   // default true — respect ARI suggestedWindow when CA publishes it
 *   },
 *   ocsp: {
 *     stapling:   boolean,            // default true — refresh + cache OCSP responses for server-side stapling
 *     refreshMs:  number,             // default 12h — OCSP-response cache lifetime
 *   },
 *   audit:    boolean | object,       // default true — emit cert.* lifecycle events via b.audit.safeEmit
 *   compliance: Array<string>,         // optional — posture names (e.g. ["hipaa"]); validated against b.compliance.KNOWN_POSTURES (throws on an unknown name) + surfaced on getContext().compliance. Cert keys/certs are always sealed at rest, so storage-confidentiality postures hold by construction.
 *
 * @example
 *   var mgr = b.cert.create({
 *     storage: { type: "sealed-disk", rootDir: "/var/lib/blamejs/certs" },
 *     acme: {
 *       directory:    "https://acme-v02.api.letsencrypt.org/directory",
 *       contactEmail: "ops@example.com",
 *       accountKey:   "auto",
 *     },
 *     certs: [
 *       {
 *         name:      "main",
 *         domains:   ["example.com", "www.example.com"],
 *         keyAlg:    "ecdsa-p256",
 *         challenge: {
 *           type:      "http-01",
 *           provision: async function (p) { await myHttp01Server.add(p.token, p.keyAuthorization); },
 *           cleanup:   async function (p) { await myHttp01Server.remove(p.token); },
 *         },
 *       },
 *     ],
 *   });
 *   await mgr.start();
 *   var ctx = await mgr.getContext("main");
 *   typeof ctx.cert;     // → "string" (PEM chain)
 *   typeof ctx.key;      // → "string" (PEM)
 *   typeof ctx.expiresAt; // → "number" (epoch ms)
 */
function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw new CertError("cert/bad-opts", "cert.create: opts is required");
  }
  validateOpts(opts, [
    "storage", "acme", "certs", "renew", "ocsp", "audit", "compliance",
  ], "cert.create");

  // ---- Storage ----
  if (!opts.storage || typeof opts.storage !== "object") {
    throw new CertError("cert/bad-storage", "cert.create: storage block is required");
  }
  var storageType = opts.storage.type || "sealed-disk";
  if (storageType !== "sealed-disk") {
    throw new CertError("cert/bad-storage-type",
      "cert.create: storage.type must be 'sealed-disk' (the only backend in v1)");
  }
  var storage = _createSealedDiskStorage(opts.storage);

  // ---- ACME opts ----
  if (!opts.acme || typeof opts.acme !== "object") {
    throw new CertError("cert/bad-acme", "cert.create: acme block is required");
  }
  validateOpts(opts.acme,
    ["directory", "contactEmail", "accountKey", "timeoutMs", "ariCompliant"],
    "cert.create.acme");
  validateOpts.requireNonEmptyString(opts.acme.directory,
    "cert.create.acme: directory (RFC 8555 directory URL) is required",
    CertError, "cert/bad-acme-directory");

  // ---- Cert manifest ----
  if (!Array.isArray(opts.certs) || opts.certs.length === 0) {
    throw new CertError("cert/bad-certs",
      "cert.create: certs must be a non-empty array of cert manifests");
  }
  if (opts.certs.length > MAX_CERTS_PER_MANAGER) {
    throw new CertError("cert/too-many-certs",
      "cert.create: certs array length " + opts.certs.length + " exceeds cap " + MAX_CERTS_PER_MANAGER);
  }
  // Cert names land as filesystem path segments under storage.rootDir
  // (e.g. `<rootDir>/<name>/cert.pem.sealed`). Restrict the character
  // set to ASCII letters / digits / `-` / `_` / `.` and refuse any
  // value containing `/`, `\`, `..`, leading dot, or non-printable
  // chars. Manifests sourced from operator-editable config or external
  // control planes can carry attacker-influenced names; this gate
  // refuses path-traversal payloads at the factory boundary instead
  // of relying on `path.join` to sanitize.
  var CERT_NAME_ALLOWED = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/;
  var certsByName = Object.create(null);
  for (var i = 0; i < opts.certs.length; i += 1) {
    var c = opts.certs[i];
    validateOpts.requireNonEmptyString(c.name,
      "cert.create.certs[" + i + "].name is required",
      CertError, "cert/bad-cert-name");
    if (!CERT_NAME_ALLOWED.test(c.name) || c.name.indexOf("..") !== -1) {
      throw new CertError("cert/bad-cert-name",
        "cert.create.certs[" + i + "].name '" + c.name +
        "' must match [A-Za-z0-9_][A-Za-z0-9_.-]{0,63} and contain no '..' " +
        "(name lands as a filesystem path segment under storage.rootDir)");
    }
    if (certsByName[c.name]) {
      throw new CertError("cert/duplicate-name",
        "cert.create.certs: duplicate name '" + c.name + "'");
    }
    if (!Array.isArray(c.domains) || c.domains.length === 0) {
      throw new CertError("cert/bad-domains",
        "cert.create.certs[" + i + "].domains must be a non-empty array");
    }
    if (c.domains.length > MAX_DOMAINS_PER_CERT) {
      throw new CertError("cert/too-many-domains",
        "cert.create.certs[" + i + "].domains length " + c.domains.length + " exceeds cap " + MAX_DOMAINS_PER_CERT);
    }
    for (var di = 0; di < c.domains.length; di += 1) {
      if (typeof c.domains[di] !== "string" || !c.domains[di]) {
        throw new CertError("cert/bad-domain",
          "cert.create.certs[" + i + "].domains[" + di + "] must be a non-empty string");
      }
    }
    if (!c.challenge || typeof c.challenge !== "object") {
      throw new CertError("cert/bad-challenge",
        "cert.create.certs[" + i + "].challenge is required");
    }
    if (["http-01", "dns-01", "tls-alpn-01"].indexOf(c.challenge.type) === -1) {
      throw new CertError("cert/bad-challenge-type",
        "cert.create.certs[" + i + "].challenge.type must be http-01 / dns-01 / tls-alpn-01");
    }
    if (typeof c.challenge.provision !== "function" ||
        typeof c.challenge.cleanup   !== "function") {
      throw new CertError("cert/bad-challenge-callbacks",
        "cert.create.certs[" + i + "].challenge requires provision + cleanup callbacks");
    }
    var keyAlg = c.keyAlg || "ecdsa-p256";
    if (["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"].indexOf(keyAlg) === -1) {
      throw new CertError("cert/bad-key-alg",
        "cert.create.certs[" + i + "].keyAlg must be ecdsa-p256 / ecdsa-p384 / rsa-2048 / rsa-3072 / rsa-4096");
    }
    if (c.keyEscrow && (!c.keyEscrow.recipient ||
        (typeof c.keyEscrow.recipient !== "string" && !Buffer.isBuffer(c.keyEscrow.recipient)))) {
      throw new CertError("cert/bad-key-escrow",
        "cert.create.certs[" + i + "].keyEscrow.recipient must be a Buffer or PEM/base64 string");
    }
    certsByName[c.name] = {
      name:      c.name,
      domains:   c.domains.slice(),
      keyAlg:    keyAlg,
      challenge: c.challenge,
      keyEscrow: c.keyEscrow || null,
    };
  }

  // ---- Renewal scheduler opts ----
  var renewOpts = opts.renew || {};
  validateOpts(renewOpts, ["intervalMs", "minDaysBeforeExpiry", "ariCompliant"],
    "cert.create.renew");
  var renewIntervalMs = _positiveFiniteOrDefault(
    renewOpts.intervalMs, DEFAULT_RENEW_INTERVAL_MS,
    "cert.create.renew.intervalMs", "cert/bad-renew-interval");
  var minDaysBeforeExpiry = _positiveFiniteOrDefault(
    renewOpts.minDaysBeforeExpiry, DEFAULT_MIN_DAYS_BEFORE_EXPIRY,
    "cert.create.renew.minDaysBeforeExpiry", "cert/bad-renew-window");
  var ariCompliant = renewOpts.ariCompliant !== false;

  // ---- OCSP opts ----
  var ocspOpts = opts.ocsp || {};
  validateOpts(ocspOpts, ["stapling", "refreshMs"], "cert.create.ocsp");
  var ocspStapling = ocspOpts.stapling !== false;
  var ocspRefreshMs = _positiveFiniteOrDefault(
    ocspOpts.refreshMs, DEFAULT_OCSP_REFRESH_MS,
    "cert.create.ocsp.refreshMs", "cert/bad-ocsp-refresh");

  // ---- Audit + compliance ----
  var auditEnabled = opts.audit !== false;
  var compliancePostures = Array.isArray(opts.compliance) ? opts.compliance.slice() : [];
  // Validate posture names against the framework catalog so a typo is
  // caught at create() rather than silently ignored. The cert manager
  // satisfies the storage-confidentiality postures (HIPAA / PCI-DSS /
  // GDPR …) by construction — keys + certs are always sealed at rest
  // (storage.type is enforced to "sealed-disk"), so there is no plaintext-
  // storage state for a posture to fail to. The postures are recorded +
  // surfaced on the served context for an auditor.
  if (compliancePostures.length > 0) {
    var knownPostures = compliance().KNOWN_POSTURES;
    compliancePostures.forEach(function (p) {
      if (knownPostures.indexOf(p) === -1) {
        throw new CertError("cert/unknown-compliance-posture",
          "cert.create: opts.compliance posture '" + p + "' is not a known posture; " +
          "see b.compliance.KNOWN_POSTURES");
      }
    });
  }

  // ---- Internal state ----
  var emitter = new EventEmitter();
  var loadedContexts = Object.create(null);   // name → { cert, key, ca, expiresAt, fingerprintSha256, sniNames, ocspResponse }
  var acmeClient = null;
  var scheduler = null;
  var ocspTimer = null;
  var stopped = false;

  var _emitAudit = audit().namespaced(null, { audit: auditEnabled });

  function _bootAcme() {
    if (acmeClient) return acmeClient;
    var accountKey = opts.acme.accountKey;
    if (accountKey === "auto" || !accountKey) {
      accountKey = _loadOrGenerateAccountKey();
    }
    acmeClient = acme().create({
      directory:    opts.acme.directory,
      accountKey:   accountKey,
      contact:      opts.acme.contactEmail ? ["mailto:" + opts.acme.contactEmail] : undefined,
      timeoutMs:    opts.acme.timeoutMs,
    });
    return acmeClient;
  }

  function _loadOrGenerateAccountKey() {
    // Read sealed account JWK; generate + persist if absent.
    var sealedBuf = nodeFs.existsSync(nodePath.join(storage.rootDir, "account/jwk.json.sealed"))
      ? atomicFile.fdSafeReadSync(nodePath.join(storage.rootDir, "account/jwk.json.sealed"), { maxBytes: C.BYTES.kib(64) })
      : null;
    if (sealedBuf) {
      var jwk;
      try {
        var plain = (opts.storage.vault || vault().getDefaultStore()).unseal(sealedBuf);
        jwk = safeJson.parse(plain.toString("utf8"), { maxBytes: C.BYTES.kib(64) });
      } catch (e) {
        // The ACME account key binds existing order + authorization
        // history, so it is NOT auto-regenerated on corruption (unlike a
        // re-issuable cert) — that would silently abandon the account.
        // Fail with an actionable error naming the file + recovery instead
        // of letting a raw decrypt/parse error escape out of start().
        throw new CertError("cert/account-key-unreadable",
          "cert: ACME account key 'account/jwk.json.sealed' is unreadable (" +
          e.message + "). Restore it from backup, or delete it to register " +
          "a fresh ACME account (this abandons prior order history).");
      }
      return _accountKeyFromJwk(jwk);
    }
    var pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    var privatePem = pair.privateKey.export({ type: "pkcs8", format: "pem" });
    var publicPem  = pair.publicKey.export({ type: "spki", format: "pem" });
    var freshJwk = pair.publicKey.export({ format: "jwk" });
    freshJwk.privatePem = privatePem;
    freshJwk.publicPem  = publicPem;
    storage.writeSealed("account/jwk.json", JSON.stringify(freshJwk));
    _emitAudit("cert.account.generated", "success", { directory: opts.acme.directory });
    return _accountKeyFromJwk(freshJwk);
  }

  function _accountKeyFromJwk(jwk) {
    return {
      privatePem: jwk.privatePem,
      publicPem:  jwk.publicPem,
      jwk:        { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
      kty:        jwk.kty,
      crv:        jwk.crv,
    };
  }

  // RSA modulus bits — operator-selected protocol constants, not byte
  // counts. The framework's leaf-key alg names embed the bit length
  // verbatim ("rsa-2048" / "rsa-3072" / "rsa-4096"), so the literals
  // here are protocol-constant references.
  var RSA_MODULUS_BITS_2048 = 2048;                                                  // RSA modulus length, not a byte count
  var RSA_MODULUS_BITS_3072 = 3072;                                                  // RSA modulus length, not a byte count
  var RSA_MODULUS_BITS_4096 = 4096;                                                  // RSA modulus length, not a byte count

  function _generateLeafKeypair(keyAlg) {
    switch (keyAlg) {
      case "ecdsa-p256": return nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
      case "ecdsa-p384": return nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
      case "rsa-2048":   return nodeCrypto.generateKeyPairSync("rsa", { modulusLength: RSA_MODULUS_BITS_2048 });
      case "rsa-3072":   return nodeCrypto.generateKeyPairSync("rsa", { modulusLength: RSA_MODULUS_BITS_3072 });
      case "rsa-4096":   return nodeCrypto.generateKeyPairSync("rsa", { modulusLength: RSA_MODULUS_BITS_4096 });
      default:
        throw new CertError("cert/bad-key-alg", "cert: unknown keyAlg " + keyAlg);
    }
  }

  async function _issueCert(certManifest) {
    var acme = _bootAcme();
    // 1. Fetch directory + ensure ACME account exists.
    await acme.fetchDirectory();
    await acme.newAccount({
      contact:              opts.acme.contactEmail ? ["mailto:" + opts.acme.contactEmail] : undefined,
      termsOfServiceAgreed: true,
    });
    // 2. Create the order.
    var order = await acme.newOrder({
      identifiers: certManifest.domains.map(function (d) {
        return { type: "dns", value: d };
      }),
    });
    // 3. For each authorization, solve the operator-supplied challenge.
    for (var ai = 0; ai < order.authorizations.length; ai += 1) {
      var auth = await acme.fetchAuthorization(order.authorizations[ai]);
      if (auth.status === "valid") continue;
      var challenge = auth.challenges.find(function (ch) {
        return ch.type === certManifest.challenge.type;
      });
      if (!challenge) {
        throw new CertError("cert/no-matching-challenge",
          "cert: CA did not offer " + certManifest.challenge.type +
          " for " + auth.identifier.value);
      }
      // tls-alpn-01 has a different key-authorization shape (RFC 8737).
      var keyAuth = certManifest.challenge.type === "tls-alpn-01"
        ? acme.tlsAlpn01KeyAuthorization(challenge.token)
        : acme.keyAuthorization(challenge.token);
      var provisionParams = {
        domain:           auth.identifier.value,
        type:             challenge.type,
        token:            challenge.token,
        keyAuthorization: keyAuth,
      };
      await certManifest.challenge.provision(provisionParams);
      try {
        await acme.notifyChallengeReady(challenge.url);
        await acme.waitForAuthorization(order.authorizations[ai]);
      } finally {
        try { await certManifest.challenge.cleanup(provisionParams); }
        catch (cleanupErr) {
          // Cleanup failure shouldn't void the order, but the
          // operator should know — emit drop-silent audit.
          _emitAudit("cert.challenge-cleanup", "failure", {
            name:   certManifest.name,
            domain: auth.identifier.value,
            error:  (cleanupErr && cleanupErr.message) || String(cleanupErr),
          });
        }
      }
    }
    // 4. Generate leaf keypair + CSR + finalize.
    var leafPair = _generateLeafKeypair(certManifest.keyAlg);
    var csrPem = acme.buildCsr({
      privateKey: leafPair.privateKey,
      publicKey:  leafPair.publicKey,
      domains:    certManifest.domains,
    });
    var finalized = await acme.finalize(order, csrPem);
    var certPem = await acme.retrieveCert(finalized);
    var privPem = leafPair.privateKey.export({ type: "pkcs8", format: "pem" });
    return { certPem: certPem, keyPem: privPem };
  }

  function _certMeta(certPem) {
    // Extract notAfter + fingerprint without re-implementing X.509.
    var cert = new nodeCrypto.X509Certificate(certPem);
    return {
      expiresAt:         Date.parse(cert.validTo),
      issuedAt:          Date.parse(cert.validFrom),
      fingerprintSha256: cert.fingerprint256.replace(/:/g, "").toLowerCase(),
      subject:           cert.subject,
      subjectAltName:    cert.subjectAltName || null,
    };
  }

  async function _persistCert(certManifest, certPem, keyPem) {
    await storage.writeSealed(certManifest.name + "/cert.pem", certPem);
    await storage.writeSealed(certManifest.name + "/key.pem", keyPem);
    if (certManifest.keyEscrow) {
      await storage.writeEscrow(certManifest.name + "/key.pem.escrow", keyPem,
        certManifest.keyEscrow.recipient);
    }
    var meta = _certMeta(certPem);
    meta.lastRenewedAt = Date.now();
    meta.keyAlg = certManifest.keyAlg;
    await storage.writeMeta(certManifest.name, meta);
    return meta;
  }

  // `forceIssue` skips the cache-fresh short-circuit and ALWAYS runs
  // the ACME issue flow. Operators invoke this path via `refresh(name)`
  // for emergency reissue / key rollover when the existing cert is
  // structurally fine but operationally compromised (suspected key
  // disclosure, CA misissuance investigation, posture-driven rotation).
  // A corrupt sealed cert/key is RECOVERABLE state — the CA re-issues on
  // demand. Treat an unreadable sealed file like a missing one (log +
  // re-issue) rather than letting a raw unseal/decrypt error escape out of
  // start(): on a managed restart the same corrupt file is read on every
  // boot, so throwing here is an unrecoverable crash loop, and a corrupt
  // file must never be handled worse than an absent one (which already
  // falls through to issue). The ACME account key is the one piece NOT
  // auto-recovered this way — see _loadOrGenerateAccountKey.
  async function _readSealedOrReissue(relPath, certName) {
    try {
      return await storage.readSealed(relPath);
    } catch (e) {
      log.warn("cert: sealed '" + relPath + "' unreadable (" + e.message +
        ") — re-issuing as if absent");
      _emitAudit("cert.sealed.corrupt", "recovered", { path: relPath, name: certName });
      return null;
    }
  }

  async function _ensureCert(certManifest, forceIssue) {
    var meta = await storage.readMeta(certManifest.name);
    var certBuf = await _readSealedOrReissue(certManifest.name + "/cert.pem", certManifest.name);
    var keyBuf  = await _readSealedOrReissue(certManifest.name + "/key.pem", certManifest.name);
    // Base the renewal decision on the SEALED cert's OWN notAfter, not the
    // plaintext meta.json index. meta is a derived convenience copy; if it
    // drifts from — or is tampered relative to — the actual cert (a far-
    // future meta.expiresAt over an actually-expiring cert), trusting it
    // would skip renewal and serve an expired cert. Re-derive expiry +
    // fingerprint from the cert itself; if it won't parse, treat it as a
    // corrupt sealed cert and re-issue (same recovery as an unreadable one).
    var actual = null;
    if (certBuf) {
      try { actual = _certMeta(certBuf.toString("utf8")); }
      catch (e) {
        log.warn("cert: sealed cert for '" + certManifest.name + "' will not parse (" +
          e.message + ") — re-issuing");
        _emitAudit("cert.sealed.corrupt", "recovered",
          { path: certManifest.name + "/cert.pem", name: certManifest.name });
        certBuf = null;
      }
    }
    if (!forceIssue && actual && certBuf && keyBuf &&
        actual.expiresAt > Date.now() + minDaysBeforeExpiry * C.TIME.days(1)) {
      // Cached, and the cert's own notAfter is comfortably in the future.
      loadedContexts[certManifest.name] = {
        cert:               certBuf.toString("utf8"),
        key:                keyBuf.toString("utf8"),
        expiresAt:          actual.expiresAt,
        fingerprintSha256:  actual.fingerprintSha256,
        sniNames:           certManifest.domains.slice(),
      };
      return loadedContexts[certManifest.name];
    }
    // Issue (or renew) the cert.
    var issued = await _issueCert(certManifest);
    var freshMeta = await _persistCert(certManifest, issued.certPem, issued.keyPem);
    loadedContexts[certManifest.name] = {
      cert:               issued.certPem,
      key:                issued.keyPem,
      expiresAt:          freshMeta.expiresAt,
      fingerprintSha256:  freshMeta.fingerprintSha256,
      sniNames:           certManifest.domains.slice(),
    };
    var event = meta ? "cert.renewed" : "cert.issued";
    _emitAudit(event, "success", {
      name:              certManifest.name,
      domains:           certManifest.domains,
      expiresAt:         freshMeta.expiresAt,
      fingerprintSha256: freshMeta.fingerprintSha256,
    });
    emitter.emit(event, {
      name:              certManifest.name,
      expiresAt:         freshMeta.expiresAt,
      fingerprintSha256: freshMeta.fingerprintSha256,
    });
    return loadedContexts[certManifest.name];
  }

  async function _renewCheckOne(certManifest) {
    var meta = await storage.readMeta(certManifest.name);
    if (!meta) return;
    var msToExpiry = meta.expiresAt - Date.now();
    var renewThresholdMs = minDaysBeforeExpiry * C.TIME.days(1);
    var shouldRenew = msToExpiry < renewThresholdMs;

    // ARI: if the CA published renewalInfo and ariCompliant is on,
    // also honor the CA's suggestedWindow (which may be sooner or
    // later than the time-based threshold).
    if (ariCompliant && acmeClient) {
      try {
        var ari = await acmeClient.renewIfDue({ certPem: loadedContexts[certManifest.name].cert });
        if (ari && ari.shouldRenew) shouldRenew = true;
      } catch (_e) {
        // ARI fetch failure is non-fatal — fall back to time-based
        // threshold (also drop-silent audit).
      }
    }

    if (!shouldRenew) return;
    try {
      await _ensureCert(certManifest);
    } catch (e) {
      _emitAudit("cert.renew-failed", "failure", {
        name:    certManifest.name,
        domains: certManifest.domains,
        error:   (e && e.message) || String(e),
      });
      emitter.emit("cert.renew-failed", {
        name:    certManifest.name,
        error:   e,
      });
    }
  }

  // Split a PEM chain into individual certificate blocks (leaf first).
  function _splitPemChain(pem) {
    return pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  }

  // Fetch + cache a validated OCSP response for one managed cert, for
  // server-side stapling. Fail-soft: a responder error, or no issuer in the
  // served chain, leaves any prior staple in place and never throws — an
  // absent staple degrades gracefully (clients fall back to their own
  // revocation checking). The validated DER is exposed on
  // getContext().ocspResponse for the operator's TLS server to staple via
  // its 'OCSPRequest' handler.
  async function _refreshOcspFor(name) {
    var ctx = loadedContexts[name];
    if (!ctx || !ocspStapling) return;
    var chain = _splitPemChain(ctx.cert);
    if (chain.length < 2) return;   // no issuer in the served chain
    try {
      // allow:raw-outbound-http-framework-internal — b.network.tls.ocsp.fetch composes b.httpClient internally (SSRF guard + pinned DNS); not a raw outbound call
      var rv = await networkTls().ocsp.fetch({ leafPem: chain[0], issuerPem: chain[1] });
      ctx.ocspResponse = rv.ocspDer;
      _emitAudit("cert.ocsp.refreshed", "success", { name: name });
    } catch (e) {
      _emitAudit("cert.ocsp.refresh-failed", "failure",
        { name: name, error: (e && e.message) || String(e) });
    }
  }

  async function _refreshAllOcsp() {
    var keys = Object.keys(loadedContexts);
    for (var i = 0; i < keys.length; i += 1) { await _refreshOcspFor(keys[i]); }
  }

  async function start() {
    if (stopped) {
      throw new CertError("cert/already-stopped",
        "cert.start: handle was stopped; create a new manager to restart");
    }
    // 1. Boot ACME client + ensure every manifest cert is issued.
    var names = Object.keys(certsByName);
    for (var ni = 0; ni < names.length; ni += 1) {
      await _ensureCert(certsByName[names[ni]]);
    }
    // 2. Start renewal scheduler.
    scheduler = safeAsync.repeating(async function () {
      var keys = Object.keys(certsByName);
      for (var ki = 0; ki < keys.length; ki += 1) {
        await _renewCheckOne(certsByName[keys[ki]]);
      }
    }, renewIntervalMs, { name: "cert-renew" });
    // 3. OCSP stapling. The initial fetch runs in the background so a slow
    //    responder never delays start(); the staple becomes available
    //    shortly after, and the timer refreshes on the configured cadence.
    if (ocspStapling) {
      _refreshAllOcsp().catch(function () { /* per-cert errors already audited */ });
      ocspTimer = safeAsync.repeating(_refreshAllOcsp, ocspRefreshMs, { name: "cert-ocsp" });
    }
  }

  async function stop() {
    stopped = true;
    if (scheduler && typeof scheduler.stop === "function") scheduler.stop();
    scheduler = null;
    if (ocspTimer && typeof ocspTimer.stop === "function") ocspTimer.stop();
    ocspTimer = null;
  }

  function getContext(name) {
    if (!certsByName[name]) {
      throw new CertError("cert/unknown-name",
        "cert.getContext: unknown cert '" + name + "' — declare it in opts.certs");
    }
    var ctx = loadedContexts[name];
    if (!ctx) {
      throw new CertError("cert/not-loaded",
        "cert.getContext: cert '" + name + "' not yet loaded — call start() first");
    }
    return {
      cert:               ctx.cert,
      key:                ctx.key,
      expiresAt:          ctx.expiresAt,
      fingerprintSha256:  ctx.fingerprintSha256,
      // The cached, validated OCSP response (DER Buffer) when ocsp.stapling
      // is on and a response has been fetched; null otherwise. Staple it
      // from the TLS server's 'OCSPRequest' handler: cb(null, ocspResponse).
      ocspResponse:       ctx.ocspResponse || null,
      compliance:         compliancePostures.slice(),
    };
  }

  function sniCallback(servername, cb) {
    // Match by exact domain first, then wildcard suffix.
    var match = null;
    var names = Object.keys(loadedContexts);
    for (var ni = 0; ni < names.length; ni += 1) {
      var ctx = loadedContexts[names[ni]];
      if (ctx.sniNames.indexOf(servername) !== -1) { match = ctx; break; }
    }
    if (!match && names.length > 0) {
      // Wildcard scan — RFC 6125 §6.4.3 restricts `*.example.com` to
      // match exactly ONE label in the left-most position. `foo.bar.
      // example.com` does NOT match `*.example.com` even though the
      // tail aligns. Enforce the single-label invariant explicitly:
      // the wildcard suffix is `.<rest>`; the leading label of
      // `servername` must not itself contain a `.`.
      for (var nj = 0; nj < names.length; nj += 1) {
        var ctxJ = loadedContexts[names[nj]];
        for (var sj = 0; sj < ctxJ.sniNames.length; sj += 1) {
          var pattern = ctxJ.sniNames[sj];
          if (pattern.charAt(0) !== "*" || pattern.charAt(1) !== ".") continue;
          var tail = pattern.slice(1);   // ".example.com"
          if (!servername.endsWith(tail)) continue;
          var leadingLabel = servername.slice(0, servername.length - tail.length);
          if (leadingLabel.length === 0 || leadingLabel.indexOf(".") !== -1) continue;
          match = ctxJ;
          break;
        }
        if (match) break;
      }
    }
    if (!match && names.length > 0) {
      // Fall back to the first registered cert (operator's default).
      match = loadedContexts[names[0]];
    }
    if (!match) {
      return cb(new CertError("cert/no-context",
        "cert.sniCallback: no certs loaded for servername '" + servername + "'"));
    }
    try {
      var secureCtx = require("node:tls").createSecureContext({
        cert: match.cert,
        key:  match.key,
      });
      cb(null, secureCtx);
    } catch (e) {
      cb(e);
    }
  }

  async function refresh(name) {
    // refresh() forces an immediate ACME issue regardless of cache
    // freshness — operator-triggered emergency rotation (key
    // compromise, CA misissuance investigation, posture-driven
    // rotation). The renewal scheduler's window-based path runs via
    // _renewCheckOne; refresh() is the override.
    if (!certsByName[name]) {
      throw new CertError("cert/unknown-name",
        "cert.refresh: unknown cert '" + name + "'");
    }
    return _ensureCert(certsByName[name], true);
  }

  function on(event, handler)   { emitter.on(event, handler);    return this; }
  function off(event, handler)  { emitter.off(event, handler);   return this; }
  function once(event, handler) { emitter.once(event, handler);  return this; }

  return {
    start:        start,
    stop:         stop,
    getContext:   getContext,
    sniCallback:  sniCallback,
    refresh:      refresh,
    on:           on,
    off:          off,
    once:         once,
  };
}

module.exports = {
  create:    create,
  CertError: CertError,
};
