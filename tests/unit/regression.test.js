/**
 * Regression tests — each test corresponds to a bug that was found
 * in production or during code review. If any of these fail, we're
 * re-introducing a previously fixed issue.
 */
const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
var projectRoot = path.join(__dirname, "..", "..");

describe("regression", function () {

  // ---- Module loading (circular deps, missing exports) ----

  describe("module require smoke test", function () {
    // NOTE: webhook logic moved to app/domain/integrations/webhook.service.js
    // and expiry moved to app/jobs/expiry-cleanup.job.js during the DDD
    // refactor. The require-smoke-test list was updated to match.
    var modules = [
      "lib/crypto", "lib/constants", "lib/vault",
      "lib/passphrase-source", "lib/config",
      "lib/session", "lib/audit", "lib/db", "lib/storage",
      "lib/api-crypto", "lib/multipart", "lib/template",
      "lib/sanitize-svg", "lib/totp", "lib/rate-limit",
      "lib/email", "lib/field-crypto",

      "app/domain/integrations/webhook.service",
      "app/jobs/expiry-cleanup.job",
    ];
    for (var i = 0; i < modules.length; i++) {
      (function (mod) {
        it("require('" + mod + "') loads without error", function () {
          assert.doesNotThrow(function () {
            require(path.join(projectRoot, mod));
          });
        });
      })(modules[i]);
    }
  });

  // ---- Vendored packages export expected functions ----
  // Server-side crypto + identity packages live inside the vendored
  // blamejs framework at lib/vendor/blamejs/. Argon2 runs through Node
  // 24+'s built-in crypto.argon2 via blamejs's argon2-builtin wrapper
  // (no native binding vendored).

  describe("vendored package exports", function () {
    it("@noble/ciphers exports xchacha20poly1305", function () {
      var mod = require(path.join(projectRoot, "lib/vendor/blamejs/lib/vendor/noble-ciphers.cjs"));
      assert.strictEqual(typeof mod.xchacha20poly1305, "function");
    });

    it("@noble/post-quantum exports ml_kem1024", function () {
      var mod = require(path.join(projectRoot, "lib/vendor/blamejs/lib/vendor/noble-post-quantum.cjs"));
      assert.strictEqual(typeof mod.ml_kem1024, "object");
      assert.strictEqual(typeof mod.ml_kem1024.keygen, "function");
    });

    it("@simplewebauthn/server exports verification functions", function () {
      var mod = require(path.join(projectRoot, "lib/vendor/blamejs/lib/vendor/simplewebauthn-server.cjs"));
      assert.strictEqual(typeof mod.verifyAuthenticationResponse, "function");
      assert.strictEqual(typeof mod.verifyRegistrationResponse, "function");
      assert.strictEqual(typeof mod.generateRegistrationOptions, "function");
      assert.strictEqual(typeof mod.generateAuthenticationOptions, "function");
    });

    it("peculiar-pki exports x509 + pkijs", function () {
      var mod = require(path.join(projectRoot, "lib/vendor/blamejs/lib/vendor/pki.cjs"));
      assert.strictEqual(typeof mod.x509, "object");
      assert.strictEqual(typeof mod.pkijs, "object");
    });

    it("argon2-builtin exports hash and verify", function () {
      var mod = require(path.join(projectRoot, "lib/vendor/blamejs/lib/argon2-builtin"));
      assert.strictEqual(typeof mod.hash, "function");
      assert.strictEqual(typeof mod.verify, "function");
    });

    it("argon2 hash/verify roundtrip works (built-in crypto.argon2)", async function () {
      var mod = require(path.join(projectRoot, "lib/vendor/blamejs/lib/argon2-builtin"));
      var h = await mod.hash("test123", { memoryCost: 1024, timeCost: 1, parallelism: 1 });
      assert.ok(h.startsWith("$argon2id$"), "should be argon2id hash");
      var ok = await mod.verify(h, "test123");
      assert.strictEqual(ok, true);
    });
  });

  // ---- Vendored blamejs drift detection ----
  // Warns (does NOT fail) when the vendored copy at lib/vendor/blamejs/
  // is older than the latest GitHub Release of github.com/blamejs/blamejs.
  // Surfaces drift so operators run scripts/vendor-update.sh blamejs when
  // the upstream framework ships a new release, without blocking releases
  // that intentionally pin to a known-good vendored version (e.g. while
  // validating a new upstream release before adopting it).
  //
  // Source of truth is the GitHub Releases API — same code path
  // scripts/vendor-update.sh and hermitstash-sync's check-blamejs-version.js
  // use to resolve "latest". Skipped on network failure or when
  // BLAMEJS_DRIFT_CHECK=skip is set (offline dev).

  describe("vendored blamejs version drift", function () {
    it("vendored lib/vendor/blamejs matches latest GitHub Release (warning only)", function (t, done) {
      if (process.env.BLAMEJS_DRIFT_CHECK === "skip") {
        t.skip("BLAMEJS_DRIFT_CHECK=skip");
        done();
        return;
      }
      var vendoredPkgPath = path.join(projectRoot, "lib/vendor/blamejs/package.json");
      var manifestPath    = path.join(projectRoot, "lib/vendor/MANIFEST.json");
      var vendored = JSON.parse(fs.readFileSync(vendoredPkgPath, "utf8"));
      var manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      var vendoredTag = manifest.packages.blamejs && manifest.packages.blamejs.tag;

      var https = require("node:https");
      var opts = {
        headers: {
          "User-Agent": "hermitstash-blamejs-drift-check",
          "Accept":     "application/vnd.github+json",
        },
        timeout: 10000,
      };
      if (process.env.GITHUB_TOKEN) opts.headers.Authorization = "Bearer " + process.env.GITHUB_TOKEN;

      var req = https.get("https://api.github.com/repos/blamejs/blamejs/releases/latest", opts, function (res) {
        var chunks = [];
        res.on("data", function (c) { chunks.push(c); });
        res.on("end", function () {
          if (res.statusCode !== 200) {
            t.skip("GitHub API HTTP " + res.statusCode + " — drift check requires network");
            done();
            return;
          }
          var parsed;
          try { parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
          catch (_e) { t.skip("GitHub API returned non-JSON — skipping drift check"); done(); return; }
          var latestTag = parsed && parsed.tag_name;
          if (typeof latestTag !== "string") {
            t.skip("GitHub API response missing tag_name");
            done();
            return;
          }
          if (vendoredTag && vendoredTag !== latestTag) {
            process.stderr.write(
              "\n[WARN] vendored blamejs drift — vendored " + vendored.version +
              " (" + vendoredTag + ") vs latest GitHub Release " + latestTag +
              ". Refresh with: ./scripts/vendor-update.sh blamejs\n\n"
            );
          }
          done();
        });
      });
      req.on("timeout", function () { req.destroy(new Error("timeout")); });
      req.on("error", function (e) {
        t.skip("network unavailable — drift check requires GitHub API (" + e.message + ")");
        done();
      });
    });

    it("vendored blamejs name is @blamejs/core", function () {
      var vendoredPkgPath = path.join(projectRoot, "lib/vendor/blamejs/package.json");
      var vendored = JSON.parse(fs.readFileSync(vendoredPkgPath, "utf8"));
      assert.strictEqual(vendored.name, "@blamejs/core");
    });

    it("MANIFEST records both blamejs version and tag", function () {
      var manifest = JSON.parse(fs.readFileSync(path.join(projectRoot, "lib/vendor/MANIFEST.json"), "utf8"));
      var entry = manifest.packages.blamejs;
      assert.ok(entry, "blamejs entry missing from MANIFEST");
      assert.strictEqual(typeof entry.version, "string", "MANIFEST.packages.blamejs.version must be a string");
      assert.strictEqual(typeof entry.tag, "string", "MANIFEST.packages.blamejs.tag must be a string (e.g. 'v0.8.52')");
      assert.ok(/^v\d+\.\d+\.\d+/.test(entry.tag), "tag must look like a semver release tag");
      assert.strictEqual(entry.tag.replace(/^v/, ""), entry.version, "tag and version must agree");
    });

    it("blamejs SBOM components mirror the vendored tree's own manifest", function () {
      // packages.blamejs.components is what Trivy / Grype scan. It is a
      // mechanical projection of the vendored tree's dependency manifest
      // (scripts/refresh-blamejs-sbom.js, run automatically by vendor-update.sh).
      // A drift here means a blamejs bump landed without the SBOM refresh, so a
      // nested package/version on disk is invisible to the CVE scanners.
      var sbom = require(path.join(projectRoot, "scripts/refresh-blamejs-sbom.js"));
      var nested = JSON.parse(fs.readFileSync(sbom.NESTED_MANIFEST, "utf8"));
      var parent = JSON.parse(fs.readFileSync(sbom.PARENT_MANIFEST, "utf8"));
      var projected = sbom.projectComponents(nested);
      var current = parent.packages.blamejs.components || {};
      assert.deepStrictEqual(
        current, projected,
        "blamejs SBOM components are stale — run: node scripts/refresh-blamejs-sbom.js"
      );
    });

    it("README + THIRD_PARTY_LICENSES blamejs version/packages are in sync with the MANIFEST", function () {
      // The operator docs hard-code the blamejs version + package list; they are
      // synced from the MANIFEST by the same refresh script (vendor-update.sh runs
      // it). Fail here if they drift, so a vendor bump that forgot the doc refresh
      // is caught in CI rather than only at the release gate.
      var sbom = require(path.join(projectRoot, "scripts/refresh-blamejs-sbom.js"));
      var parent = JSON.parse(fs.readFileSync(sbom.PARENT_MANIFEST, "utf8"));
      var bj = parent.packages.blamejs;
      var result = sbom.checkDocs(bj.version, bj.components || {});
      assert.strictEqual(
        result.stale, false,
        "operator docs are stale — run: node scripts/refresh-blamejs-sbom.js\n" + result.messages.join("\n")
      );
    });

    it("sectionContaining scopes a version-token check to one package's own section", function () {
      // A compound-version package (e.g. peculiar-pki "a+pkijs-b") is staleness-
      // checked token-by-token. The check must be scoped to the package's OWN
      // `## ` section — a document-wide search would false-negative when the
      // stale token coincidentally appears in another package's section.
      var sbom = require(path.join(projectRoot, "scripts/refresh-blamejs-sbom.js"));
      var doc = [
        "## @noble/ciphers v2.2.0",
        "- Source: https://example.com/ciphers",
        "",
        "## @peculiar/x509 v2.0.0 + pkijs v3.4.0 (peculiar-pki bundle)",
        "- Source: https://github.com/PeculiarVentures",
        "",
        "## tail v1.0.0",
        "- Source: https://example.com/tail",
        "",
      ].join("\n");
      var section = sbom.sectionContaining(doc, "https://github.com/PeculiarVentures");
      // Scoped to the peculiar section only — the colliding "2.2.0" in the
      // noble-ciphers header is NOT in scope, so a stale x509 header is caught.
      assert.ok(section.indexOf("@peculiar/x509 v2.0.0") !== -1, "returns the peculiar section");
      assert.strictEqual(section.indexOf("2.2.0"), -1, "does not leak the colliding token from another section");
      assert.strictEqual(section.indexOf("tail v1.0.0"), -1, "stops at the next ## header");
      // Absent needle falls back to the whole document (never throws).
      assert.strictEqual(sbom.sectionContaining(doc, "https://nope.example"), doc);
    });
  });

  // ---- ShareID entropy (was 32-bit, now 128-bit) ----

  describe("shareID entropy", function () {
    it("generateShareId returns 64 hex chars (256-bit)", function () {
      var { generateShareId } = require(path.join(projectRoot, "lib/crypto"));
      var id = generateShareId();
      assert.strictEqual(id.length, 64, "shareId should be 64 hex chars");
      assert.ok(/^[0-9a-f]+$/.test(id), "shareId should be hex");
    });

    it("generateShareId produces unique values", function () {
      var { generateShareId } = require(path.join(projectRoot, "lib/crypto"));
      var ids = new Set();
      for (var i = 0; i < 1000; i++) ids.add(generateShareId());
      assert.strictEqual(ids.size, 1000, "1000 shareIds should all be unique");
    });
  });

  // ---- Cross-version encrypt/decrypt backward compat ----

  describe("envelope backward compatibility", function () {
    it("decrypt still reads a legacy 0xE1 envelope", function () {
      // The 0xE1 producer was retired from lib/crypto (no code mints 0xE1 anymore),
      // so the legacy blob is built from the test-only constructor. decrypt() must
      // keep reading it for the migration window.
      var { decrypt, generateEncryptionKeyPair } = require(path.join(projectRoot, "lib/crypto"));
      var { encryptLegacy0xE1 } = require(path.join(projectRoot, "tests/helpers/legacy-envelope"));
      var kp = generateEncryptionKeyPair();
      var sealed = encryptLegacy0xE1("hello envelope", kp);
      var packed = Buffer.from(sealed, "base64");
      assert.strictEqual(packed[0], 0xE1, "should start with envelope magic byte");
      assert.strictEqual(decrypt(sealed, kp), "hello envelope");
    });

    it("vault seal/unseal roundtrip works", function () {
      var vault = require(path.join(projectRoot, "lib/vault"));
      var sealed = vault.seal("test-value");
      assert.ok(sealed.startsWith("vault:"), "sealed value should have vault: prefix");
      assert.strictEqual(vault.unseal(sealed), "test-value");
    });

    it("vault unseal returns plaintext for non-sealed values", function () {
      var vault = require(path.join(projectRoot, "lib/vault"));
      assert.strictEqual(vault.unseal("plain text"), "plain text");
      assert.strictEqual(vault.unseal(null), null);
      assert.strictEqual(vault.unseal(""), "");
    });
  });

  // ---- packed buffer encrypt/decrypt (b.crypto — used by storage + db) ----

  describe("packed buffer encrypt/decrypt", function () {
    it("roundtrips correctly", function () {
      var { generateBytes } = require(path.join(projectRoot, "lib/crypto"));
      var { encryptPacked, decryptPacked } = require(path.join(projectRoot, "lib/vendor/blamejs")).crypto;
      var key = generateBytes(32);
      var data = Buffer.from("file content here");
      var packed = encryptPacked(data, key);
      assert.strictEqual(packed[0], 0x02, "should have XChaCha20 format byte");
      var decrypted = decryptPacked(packed, key);
      assert.ok(data.equals(decrypted), "decrypted should match original");
    });

    it("rejects tampered ciphertext", function () {
      var { generateBytes } = require(path.join(projectRoot, "lib/crypto"));
      var { encryptPacked, decryptPacked } = require(path.join(projectRoot, "lib/vendor/blamejs")).crypto;
      var key = generateBytes(32);
      var packed = encryptPacked(Buffer.from("secret"), key);
      packed[packed.length - 1] ^= 0xff; // flip a byte
      assert.throws(function () { decryptPacked(packed, key); }, "tampered data should throw");
    });

    it("rejects wrong key", function () {
      var { generateBytes } = require(path.join(projectRoot, "lib/crypto"));
      var { encryptPacked, decryptPacked } = require(path.join(projectRoot, "lib/vendor/blamejs")).crypto;
      var key1 = generateBytes(32);
      var key2 = generateBytes(32);
      var packed = encryptPacked(Buffer.from("secret"), key1);
      assert.throws(function () { decryptPacked(packed, key2); }, "wrong key should throw");
    });
  });

  // ---- Cache-busting hashes ----

  describe("cache-busting file hashes", function () {
    it("constants.js computes hashes for JS files", function () {
      var C = require(path.join(projectRoot, "lib/constants"));
      assert.ok(C.apiJsVersion.length > 20, "api.js hash should be full SHA3-512 hex");
      assert.ok(C.vaultPqVersion.length > 20, "vault-pq.js hash should be full SHA3-512 hex");
      assert.ok(C.cssVersion.length > 20, "style.css hash should be full SHA3-512 hex");
    });

    it("different files produce different hashes", function () {
      var C = require(path.join(projectRoot, "lib/constants"));
      assert.notStrictEqual(C.apiJsVersion, C.cssVersion, "api.js and style.css should have different hashes");
      assert.notStrictEqual(C.apiJsVersion, C.vaultPqVersion, "api.js and vault-pq.js should have different hashes");
    });
  });

  // ---- Constants centralization ----

  describe("centralized constants", function () {
    it("VAULT_PREFIX is defined and used consistently", function () {
      var C = require(path.join(projectRoot, "lib/constants"));
      assert.strictEqual(C.VAULT_PREFIX, "vault:");
    });

    it("HASH_PREFIX has all required keys", function () {
      var C = require(path.join(projectRoot, "lib/constants"));
      assert.ok(C.HASH_PREFIX.EMAIL, "should have EMAIL prefix");
      assert.ok(C.HASH_PREFIX.SHARE_ID, "should have SHARE_ID prefix");
      assert.ok(C.HASH_PREFIX.IP, "should have IP prefix");
      assert.ok(C.HASH_PREFIX.BLOCKED_IP, "should have BLOCKED_IP prefix");
    });

    it("FORMAT.XCHACHA20 is 0x02", function () {
      var C = require(path.join(projectRoot, "lib/constants"));
      assert.strictEqual(C.FORMAT.XCHACHA20, 0x02);
    });
  });

  // ---- HMAC uses SHA3-512 (not SHA3-256) ----

  describe("HMAC algorithm", function () {
    it("hmacSha3 produces 128-char hex (SHA3-512)", function () {
      var b = require(path.join(projectRoot, "lib/vendor/blamejs"));
      var result = b.crypto.hmacSha3("key", "data");
      assert.strictEqual(result.length, 128, "HMAC-SHA3-512 should be 128 hex chars");
    });
  });

  // ---- No direct crypto.randomBytes outside lib/crypto.js ----

  describe("no raw crypto.randomBytes in source files", function () {
    it("only lib/crypto.js uses crypto.randomBytes", function () {
      var srcDirs = ["lib", "routes", "middleware", "app"].map(function (d) { return path.join(projectRoot, d); });
      var violations = [];

      function scanDir(dir) {
        var entries;
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_e) { return; }
        for (var e of entries) {
          var full = path.join(dir, e.name);
          if (e.isDirectory()) {
            if (e.name === "node_modules" || e.name === "vendor") continue;
            scanDir(full);
          } else if (e.name.endsWith(".js")) {
            var content = fs.readFileSync(full, "utf8");
            if (content.includes("crypto.randomBytes") && !full.includes("crypto.js")) {
              violations.push(path.relative(projectRoot, full));
            }
          }
        }
      }

      for (var d of srcDirs) scanDir(d);
      assert.deepStrictEqual(violations, [], "no files should use crypto.randomBytes directly (use lib/crypto.js)");
    });
  });

  // ---- No require("../lib/password") anywhere ----

  describe("deleted password.js not referenced", function () {
    it("no source files import lib/password", function () {
      var srcDirs = ["lib", "routes", "middleware", "app", "server.js"].map(function (d) { return path.join(projectRoot, d); });
      var violations = [];

      function scanDir(dir) {
        var stat;
        try { stat = fs.statSync(dir); } catch (_e) { return; }
        if (stat.isFile() && dir.endsWith(".js")) {
          var content = fs.readFileSync(dir, "utf8");
          if (content.includes('lib/password') || content.includes('lib", "password"')) {
            violations.push(path.relative(projectRoot, dir));
          }
          return;
        }
        if (!stat.isDirectory()) return;
        var entries;
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_e) { return; }
        for (var e of entries) {
          if (e.name === "node_modules" || e.name === "vendor") continue;
          scanDir(path.join(dir, e.name));
        }
      }

      for (var d of srcDirs) scanDir(d);
      assert.deepStrictEqual(violations, [], "no source files should reference deleted lib/password.js");
    });
  });
});
