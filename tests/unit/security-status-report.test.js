"use strict";

/**
 * What Admin → Security claims about each protection, across the states it can
 * be in.
 *
 * An operator reads these rows to decide whether a deployment is safe to
 * expose, so a row that says a protection is on when it is off is worse than no
 * row at all. That has happened here: the TLS row reported "enabled" on a
 * server running plain HTTP, because it checked the key and not the
 * certificate, and the mTLS row reported hard enforcement on a server with no
 * TLS listener, where no client certificate was required on any connection.
 *
 * The report is a pure function of gathered state, so every combination can be
 * asked directly rather than by arranging a server to be in it.
 */

var { describe, it } = require("node:test");
var assert = require("node:assert");

var { buildReport } = require("../../app/domain/admin/security-status.service");

// A deployment with nothing configured: no keys, no CA, no TLS, no enforcement.
// Each test turns on only what it is about, so a claim cannot come from a
// neighbouring field.
function state(over) {
  return Object.assign({
    vaultMode: "disabled", vaultSealedExists: false, vaultKeyExists: false,
    caKeyMode: "auto", caSealedExists: false, caPlainExists: false, caExists: false,
    tlsKeyMode: "auto", tlsSealedExists: false, tlsPlainExists: false,
    tlsCertExists: false, tlsKeyExists: false, tlsServing: false,
    enforceMtlsStrict: undefined, mtlsHardEnforced: false, mtlsSoftEnforced: false,
  }, over || {});
}

function row(over, key) {
  var found = buildReport(state(over)).items.filter(function (i) { return i.key === key; });
  assert.equal(found.length, 1, "expected exactly one '" + key + "' row");
  return found[0];
}

describe("security status — the report's shape", function () {
  it("returns every row the admin page renders, once each", function () {
    var report = buildReport(state());
    var keys = report.items.map(function (i) { return i.key; });
    assert.deepEqual(keys,
      ["vault_passphrase", "ca_key_sealed", "tls_key_sealed", "mtls_enforcement", "tls"]);
    assert.equal(new Set(keys).size, keys.length, "keys must be unique — the UI keys rows by them");
  });

  it("gives every row a status the UI knows how to draw", function () {
    // The frontend picks an icon from this; an unexpected value renders as
    // nothing and the row silently loses its severity.
    [state(), state({ tlsServing: true, vaultMode: "required", vaultSealedExists: true }),
      state({ enforceMtlsStrict: "false" }), state({ caExists: true, caPlainExists: true })
    ].forEach(function (s) {
      buildReport(s).items.forEach(function (i) {
        assert.ok(["ok", "warn", "info"].indexOf(i.status) !== -1,
          i.key + " has status " + JSON.stringify(i.status));
        assert.equal(typeof i.value, "string", i.key + " must have a value string");
        assert.ok(Array.isArray(i.actions), i.key + " actions must be an array");
      });
    });
  });
});

describe("security status — TLS row", function () {
  it("says enabled only when the process reports it is serving TLS", function () {
    assert.equal(row({ tlsServing: true }, "tls").status, "ok");
    assert.equal(row({ tlsServing: true }, "tls").value, "enabled");
  });

  it("does not call it enabled merely because both files are present", function () {
    // The regression: key + certificate on disk does not mean the listener came
    // up — it also depends on the key loading under the sealed-key mode.
    var r = row({ tlsKeyExists: true, tlsCertExists: true, tlsServing: false }, "tls");
    assert.equal(r.status, "warn");
    assert.match(r.value, /disabled \(HTTP only\)/);
  });

  it("names which half is missing, because that is the fix", function () {
    assert.match(row({ tlsKeyExists: true, tlsCertExists: false }, "tls").value,
      /key present, certificate missing/);
    assert.match(row({ tlsKeyExists: false, tlsCertExists: true }, "tls").value,
      /certificate present, key missing/);
    assert.equal(row({}, "tls").value, "disabled (HTTP only)");
  });

  it("points a key-without-certificate deployment at the chain", function () {
    assert.match(row({ tlsKeyExists: true, tlsCertExists: false }, "tls").guidance,
      /Mount the chain at data\/tls\/fullchain\.pem/);
  });

  it("offers no guidance when TLS is already serving", function () {
    assert.equal(row({ tlsServing: true }, "tls").guidance, null);
  });
});

describe("security status — mTLS enforcement row", function () {
  it("reports hard enforcement only when it is actually in force", function () {
    var r = row({ enforceMtlsStrict: "true", mtlsHardEnforced: true, tlsServing: true, caExists: true }, "mtls_enforcement");
    assert.equal(r.status, "ok");
    assert.equal(r.value, "hard (TLS layer)");
  });

  it("does not claim hard enforcement on a server with no TLS listener", function () {
    // Asking for it does not make it so: rejectUnauthorized is a property of a
    // TLS listener, and without one no client certificate is required anywhere.
    var r = row({ enforceMtlsStrict: "true", caExists: true, tlsServing: false, mtlsHardEnforced: false }, "mtls_enforcement");
    assert.notEqual(r.value, "hard (TLS layer)");
    assert.equal(r.status, "warn");
    assert.match(r.guidance, /running without TLS — no client certificate is required on any connection/);
  });

  it("says something different when the app layer is picking up the slack", function () {
    // Same misconfiguration, but the middleware IS enforcing. Telling this
    // operator nothing is enforced would be its own false claim.
    var r = row({ enforceMtlsStrict: "true", caExists: true, tlsServing: false,
      mtlsHardEnforced: false, mtlsSoftEnforced: true }, "mtls_enforcement");
    assert.equal(r.status, "info");
    assert.equal(r.value, "soft (app layer)");
    assert.match(r.guidance, /still required by the app-layer check/);
  });

  it("does not repeat advice the operator has already taken", function () {
    var r = row({ enforceMtlsStrict: "true", caExists: true, tlsServing: false, mtlsHardEnforced: false }, "mtls_enforcement");
    assert.ok(!/Set ENFORCE_MTLS_STRICT=true for hard enforcement/.test(r.guidance),
      "ENFORCE_MTLS_STRICT is already true here: " + r.guidance);
  });

  it("marks the escape hatch as off rather than as enforcement", function () {
    var r = row({ enforceMtlsStrict: "false", mtlsHardEnforced: false, mtlsSoftEnforced: false }, "mtls_enforcement");
    assert.equal(r.value, "OFF (escape hatch)");
    assert.match(r.guidance, /escape hatch for locked-out operators/);
  });

  it("warns when nothing is enforcing at all", function () {
    assert.equal(row({}, "mtls_enforcement").status, "warn");
    assert.equal(row({}, "mtls_enforcement").value, "off");
  });
});

describe("security status — vault passphrase row", function () {
  it("is ok only when required AND the sealed key exists", function () {
    assert.equal(row({ vaultMode: "required", vaultSealedExists: true }, "vault_passphrase").status, "ok");
  });

  it("warns when required but the sealed key is missing — the next boot fails", function () {
    assert.equal(row({ vaultMode: "required", vaultSealedExists: false }, "vault_passphrase").status, "warn");
  });

  it("offers Enable only when there is a plaintext key to wrap", function () {
    var withKey = row({ vaultKeyExists: true }, "vault_passphrase");
    assert.equal(withKey.actions.length, 1);
    assert.equal(withKey.actions[0].kind, "seal");
    assert.equal(withKey.actions[0].needsPassphrase, true);
    assert.deepEqual(row({ vaultKeyExists: false }, "vault_passphrase").actions, [],
      "nothing to wrap means no button");
  });

  it("offers Disable once it is sealed, and warns what the restart needs", function () {
    var r = row({ vaultMode: "required", vaultSealedExists: true, vaultKeyExists: true }, "vault_passphrase");
    assert.equal(r.actions.length, 1);
    assert.equal(r.actions[0].kind, "unseal");
    assert.match(r.actions[0].confirmText, /unset VAULT_PASSPHRASE_MODE before the next restart/);
  });
});

describe("security status — CA and TLS key sealing rows", function () {
  it("distinguishes no-CA-yet from an unsealed CA", function () {
    assert.equal(row({}, "ca_key_sealed").value, "no CA generated yet");
    assert.equal(row({ caExists: true, caPlainExists: true }, "ca_key_sealed").value, "disabled (ca.key plaintext)");
    assert.equal(row({ caSealedExists: true }, "ca_key_sealed").value, "active (ca.key.sealed)");
  });

  it("offers Enable for a CA key only once one exists in plaintext", function () {
    assert.deepEqual(row({}, "ca_key_sealed").actions, []);
    assert.equal(row({ caExists: true, caPlainExists: true }, "ca_key_sealed").actions[0].kind, "seal");
    assert.equal(row({ caSealedExists: true }, "ca_key_sealed").actions[0].kind, "unseal");
  });

  it("is ok for the CA key only when required AND sealed", function () {
    assert.equal(row({ caKeyMode: "required", caSealedExists: true }, "ca_key_sealed").status, "ok");
    assert.equal(row({ caKeyMode: "auto", caSealedExists: true }, "ca_key_sealed").status, "info");
  });

  it("distinguishes no-TLS-key from an unsealed one", function () {
    assert.equal(row({}, "tls_key_sealed").value, "no TLS key configured");
    assert.equal(row({ tlsPlainExists: true }, "tls_key_sealed").value, "disabled (privkey.pem plaintext)");
    assert.equal(row({ tlsSealedExists: true }, "tls_key_sealed").value, "active (privkey.pem.sealed)");
  });

  it("is ok for the TLS key only when required AND sealed", function () {
    assert.equal(row({ tlsKeyMode: "required", tlsSealedExists: true }, "tls_key_sealed").status, "ok");
    assert.equal(row({ tlsKeyMode: "auto", tlsSealedExists: true }, "tls_key_sealed").status, "info");
  });

  it("tells an operator with no TLS key to configure TLS first", function () {
    assert.match(row({}, "tls_key_sealed").guidance, /Configure TLS first/);
  });
});

describe("security status — notes", function () {
  it("explains the two env-var conventions rather than leaving them looking inconsistent", function () {
    var notes = buildReport(state()).notes;
    assert.equal(notes.length, 2);
    assert.match(notes[0], /Two env-var conventions/);
    assert.match(notes[1], /not displayed here/);
  });

  it("never puts a boot-time secret in the payload", function () {
    // The row values and notes are rendered verbatim in the admin page.
    var report = buildReport(state({
      vaultMode: "required", vaultSealedExists: true, vaultKeyExists: true,
      caSealedExists: true, tlsSealedExists: true, tlsServing: true,
    }));
    var blob = JSON.stringify(report);
    ["VAULT_PASSPHRASE=", "BACKUP_PASSPHRASE=", "-----BEGIN"].forEach(function (needle) {
      assert.ok(blob.indexOf(needle) === -1, "payload must not carry " + needle);
    });
  });
});
