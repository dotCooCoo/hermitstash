"use strict";

/**
 * TLS secure-context material for the listener.
 *
 * Lives here rather than inline in server-main.js so the certificate-renewal
 * path and a test can build the SAME object. server.setSecureContext() replaces
 * the context wholesale — every option the caller omits is assigned undefined
 * rather than carried over from the context the listener booted with — so a
 * reload assembled ad hoc silently drops whatever it forgets. It forgot the
 * mTLS trust bundle, and client certificates stopped verifying from the first
 * renewal onward while the listener stayed up and still reported mTLS as
 * configured. Building it in one place is what lets a test assert against the
 * real thing instead of a copy that can drift away from it.
 */

var nodeFs = require("node:fs");
var b = require("./vendor/blamejs");
var mtlsCa = require("./mtls-ca");
var mtlsCaBrowser = require("./mtls-ca-browser");

/**
 * The mTLS trust bundle, read fresh from disk.
 *
 * Dual-CA: the server trusts BOTH the sync CA (ca.crt — may be ML-DSA-87 after
 * the PQC migration) AND the classical browser CA (ca-browser.crt), so machine
 * sync clients and browser-imported PKCS#12 client certs both authenticate.
 * During a sync-CA algorithm migration the superseded CA (ca.prev.crt) is
 * trusted too, so existing sync certs keep verifying while their owners
 * re-enroll. Each is read from the singleton's RESOLVED path — operators may
 * override via MTLS_CA_CERT / MTLS_BROWSER_CA_CERT to an absolute path outside
 * DATA_DIR.
 *
 * Read fresh rather than from a boot-time snapshot so a certificate-authority
 * rotation reaches the running listener instead of waiting for a restart.
 */
function caListSync() {
  var list = [];
  if (mtlsCa.exists()) list.push(nodeFs.readFileSync(mtlsCa.paths.caCert));
  if (mtlsCaBrowser.exists()) list.push(nodeFs.readFileSync(mtlsCaBrowser.paths.caCert));
  if (mtlsCa.paths.caCertPrev && nodeFs.existsSync(mtlsCa.paths.caCertPrev)) {
    list.push(nodeFs.readFileSync(mtlsCa.paths.caCertPrev));
  }
  return list;
}

/**
 * The same bundle, read through each authority's locked snapshot.
 *
 * A rotation publishes the retained root and the new current root as separate
 * writes. Reading the files independently can land between them and observe
 * neither state: the old current alongside the already-retained old root, with
 * the new root missing. Installing that leaves clients enrolled under the new
 * CA failing verification until something triggers another reload. Each
 * authority's `loadTrustBundle()` takes the lock and returns a consistent
 * `[current, ...retained]`, which is what a reload racing a rotation needs.
 *
 * Boot uses the synchronous reader instead, deliberately: it runs after the
 * boot migration has reconciled the handles and before anything can rotate, so
 * there is no window to guard, and making it async would push a `await` into
 * listener construction for no gain.
 */
async function caListLocked() {
  var sync = await mtlsCa.loadTrustBundle();
  var browser = await mtlsCaBrowser.loadTrustBundle();
  return [].concat(sync || [], browser || []);
}

/**
 * The object handed to server.setSecureContext() on a certificate reload.
 *
 * `cert`, `key` and `ecdhCurve` are supplied by the caller because only it
 * knows the resolved certificate paths and whether post-quantum enforcement has
 * narrowed the group list. Everything else that must survive a context
 * replacement is added here. requestCert and rejectUnauthorized are properties
 * of the listener rather than of the secure context and are deliberately absent
 * — setSecureContext does not touch them.
 *
 * `opts.ca` overrides the trust bundle for a caller that already holds one.
 * Omitted — which is how the server calls it — it reads the real bundle, so
 * there is no configuration in which leaving it out yields a context with no
 * trust anchors. It exists so a test can drive this exact function against a
 * throwaway CA rather than reimplementing what it returns, because a test that
 * asserts against its own copy of this object passes just as happily once this
 * one stops setting `ca`.
 */
async function reloadContext(opts) {
  var ca = opts.ca || await caListLocked();
  return {
    cert: opts.cert,
    key: opts.key,
    ecdhCurve: opts.ecdhCurve,
    minVersion: "TLSv1.3",
    ca: ca.length > 0 ? ca : undefined,
    certificateCompression: b.constants.TLS_CERT_COMPRESSION(),
  };
}

module.exports = {
  caListSync: caListSync,
  caListLocked: caListLocked,
  reloadContext: reloadContext,
};
