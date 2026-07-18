// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live OpenID Federation 1.0 trust-chain round-trip over loopback HTTP.
 *
 * Unlike the layer-0 unit test (which drives buildTrustChain against an
 * in-memory fetcher), this harness stands up THREE real loopback
 * entity-statement servers — anchor -> intermediate -> leaf — each
 * serving its own `/.well-known/openid-federation` self-configuration
 * plus a superior-signed subordinate statement from its
 * `federation_fetch_endpoint`. buildTrustChain / resolveLeaf are driven
 * with a fetcher that performs a genuine `b.httpClient` GET against those
 * servers, so the whole fetch + top-down verification path runs over the
 * wire.
 *
 * It asserts the two provenance / policy properties fixed in v0.16.22 /
 * v0.16.23:
 *
 *   - buildTrustChain REJECTS a leaf whose entity configuration is signed
 *     by a key the superior does NOT attest (an attacker who controls the
 *     leaf's .well-known endpoint but not its federation-attested key).
 *     The honest superior's subordinate statement pins the leaf's real
 *     keys; the forged self-config must fail the top-down re-verify with
 *     bad-signature (v0.16.22 — config bound to superior-attested keys).
 *
 *   - applyMetadataPolicy REFUSES a subordinate that tries to escape a
 *     superior's constraint through a DIFFERENT operator: a leaf-ward
 *     `value` against an anchor `one_of`, and a leaf-ward `add` past an
 *     anchor `subset_of` (v0.16.23 — cross-operator policy merge).
 *
 * No docker services are required; this file runs in-process.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var nodeHttp   = require("node:http");

// ---- entity-statement minting (in-process keys) --------------------------
// Mirrors test/layer-0-primitives/openid-federation.test.js so the wire
// statements are byte-identical to the unit-test fixtures, just served over
// real HTTP instead of an in-memory map.

function _b64url(buf) { return Buffer.from(buf).toString("base64url"); }

function _ecEntity(kid) {
  var kp  = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var jwk = kp.publicKey.export({ format: "jwk" });
  jwk.kid = kid;
  return { priv: kp.privateKey, jwk: jwk, jwks: { keys: [jwk] } };
}

function _mint(priv, kid, claims) {
  var header = { typ: "entity-statement+jwt", alg: "ES256", kid: kid };
  var input  = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(claims));
  var sig    = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), { key: priv, dsaEncoding: "ieee-p1363" });
  return input + "." + _b64url(sig);
}

var _NOW = Math.floor(Date.now() / 1000);                                        // allow:raw-byte-literal — seconds-per-ms
function _cfg(id, entity, extra) {
  var c = { iss: id, sub: id, iat: _NOW, exp: _NOW + 3600, jwks: entity.jwks };  // allow:raw-byte-literal — 1h validity
  if (extra) Object.keys(extra).forEach(function (k) { c[k] = extra[k]; });
  return c;
}

// ---- loopback servers ----------------------------------------------------
// One server per federation entity (each entity_id is an origin, so distinct
// ports are required). Every server reads the JWT it should return from the
// shared, per-scenario `served` map so a test can swap the served config /
// subordinate statement without rebinding ports.

var served = {
  leaf:   { config: null, subBySub: {} },
  inter:  { config: null, subBySub: {} },
  anchor: { config: null, subBySub: {} },
};

function _mkServer(which) {
  return nodeHttp.createServer(function (req, res) {
    var u = req.url || "";
    if (u.indexOf("/.well-known/openid-federation") === 0) {
      var cfg = served[which].config;
      if (!cfg) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { "Content-Type": "application/entity-statement+jwt" });
      return res.end(cfg);
    }
    if (u.indexOf("/fetch") === 0) {
      var sub = new URL(u, "http://127.0.0.1").searchParams.get("sub");
      var stmt = sub && served[which].subBySub[sub];
      if (!stmt) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { "Content-Type": "application/entity-statement+jwt" });
      return res.end(stmt);
    }
    res.writeHead(404);
    res.end();
  });
}

// A real HTTP fetcher — buildTrustChain's default subordinate fetcher calls it
// for both the .well-known discovery and the federation_fetch_endpoint pull, so
// the entire fetch path exercises the wire. Non-2xx surfaces as a throw (the
// framework http client rejects 4xx in buffer mode), which the chain builder
// treats as a failed hint.
function _loopbackFetcher(url) {
  return b.httpClient.request({
    method:           "GET",
    url:              url,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
  }).then(function (res) { return res.body.toString("utf8"); });
}

async function run() {
  // Keys: leaf (honest), evil (an attacker key sharing the leaf's kid so a
  // forged config forces a signature check, not a kid mismatch), intermediate,
  // anchor. Generated once and reused across scenarios.
  var leaf   = _ecEntity("leaf-k");
  var evil   = _ecEntity("leaf-k");
  var inter  = _ecEntity("inter-k");
  var anchor = _ecEntity("anchor-k");

  var leafSrv   = _mkServer("leaf");
  var interSrv  = _mkServer("inter");
  var anchorSrv = _mkServer("anchor");
  var leafId, interId, anchorId, anchors;
  try {
    var leafPort   = await helpers.listenOnRandomPort(leafSrv);
    var interPort  = await helpers.listenOnRandomPort(interSrv);
    var anchorPort = await helpers.listenOnRandomPort(anchorSrv);
    leafId   = "http://127.0.0.1:" + leafPort;
    interId  = "http://127.0.0.1:" + interPort;
    anchorId = "http://127.0.0.1:" + anchorPort;
    anchors  = {}; anchors[anchorId] = anchor.jwks;

    // Populate the three servers for one scenario. `opts`:
    //   forgeLeaf     — sign the leaf self-config with `evil` (same kid) while
    //                   the intermediate still pins the leaf's REAL keys.
    //   leafMetadata  — the leaf's declared metadata (default a bare RP).
    //   anchorPolicy  — metadata_policy the anchor signs onto the intermediate.
    //   interPolicy   — metadata_policy the intermediate signs onto the leaf.
    function _install(opts) {
      opts = opts || {};
      var leafSigner = opts.forgeLeaf ? evil : leaf;
      served.leaf.config = _mint(leafSigner.priv, "leaf-k", _cfg(leafId, leafSigner, {
        authority_hints: [interId],
        metadata:        opts.leafMetadata || { openid_relying_party: { client_name: "RP" } },
      }));
      served.inter.config = _mint(inter.priv, "inter-k", _cfg(interId, inter, {
        authority_hints:            [anchorId],
        federation_fetch_endpoint:  interId + "/fetch",
      }));
      served.anchor.config = _mint(anchor.priv, "anchor-k", _cfg(anchorId, anchor, {
        federation_fetch_endpoint: anchorId + "/fetch",
      }));
      // Intermediate-signed subordinate ABOUT the leaf — pins the leaf's REAL
      // keys (+ optional policy). This is what the top-down verify trusts.
      var subLeaf = { iss: interId, sub: leafId, iat: _NOW, exp: _NOW + 3600, jwks: leaf.jwks };  // allow:raw-byte-literal — 1h validity
      if (opts.interPolicy) subLeaf.metadata_policy = opts.interPolicy;
      served.inter.subBySub[leafId] = _mint(inter.priv, "inter-k", subLeaf);
      // Anchor-signed subordinate ABOUT the intermediate — pins the
      // intermediate's REAL keys (+ optional policy).
      var subInter = { iss: anchorId, sub: interId, iat: _NOW, exp: _NOW + 3600, jwks: inter.jwks };  // allow:raw-byte-literal — 1h validity
      if (opts.anchorPolicy) subInter.metadata_policy = opts.anchorPolicy;
      served.anchor.subBySub[interId] = _mint(anchor.priv, "anchor-k", subInter);
    }

    // ---- 1) Happy leaf -> intermediate -> anchor chain over real HTTP ----
    _install({});
    var chain = await b.auth.openidFederation.buildTrustChain({
      leafEntityId: leafId, trustAnchors: anchors, fetcher: _loopbackFetcher,
    });
    check("buildTrustChain: 3-node leaf+intermediate+anchor over loopback",
      chain.length === 3 && chain[0].role === "leaf" &&
      chain[1].role === "intermediate" && chain[2].role === "trust_anchor");
    var resolved = await b.auth.openidFederation.resolveLeaf({
      leafEntityId: leafId, trustAnchors: anchors, kind: "openid_relying_party",
      fetcher: _loopbackFetcher,
    });
    check("resolveLeaf: effective metadata + anchor resolved over loopback",
      resolved.trustAnchor === anchorId && resolved.effectiveMetadata.client_name === "RP");

    // ---- 2) Leaf config signed by a NON-attested key is refused ----------
    // The attacker controls the leaf's .well-known endpoint (serves a config
    // signed by `evil`, carrying attacker metadata) but not the leaf's
    // federation-attested key; the intermediate's subordinate pins the leaf's
    // REAL keys. The top-down re-verify must reject with bad-signature.
    _install({ forgeLeaf: true, leafMetadata: { openid_relying_party: { client_name: "ATTACKER", redirect_uris: ["http://127.0.0.1:1/evil"] } } });
    var forgedThrew = null;
    try {
      await b.auth.openidFederation.buildTrustChain({
        leafEntityId: leafId, trustAnchors: anchors, fetcher: _loopbackFetcher,
      });
    } catch (e) { forgedThrew = e; }
    check("buildTrustChain: leaf config signed by non-attested key refused (bad-signature)",
      !!forgedThrew && /auth-openid-federation\/bad-signature/.test(forgedThrew.code || ""));
    var forgedResolveThrew = null;
    try {
      await b.auth.openidFederation.resolveLeaf({
        leafEntityId: leafId, trustAnchors: anchors, kind: "openid_relying_party",
        fetcher: _loopbackFetcher,
      });
    } catch (e) { forgedResolveThrew = e; }
    check("resolveLeaf: forged leaf metadata never resolved (config unbound to pinned keys)",
      !!forgedResolveThrew && /auth-openid-federation\/bad-signature/.test(forgedResolveThrew.code || ""));

    // ---- 3) Cross-operator downgrade: leaf-ward `value` vs anchor `one_of` -
    // The anchor pins token_endpoint_auth_method one_of ['private_key_jwt'];
    // the intermediate tries to substitute value 'none' (removing client auth).
    // The merged policy must refuse the final value, not silently downgrade.
    _install({
      anchorPolicy: { openid_relying_party: { token_endpoint_auth_method: { one_of: ["private_key_jwt"] } } },
      interPolicy:  { openid_relying_party: { token_endpoint_auth_method: { value: "none" } } },
    });
    var oneOfChain = await b.auth.openidFederation.buildTrustChain({
      leafEntityId: leafId, trustAnchors: anchors, fetcher: _loopbackFetcher,
    });
    var oneOfThrew = null;
    try {
      b.auth.openidFederation.applyMetadataPolicy(
        oneOfChain[0].claims.metadata.openid_relying_party, oneOfChain, "openid_relying_party");
    } catch (e) { oneOfThrew = e; }
    check("applyMetadataPolicy: subordinate `value` cannot override a superior `one_of` (policy-one-of-failed)",
      !!oneOfThrew && /auth-openid-federation\/policy-one-of-failed/.test(oneOfThrew.code || ""));

    // ---- 4) Cross-operator downgrade: leaf-ward `add` past anchor `subset_of`
    // The anchor pins scope subset_of ['read']; the intermediate adds 'write'.
    // The merged policy must refuse the widened value.
    _install({
      leafMetadata: { openid_relying_party: { scope: ["read"] } },
      anchorPolicy: { openid_relying_party: { scope: { subset_of: ["read"] } } },
      interPolicy:  { openid_relying_party: { scope: { add: ["write"] } } },
    });
    var subsetChain = await b.auth.openidFederation.buildTrustChain({
      leafEntityId: leafId, trustAnchors: anchors, fetcher: _loopbackFetcher,
    });
    var subsetThrew = null;
    try {
      b.auth.openidFederation.applyMetadataPolicy(
        subsetChain[0].claims.metadata.openid_relying_party, subsetChain, "openid_relying_party");
    } catch (e) { subsetThrew = e; }
    check("applyMetadataPolicy: subordinate `add` cannot widen past a superior `subset_of` (policy-subset-of-failed)",
      !!subsetThrew && /auth-openid-federation\/policy-subset-of-failed/.test(subsetThrew.code || ""));

    // ---- 5) A consistent narrowing still resolves (guards a false-refuse) --
    // The intermediate `add` stays WITHIN the anchor's subset_of — a legitimate
    // narrowing that must pass, proving the refusals above are not blanket.
    _install({
      leafMetadata: { openid_relying_party: { scope: ["read"] } },
      anchorPolicy: { openid_relying_party: { scope: { subset_of: ["read", "write"] } } },
      interPolicy:  { openid_relying_party: { scope: { add: ["write"] } } },
    });
    var okChain = await b.auth.openidFederation.buildTrustChain({
      leafEntityId: leafId, trustAnchors: anchors, fetcher: _loopbackFetcher,
    });
    var okEffective = b.auth.openidFederation.applyMetadataPolicy(
      okChain[0].claims.metadata.openid_relying_party, okChain, "openid_relying_party");
    check("applyMetadataPolicy: consistent narrowing (add within subset_of) still resolves",
      okEffective.scope.indexOf("read") !== -1 && okEffective.scope.indexOf("write") !== -1);
  } finally {
    leafSrv.close();
    interSrv.close();
    anchorSrv.close();
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(
    function () { console.log("[openid-federation-chain] OK"); },
    function (e) { console.error("[openid-federation-chain] FAIL:", e.stack || e); process.exit(1); }
  );
}
