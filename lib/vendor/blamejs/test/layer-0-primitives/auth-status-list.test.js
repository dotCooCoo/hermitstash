// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.auth.statusList — IETF Token Status List (draft) revocation bitstring.
//
// B11: the relying-party read path (fromJwt().list.get) had NO bounds check —
// _getAt over-reads the inflated buffer and returns 0 for an out-of-range index,
// and status 0 = VALID. So a credential whose status_list index points PAST the
// decoded list read as "not revoked": a fail-OPEN revocation bypass. create().get
// already throws on a bad index; fromJwt().get must match (fail closed).
//
// RED on the buggy tree: fromJwt(...).list.get(size + N) returns 0 (valid).
// GREEN after the fix: it throws status-list/bad-index.
//
// Also the first dedicated behavioral coverage for the primitive (was only an
// export-presence check), driving the real create -> toJwt -> fromJwt path.

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("b.auth.statusList.create is a function", typeof b.auth.statusList.create === "function");
  check("b.auth.statusList.fromJwt is a function", typeof b.auth.statusList.fromJwt === "function");

  // ML-DSA-87 is available on the Node 24 CI floor (SLH-DSA keygen is Node-26+).
  var kp = nodeCrypto.generateKeyPairSync("ml-dsa-87");

  var list = b.auth.statusList.create({ size: 64, bits: 1 });
  list.set(5, 1);    // revoke index 5

  // create()/get already fail closed on a bad index (control for the contract).
  var createThrew = null;
  try { list.get(64); } catch (e) { createThrew = e.code; }
  check("create().get throws on an out-of-range index (fail closed)",
        createThrew === "status-list/bad-index");

  var token = await list.toJwt({
    issuer: "https://issuer.example", subject: "https://issuer.example/sl/1",
    privateKey: kp.privateKey, algorithm: "ML-DSA-87",
  });
  var parsed = await b.auth.statusList.fromJwt(token, {
    publicKey: kp.publicKey, algorithms: ["ML-DSA-87"],
    expectedIssuer: "https://issuer.example",
  });

  check("fromJwt round-trips the decoded list size", parsed.list.size === 64);
  check("fromJwt: revoked index reads as revoked (status 1)", parsed.list.get(5) === 1);
  check("fromJwt: an unset index reads as valid (status 0)", parsed.list.get(0) === 0);

  // #49 (RFC 8725 §3.11 typ-confusion): fromJwt binds header.typ to the
  // "statuslist+jwt" that toJwt stamps. A token carrying a VALID status_list
  // claim but a different typ (minted for another purpose) must be refused on
  // the typ, before the claim check — every sibling verifier enforces its typ.
  var slPayload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
  var wrongTypToken = await b.auth.jwt.sign(slPayload, {
    privateKey: kp.privateKey, algorithm: "ML-DSA-87", typ: "JWT",
  });
  var typThrew = null;
  try {
    await b.auth.statusList.fromJwt(wrongTypToken, {
      publicKey: kp.publicKey, algorithms: ["ML-DSA-87"], expectedIssuer: "https://issuer.example",
    });
  } catch (e) { typThrew = e.code; }
  check("fromJwt rejects a typ-confused token carrying a valid status_list claim (auth-jwt/typ-mismatch)",
        typThrew === "auth-jwt/typ-mismatch");

  // B11: the out-of-range read MUST fail closed, not read 0/valid.
  var oobThrew = null, oobValue;
  try { oobValue = parsed.list.get(parsed.list.size + 10); }
  catch (e) { oobThrew = e.code; }
  check("fromJwt().get throws on an out-of-range index (no fail-open revocation bypass)",
        oobThrew === "status-list/bad-index");
  check("fromJwt().get did NOT return a status for the out-of-range index",
        oobValue === undefined);
  // Negative + non-integer indices fail closed too.
  var negThrew = null;
  try { parsed.list.get(-1); } catch (e) { negThrew = e.code; }
  check("fromJwt().get fails closed on a negative index", negThrew === "status-list/bad-index");
  var fracThrew = null;
  try { parsed.list.get(3.5); } catch (e) { fracThrew = e.code; }
  check("fromJwt().get fails closed on a non-integer index", fracThrew === "status-list/bad-index");

  console.log("OK — auth status-list (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
