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
//
// This file additionally exercises the primitive's adversarial branches — the
// lowest-branch-coverage verifier in the tree. Every read path (create().get,
// fromJwt().get) MUST fail closed; every claim/compression/signature failure
// on the receive side MUST throw (never read as status 0 / valid). The signed
// adversarial tokens are minted with the framework's own b.auth.jwt.sign so
// they carry a PASSING signature — the refusal comes from the status-list
// claim/compression checks, not a parse failure.

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

var nodeCrypto = require("node:crypto");
var zlib       = require("node:zlib");

var C       = require("../../lib/constants");
var bCrypto = require("../../lib/crypto");

async function run() {
  check("b.auth.statusList.create is a function", typeof b.auth.statusList.create === "function");
  check("b.auth.statusList.fromJwt is a function", typeof b.auth.statusList.fromJwt === "function");

  // ML-DSA-87 is available on the Node 24 CI floor (SLH-DSA keygen is Node-26+).
  var kp = nodeCrypto.generateKeyPairSync("ml-dsa-87");

  // ---- error-capture helpers (avoid a try/catch pyramid) ----
  function syncCode(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e && e.code; } }
  async function asyncCode(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e && e.code; } }

  // Mint a status-list token with an operator-crafted status_list claim, signed
  // with the issuer key + the "statuslist+jwt" typ (so fromJwt's typ bind and
  // signature check pass, and the refusal is on the crafted claim body).
  async function signSL(statusListClaim) {
    var claims = { iss: "https://issuer.example", sub: "https://issuer.example/sl/1" };
    if (statusListClaim !== undefined) claims.status_list = statusListClaim;
    return await b.auth.jwt.sign(claims, {
      privateKey: kp.privateKey, algorithm: "ML-DSA-87", typ: "statuslist+jwt",
    });
  }
  var verifyOpts = {
    publicKey: kp.publicKey, algorithms: ["ML-DSA-87"], expectedIssuer: "https://issuer.example",
  };

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

  // ---- exported status-value constants (draft §4.2 semantics) ----
  var SL = b.auth.statusList;
  check("STATUS_VALID constant is 0",                SL.STATUS_VALID === 0);
  check("STATUS_INVALID constant is 1",              SL.STATUS_INVALID === 1);
  check("STATUS_SUSPENDED constant is 2",            SL.STATUS_SUSPENDED === 2);
  check("STATUS_APPLICATION_SPECIFIC constant is 3", SL.STATUS_APPLICATION_SPECIFIC === 3);

  // ---- bit-width round trips (1/2/4/8) drive both _setAt/_getAt paths ----
  // bits=2/4 exercise the sub-byte packing; bits=8 exercises the byte fast path.
  var widths = [1, 2, 4, 8];
  for (var wi = 0; wi < widths.length; wi += 1) {
    var wbits = widths[wi];
    var wmax  = (1 << wbits) - 1;
    var wlist = b.auth.statusList.create({ size: 40, bits: wbits });
    wlist.set(1, 1);           // a set-but-not-max status at a sub-byte offset
    wlist.set(9, wmax);        // the ceiling status for this width
    check("create().get reads back the set status (bits=" + wbits + ")",
          wlist.get(1) === 1 && wlist.get(9) === wmax && wlist.get(0) === 0);
    check("create().bits reports the chosen width (bits=" + wbits + ")", wlist.bits === wbits);

    var wtok = await wlist.toJwt({
      issuer: "https://issuer.example", subject: "https://issuer.example/sl/1",
      privateKey: kp.privateKey, algorithm: "ML-DSA-87",
    });
    var wparsed = await b.auth.statusList.fromJwt(wtok, verifyOpts);
    check("fromJwt round-trips every status across the byte boundary (bits=" + wbits + ")",
          wparsed.list.get(1) === 1 && wparsed.list.get(9) === wmax && wparsed.list.get(0) === 0);
    check("fromJwt reports the token-declared bit width (bits=" + wbits + ")",
          wparsed.list.bits === wbits);
  }

  // Status semantics: a 2-bit list stores VALID/INVALID/SUSPENDED/APPLICATION_SPECIFIC.
  var semList = b.auth.statusList.create({ size: 8, bits: 2 });
  semList.set(0, SL.STATUS_VALID);
  semList.set(1, SL.STATUS_INVALID);
  semList.set(2, SL.STATUS_SUSPENDED);
  semList.set(3, SL.STATUS_APPLICATION_SPECIFIC);
  var semParsed = await b.auth.statusList.fromJwt(await semList.toJwt({
    issuer: "https://issuer.example", subject: "https://issuer.example/sl/1",
    privateKey: kp.privateKey, algorithm: "ML-DSA-87",
  }), verifyOpts);
  check("2-bit list round-trips all four status values (0/1/2/3)",
        semParsed.list.get(0) === 0 && semParsed.list.get(1) === 1 &&
        semParsed.list.get(2) === 2 && semParsed.list.get(3) === 3);

  // 8-bit list holds arbitrary application-specific status bytes (draft allows
  // an operator-defined status space when bits=8).
  var byteList = b.auth.statusList.create({ size: 4, bits: 8 });
  byteList.set(0, 200);
  byteList.set(1, 255);           // the 8-bit ceiling
  var byteParsed = await b.auth.statusList.fromJwt(await byteList.toJwt({
    issuer: "https://issuer.example", subject: "https://issuer.example/sl/1",
    privateKey: kp.privateKey, algorithm: "ML-DSA-87",
  }), verifyOpts);
  check("8-bit list round-trips arbitrary status bytes",
        byteParsed.list.get(0) === 200 && byteParsed.list.get(1) === 255);

  // ---- fill: prebuild every entry to a non-zero status ----
  var filled = b.auth.statusList.create({ size: 12, bits: 2, fill: SL.STATUS_SUSPENDED });
  check("create(fill) sets every entry to the fill status",
        filled.get(0) === 2 && filled.get(11) === 2);
  var fillZero = b.auth.statusList.create({ size: 4, bits: 1, fill: 0 });   // fill=0 is the no-op branch
  check("create(fill=0) leaves every entry valid", fillZero.get(0) === 0 && fillZero.get(3) === 0);

  // ---- snapshot() on both the issuer and relying-party list objects ----
  var issuerSnap = list.snapshot();
  check("create().snapshot() returns { size, bits, bytes-copy }",
        issuerSnap.size === 64 && issuerSnap.bits === 1 &&
        Buffer.isBuffer(issuerSnap.bytes) && issuerSnap.bytes.length === 8);
  issuerSnap.bytes[0] = 0xff;   // snapshot is a copy — mutating it must not corrupt the list
  check("create().snapshot() bytes are a defensive copy", list.get(0) === 0);
  var rpSnap = parsed.list.snapshot();
  check("fromJwt().snapshot() returns { size, bits, bytes-copy }",
        rpSnap.size === 64 && rpSnap.bits === 1 && Buffer.isBuffer(rpSnap.bytes));

  // ---- create() input validation (config-time: THROW) ----
  check("create rejects a non-object opts",           syncCode(function () { b.auth.statusList.create(null); }) === "BAD_OPT");
  check("create rejects size=0",                      syncCode(function () { b.auth.statusList.create({ size: 0 }); }) === "status-list/bad-size");
  check("create rejects a negative size",             syncCode(function () { b.auth.statusList.create({ size: -8 }); }) === "status-list/bad-size");
  check("create rejects a fractional size",           syncCode(function () { b.auth.statusList.create({ size: 3.5 }); }) === "status-list/bad-size");
  check("create rejects a non-number size",           syncCode(function () { b.auth.statusList.create({ size: "8" }); }) === "status-list/bad-size");
  check("create rejects a non-finite size",           syncCode(function () { b.auth.statusList.create({ size: Infinity }); }) === "status-list/bad-size");
  check("create rejects an unsupported bit width",    syncCode(function () { b.auth.statusList.create({ size: 8, bits: 3 }); }) === "status-list/bad-bits");
  check("create rejects a fill above the bit ceiling", syncCode(function () { b.auth.statusList.create({ size: 8, bits: 1, fill: 2 }); }) === "status-list/bad-status");
  var unknownOptErr = null;
  try { b.auth.statusList.create({ size: 8, boom: 1 }); } catch (e) { unknownOptErr = e; }
  check("create rejects an unknown option key",
        unknownOptErr !== null && /unknown option 'boom'/.test(unknownOptErr.message));

  // ---- set() input validation (idx bounds + status ceiling) ----
  var setList = b.auth.statusList.create({ size: 8, bits: 1 });
  check("set rejects idx >= size",               syncCode(function () { setList.set(8, 1); }) === "status-list/bad-index");
  check("set rejects a negative idx",            syncCode(function () { setList.set(-1, 1); }) === "status-list/bad-index");
  check("set rejects a fractional idx",          syncCode(function () { setList.set(2.5, 1); }) === "status-list/bad-index");
  check("set rejects a status above the ceiling", syncCode(function () { setList.set(0, 2); }) === "status-list/bad-status");
  check("set rejects a negative status",         syncCode(function () { setList.set(0, -1); }) === "status-list/bad-status");
  check("set rejects a fractional status",       syncCode(function () { setList.set(0, 1.5); }) === "status-list/bad-status");
  check("set rejects a NaN status",              syncCode(function () { setList.set(0, NaN); }) === "status-list/bad-status");
  check("set rejects a non-number status",       syncCode(function () { setList.set(0, "1"); }) === "status-list/bad-status");
  check("get rejects a non-number idx",          syncCode(function () { setList.get("0"); }) === "status-list/bad-index");

  // ---- toJwt() input validation ----
  check("toJwt rejects a non-object opts",  await asyncCode(function () { return setList.toJwt(null); }) === "BAD_OPT");
  check("toJwt rejects a missing issuer",   await asyncCode(function () { return setList.toJwt({ subject: "s", privateKey: kp.privateKey, algorithm: "ML-DSA-87" }); }) === "status-list/bad-issuer");
  check("toJwt rejects an empty issuer",    await asyncCode(function () { return setList.toJwt({ issuer: "", subject: "s", privateKey: kp.privateKey, algorithm: "ML-DSA-87" }); }) === "status-list/bad-issuer");
  check("toJwt rejects a missing subject",  await asyncCode(function () { return setList.toJwt({ issuer: "i", privateKey: kp.privateKey, algorithm: "ML-DSA-87" }); }) === "status-list/bad-subject");

  // toJwt stamps the optional ttl cache hint only when it is a number.
  var ttlToken = await setList.toJwt({
    issuer: "https://issuer.example", subject: "s",
    privateKey: kp.privateKey, algorithm: "ML-DSA-87", ttl: 300,
  });
  var ttlClaims = JSON.parse(Buffer.from(ttlToken.split(".")[1], "base64url").toString("utf8"));
  check("toJwt(ttl) writes the ttl claim", ttlClaims.ttl === 300);
  var noTtlClaims = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
  check("toJwt without ttl omits the ttl claim", noTtlClaims.ttl === undefined);

  // toJwt fails closed when the issuer's own compressed list exceeds the 1 MiB
  // on-the-wire cap (draft expects large lists to shard). Random bytes are
  // incompressible, so a >1 MiB 8-bit list deflates to >1 MiB.
  var oversize = C.BYTES.mib(1) + 512;
  var bigList = b.auth.statusList.create({ size: oversize, bits: 8 });
  var rnd = nodeCrypto.randomBytes(oversize);
  for (var bi = 0; bi < oversize; bi += 1) { if (rnd[bi] !== 0) bigList.set(bi, rnd[bi]); }
  check("toJwt refuses a compressed list larger than the wire cap",
        await asyncCode(function () {
          return bigList.toJwt({ issuer: "i", subject: "s", privateKey: kp.privateKey, algorithm: "ML-DSA-87" });
        }) === "status-list/too-large");

  // ---- fromJwt() input validation ----
  check("fromJwt rejects a non-object opts",     await asyncCode(function () { return b.auth.statusList.fromJwt(token, null); }) === "BAD_OPT");
  check("fromJwt rejects an empty-string token", await asyncCode(function () { return b.auth.statusList.fromJwt("", verifyOpts); }) === "status-list/bad-token");
  check("fromJwt rejects a non-string token",    await asyncCode(function () { return b.auth.statusList.fromJwt(12345, verifyOpts); }) === "status-list/bad-token");

  // ---- fromJwt() adversarial (signature-PASSING) claim + compression bodies ----
  // Every token below carries a valid issuer signature + the correct typ; the
  // refusal comes from the status-list claim/compression check, not a parse or
  // signature failure — a status read that fails OPEN here is a revocation bypass.
  var noStatusListToken = await signSL(undefined);
  var lstNotStringToken = await signSL({ bits: 1, lst: 123 });
  var badBitsToken      = await signSL({ bits: 3, lst: bCrypto.toBase64Url(zlib.deflateRawSync(Buffer.alloc(4))) });
  var badBase64Token    = await signSL({ bits: 1, lst: "@@@not-base64@@@" });
  // A DETERMINISTIC non-deflate payload: an all-0xFF buffer's first byte has
  // deflate BTYPE=3 (the reserved/invalid block type), so inflateRawSync always
  // rejects it. (Random bytes are NOT safe here — ~0.5% of random 64-byte
  // sequences are a valid-enough raw-deflate stream to inflate, which flaked
  // this check on CI.)
  var garbageInflateToken = await signSL({ bits: 1, lst: bCrypto.toBase64Url(Buffer.alloc(64, 0xff)) });
  // Decompression bomb: a tiny compressed payload that inflates past the 8x cap
  // (MAX_LIST_BYTES * 8) — zeros compress to a few KB but inflate to >8 MiB.
  var bombToken = await signSL({
    bits: 1, lst: bCrypto.toBase64Url(zlib.deflateRawSync(Buffer.alloc(C.BYTES.mib(1) * 8 + 64))),
  });

  check("fromJwt rejects a token with no status_list claim",
        await asyncCode(function () { return b.auth.statusList.fromJwt(noStatusListToken, verifyOpts); }) === "status-list/bad-claims");
  check("fromJwt rejects a status_list whose lst is not a string",
        await asyncCode(function () { return b.auth.statusList.fromJwt(lstNotStringToken, verifyOpts); }) === "status-list/bad-claims");
  check("fromJwt rejects a status_list with an unsupported bit width",
        await asyncCode(function () { return b.auth.statusList.fromJwt(badBitsToken, verifyOpts); }) === "status-list/bad-bits");
  check("fromJwt rejects an lst that is not valid base64url",
        await asyncCode(function () { return b.auth.statusList.fromJwt(badBase64Token, verifyOpts); }) === "status-list/bad-base64");
  check("fromJwt rejects an lst that base64-decodes to non-deflate garbage",
        await asyncCode(function () { return b.auth.statusList.fromJwt(garbageInflateToken, verifyOpts); }) === "status-list/inflate-failed");
  // The bomb must be refused, not expanded — inflateRawSync's maxOutputLength
  // fails closed. (fromJwt's own >1 MiB compressed-size check is unreachable
  // through this path: jwt.verify caps the JWT payload at 1 MiB via safeJson
  // before status-list decodes the lst, so the base64 lst can never carry
  // >1 MiB of compressed bytes. The inflate output cap below is the live guard.)
  check("fromJwt refuses a decompression bomb (inflate output cap fails closed)",
        await asyncCode(function () { return b.auth.statusList.fromJwt(bombToken, verifyOpts); }) === "status-list/inflate-failed");

  // ---- fromJwt() signature / clock failures propagate from the JWT verifier ----
  var otherKp = nodeCrypto.generateKeyPairSync("ml-dsa-87");
  check("fromJwt rejects a token signed by the wrong key",
        await asyncCode(function () {
          return b.auth.statusList.fromJwt(token, { publicKey: otherKp.publicKey, algorithms: ["ML-DSA-87"] });
        }) === "auth-jwt/invalid-signature");

  var tamperedPayload = Buffer.from(JSON.stringify({
    iss: "https://attacker.example", sub: "s",
    status_list: { bits: 1, lst: bCrypto.toBase64Url(zlib.deflateRawSync(Buffer.alloc(1))) },
  })).toString("base64url");
  var tokenParts = token.split(".");
  var tamperedToken = tokenParts[0] + "." + tamperedPayload + "." + tokenParts[2];
  check("fromJwt rejects a token whose payload was tampered after signing",
        await asyncCode(function () { return b.auth.statusList.fromJwt(tamperedToken, verifyOpts); }) === "auth-jwt/invalid-signature");

  var clock0 = 1700000000000;
  var expiredToken = await setList.toJwt({
    issuer: "https://issuer.example", subject: "s",
    privateKey: kp.privateKey, algorithm: "ML-DSA-87", expiresInSec: 60, now: clock0,
  });
  check("fromJwt rejects an expired status-list token",
        await asyncCode(function () {
          return b.auth.statusList.fromJwt(expiredToken, {
            publicKey: kp.publicKey, algorithms: ["ML-DSA-87"], now: clock0 + C.TIME.hours(1),
          });
        }) === "auth-jwt/expired");

  var notYetToken = await setList.toJwt({
    issuer: "https://issuer.example", subject: "s",
    privateKey: kp.privateKey, algorithm: "ML-DSA-87", notBeforeSec: 3600, now: clock0,
  });
  check("fromJwt rejects a not-yet-valid status-list token",
        await asyncCode(function () {
          return b.auth.statusList.fromJwt(notYetToken, {
            publicKey: kp.publicKey, algorithms: ["ML-DSA-87"], now: clock0,
          });
        }) === "auth-jwt/not-yet-valid");

  console.log("OK — auth status-list (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
