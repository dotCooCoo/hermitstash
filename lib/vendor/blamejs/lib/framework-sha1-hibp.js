// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * framework-sha1-hibp — SHA-1 hex digest, RESTRICTED to the
 * HaveIBeenPwned k-anonymity API caller (lib/auth/password.js policy).
 *
 * SHA-1 is broken for collision-resistance and trivially extendable;
 * the framework MUST NOT use it for storage, signing, message
 * authentication, key derivation, fingerprinting, or any other
 * security-relevant path. The HIBP API mandates SHA-1 for backwards
 * compatibility with leaked-password corpora; that's the only reason
 * this exists.
 *
 * Why not export from b.crypto:
 *   - Public exports invite cargo-cult use. A future contributor
 *     would search `b.crypto.sha1*` and slot it into "I just need
 *     a quick hash" code — re-introducing SHA-1 into a crypto-
 *     relevant path the framework spent every other primitive
 *     keeping out.
 *   - The single legitimate caller (auth/password.js) requires it
 *     for HIBP interop only. Restricting it to that module via a
 *     filename + comment-block gate keeps the surface honest.
 *
 * If a SECOND legitimate use case for SHA-1 ever emerges (operator
 * needs to interop with another SHA-1-mandated API), this module
 * stays internal — the new caller imports it directly. Public
 * `b.crypto.sha1*` is permanently off the table.
 */
var nodeCrypto = require("node:crypto");

function sha1Hex(data) {
  return nodeCrypto.createHash("sha1").update(data).digest("hex");
}

module.exports = { sha1Hex: sha1Hex };
