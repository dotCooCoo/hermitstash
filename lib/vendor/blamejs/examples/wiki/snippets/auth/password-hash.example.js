// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Hash an incoming password and persist the resulting Argon2id string.
// The verify path takes the same `stored` value back and the fresh
// plain text; framework upgrades the hash transparently when the
// posture parameters tighten between releases.

var hashed = await b.auth.password.hash(plain);
await db.users.insert({ email: email, passwordHash: hashed });

// On a later login:
var ok = await b.auth.password.verify(stored, plain);
if (b.auth.password.needsRehash(stored)) {
  var fresh = await b.auth.password.hash(plain);
  await db.users.update({ email: email }, { passwordHash: fresh });
}
