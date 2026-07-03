// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.keychain — fail-closed / concurrency guarantees for the encrypted
 * file backend. Everything here drives the public API with
 * `preferFile: true` so the file backend is exercised deterministically.
 * Focuses on:
 *
 *   - Concurrent stores to the same fallbackFile never drop a binding.
 *     The read-modify-write is serialized through the file mutex, so two
 *     stores that would otherwise each read the pre-update document and
 *     clobber one another's write both survive.
 *   - Concurrent store + remove on the same file leave a consistent
 *     document (the RMW in remove is serialized the same way).
 *   - remove rejects a relative fallbackFile with the same typed error
 *     store/retrieve raise, instead of silently returning a no-op false.
 */
var fs = require("fs");
var os = require("os");
var path = require("path");

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

// Hardcoded fixture names — no operator input crosses this boundary.
// path.join composes os.tmpdir() with a literal string + fs.mkdtempSync's
// random suffix; nothing here is operator-controlled.
var _TMP_PREFIX = "blamejs-keychain-fc-";
var _TMP_DEFAULT_NAME = "keychain.enc";

function _tmpFile(leaf) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), _TMP_PREFIX));
  return path.join(dir, leaf || _TMP_DEFAULT_NAME);
}

async function run() {
  var pass = "correct horse battery staple";
  var threw;

  // ---- Concurrent stores keep every binding ------------------------------
  // Seed the file first so every store's read hits real async unseal I/O,
  // then fire N stores of distinct (service, account) pairs at the same
  // fallbackFile in parallel. Without a serialized read-modify-write each
  // store reads the pre-update document and the last writer wins, dropping
  // the rest. With the file mutex every binding survives.
  var ffConc = _tmpFile();
  await b.keychain.store({
    service: "seed", account: "a", password: "SEED", preferFile: true,
    fallbackFile: ffConc, passphrase: pass,
  });

  var N = 8;
  var ops = [];
  for (var i = 0; i < N; i++) {
    ops.push(b.keychain.store({
      service: "svc" + i, account: "acct", password: "pw" + i,
      preferFile: true, fallbackFile: ffConc, passphrase: pass,
    }));
  }
  await Promise.all(ops);

  var present = 0;
  for (var j = 0; j < N; j++) {
    var got = await b.keychain.retrieve({
      service: "svc" + j, account: "acct", preferFile: true,
      fallbackFile: ffConc, passphrase: pass,
    });
    if (got && got.password === "pw" + j) present++;
  }
  check("keychain.store: concurrent stores keep every binding",
    present === N);

  var seedStill = await b.keychain.retrieve({
    service: "seed", account: "a", preferFile: true,
    fallbackFile: ffConc, passphrase: pass,
  });
  check("keychain.store: concurrent stores don't drop the seed binding",
    seedStill && seedStill.password === "SEED");

  // ---- Concurrent store + remove stay consistent -------------------------
  // A remove racing a store on the same file must not lose the store's
  // write (nor leave the removed key present). Serializing both RMWs
  // through the file mutex keeps the document consistent.
  var ffMix = _tmpFile();
  await b.keychain.store({
    service: "keep", account: "a", password: "KEEP", preferFile: true,
    fallbackFile: ffMix, passphrase: pass,
  });
  await b.keychain.store({
    service: "drop", account: "a", password: "DROP", preferFile: true,
    fallbackFile: ffMix, passphrase: pass,
  });
  await Promise.all([
    b.keychain.store({
      service: "added", account: "a", password: "ADDED", preferFile: true,
      fallbackFile: ffMix, passphrase: pass,
    }),
    b.keychain.remove({
      service: "drop", account: "a", preferFile: true,
      fallbackFile: ffMix, passphrase: pass,
    }),
  ]);
  var keepGot = await b.keychain.retrieve({
    service: "keep", account: "a", preferFile: true,
    fallbackFile: ffMix, passphrase: pass,
  });
  var addedGot = await b.keychain.retrieve({
    service: "added", account: "a", preferFile: true,
    fallbackFile: ffMix, passphrase: pass,
  });
  var dropGot = await b.keychain.retrieve({
    service: "drop", account: "a", preferFile: true,
    fallbackFile: ffMix, passphrase: pass,
  });
  check("keychain: concurrent store+remove keeps the added binding",
    addedGot && addedGot.password === "ADDED");
  check("keychain: concurrent store+remove keeps the untouched binding",
    keepGot && keepGot.password === "KEEP");
  check("keychain: concurrent store+remove drops the removed binding",
    dropGot === null);

  // ---- remove rejects a relative fallbackFile ----------------------------
  // store and retrieve validate the fallbackFile (must be absolute) before
  // touching disk; remove must refuse the same way rather than silently
  // no-op'ing on a relative path that atomicFile.exists reads as absent.
  threw = null;
  try {
    await b.keychain.remove({
      service: "s", account: "a", preferFile: true,
      fallbackFile: "relative/keychain.enc", passphrase: pass,
    });
  } catch (e) { threw = e; }
  check("keychain.remove: relative fallbackFile throws relative-fallback-file",
    threw && threw.code === "keychain/relative-fallback-file");

  // Counter-check: the same relative path is refused by store, so remove
  // now matches the family rather than diverging.
  threw = null;
  try {
    await b.keychain.store({
      service: "s", account: "a", password: "p", preferFile: true,
      fallbackFile: "relative/keychain.enc", passphrase: pass,
    });
  } catch (e) { threw = e; }
  check("keychain.store: relative fallbackFile throws relative-fallback-file",
    threw && threw.code === "keychain/relative-fallback-file");

  // A remove with no fallbackFile at all is still a clean no-op (false),
  // not a throw — validation only fires when a path is actually supplied.
  var noneRemove = await b.keychain.remove({
    service: "s", account: "a", preferFile: true,
  });
  check("keychain.remove: no fallbackFile still returns false (no throw)",
    noneRemove === false);

  // First-writer store into a not-yet-existing directory: the RMW lock's
  // sentinel file lives beside fallbackFile, so store must create the parent
  // directory before locking — otherwise the first store into a fresh path
  // fails where the pre-lock atomicFile.write created the dir lazily.
  var freshBase = path.join(os.tmpdir(), "kc-fc-firstwriter-" + process.pid);
  fs.rmSync(freshBase, { recursive: true, force: true });
  var freshFile = path.join(freshBase, "nested", "deep", "keychain.enc");
  var freshStored = await b.keychain.store({
    service: "s", account: "a", password: "pw", preferFile: true,
    fallbackFile: freshFile, passphrase: pass,
  });
  var freshGot = await b.keychain.retrieve({
    service: "s", account: "a", preferFile: true,
    fallbackFile: freshFile, passphrase: pass,
  });
  check("keychain.store: first writer creates the missing parent directory",
    freshStored.stored === true && !!freshGot && freshGot.password === "pw");
  fs.rmSync(freshBase, { recursive: true, force: true });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[keychain-failclosed] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
