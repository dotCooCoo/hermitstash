"use strict";
/**
 * b.backup.runInWorker — worker_threads dispatch helper for backup
 * and restore long-running operations.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  var rejected;
  try {
    await b.backup.runInWorker({});
  } catch (e) { rejected = e; }
  check("backup.runInWorker: missing workerScript rejects",
    rejected && rejected.code === "backup/no-worker-script");

  var rejected2;
  try {
    await b.backup.runInWorker({ workerScript: "/dev/null/nope.js", timeoutMs: -1 });
  } catch (e) { rejected2 = e; }
  check("backup.runInWorker: negative timeoutMs rejects",
    rejected2 && rejected2.code === "backup/bad-timeout");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-worker] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
