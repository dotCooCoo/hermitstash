"use strict";
/**
 * b.processSpawn — child-process launcher with default secret-stripping.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  // filteredEnv strips known secret-shaped names.
  var src = {
    PATH:                "/usr/bin",
    DATABASE_URL:        "postgres://x:y@h/db",
    PGPASSWORD:          "secret",
    AWS_SECRET_ACCESS_KEY: "AKIA...",
    APP_API_KEY:         "secret-key",
    GOOGLE_APPLICATION_CREDENTIALS: "/path/to/key.json",
    SOMETHING_BENIGN:    "value",
  };
  var built = b.processSpawn.filteredEnv(src);
  check("filteredEnv: PATH preserved",
    built.env.PATH === "/usr/bin");
  check("filteredEnv: DATABASE_URL stripped",
    built.env.DATABASE_URL === undefined &&
    built.filtered.indexOf("DATABASE_URL") !== -1);
  check("filteredEnv: PGPASSWORD stripped",
    built.env.PGPASSWORD === undefined);
  check("filteredEnv: AWS_SECRET_ACCESS_KEY stripped",
    built.env.AWS_SECRET_ACCESS_KEY === undefined);
  check("filteredEnv: *_API_KEY stripped",
    built.env.APP_API_KEY === undefined);
  check("filteredEnv: GOOGLE_APPLICATION_CREDENTIALS stripped",
    built.env.GOOGLE_APPLICATION_CREDENTIALS === undefined);
  check("filteredEnv: SOMETHING_BENIGN preserved",
    built.env.SOMETHING_BENIGN === "value");

  // allowEnv list lets specific names through.
  var allowed = b.processSpawn.filteredEnv(src, ["DATABASE_URL"]);
  check("filteredEnv: allowEnv pass-through",
    allowed.env.DATABASE_URL === "postgres://x:y@h/db");

  // spawn() requires a non-empty command.
  var threw;
  try { b.processSpawn.spawn(""); } catch (e) { threw = e; }
  check("spawn: empty command throws",
    threw && threw.code === "process-spawn/bad-command");

  check("processSpawn.ProcessSpawnError class registered",
    typeof b.processSpawn.ProcessSpawnError === "function");
  check("processSpawn.FILTER_PATTERNS exposes regex array",
    Array.isArray(b.processSpawn.FILTER_PATTERNS));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[process-spawn] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
