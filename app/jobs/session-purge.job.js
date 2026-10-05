/**
 * run() calls purgeStaleSessions and then compactSessionStore, and logs the
 * result when either one changed the session store. server-main.js calls run()
 * once at boot and registers it to run every hour.
 */
var session = require("../../lib/session");
var logger = require("../shared/logger");

async function run() {
  var removed = await session.purgeStaleSessions();
  var compacted = await session.compactSessionStore();
  if (removed > 0 || compacted) {
    logger.info("[session-purge] Removed " + removed + " stale sessions", { removed: removed, compacted: compacted });
  }
  return { removed: removed, compacted: compacted };
}

module.exports = { run: run };
