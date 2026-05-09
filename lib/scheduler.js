"use strict";
/**
 * App-wide scheduler instance.
 *
 * blamejs's `b.scheduler.create()` returns a fresh instance per call —
 * fine for libraries that scope their own jobs but wrong for HermitStash
 * which has multi-file consumers (server-main.js registers ~15 cleanup
 * jobs at boot; routes/admin.js calls getStatus() to render the admin
 * Tasks tab). Both need to reference the SAME instance, otherwise
 * getStatus() returns an empty array and the admin UI shows "no
 * scheduled jobs" while server-main's jobs run unobserved.
 *
 * This module instantiates the singleton once at first require (Node's
 * module cache holds the instance for the rest of the process). Every
 * importer gets the same object.
 *
 * Surface preserved (every existing call site keeps working):
 *   register(name, intervalMs, fn)
 *   start()
 *   getStatus()
 *
 * The legacy 4th-arg `opts` (baseline / timezone / skipInitial) was
 * dead code in HermitStash's hand-rolled scheduler — verified with a
 * grep across all callers before the swap. blamejs's register() is
 * the matching 3-arg shape.
 */
module.exports = require("./vendor/blamejs").scheduler.create();
