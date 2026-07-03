/**
 * Idempotency-Key middleware mount-ready instance.
 *
 * Composes `b.middleware.bodyParser` -> `b.middleware.idempotencyKey` so
 * the body fingerprint is populated by the time the idempotency cache
 * lookup runs. Upstream's v0.10.0 `bodyFingerprintFallback: "deny"`
 * default refuses body-bearing requests that arrive without parsed-body
 * data; mounting the parser inline guarantees `req.body` is set before
 * fingerprinting and closes the same-key-different-body 422 detection
 * that the legacy "parse-inside-handler" pattern couldn't support.
 *
 * Mounted on mutating POST endpoints where a network retry would
 * otherwise create a duplicate resource (apikeys create, webhooks
 * create, drop init/finalize, user invite).
 *
 * Idempotency-Key is OPTIONAL. Clients that don't send the header
 * skip the cache and the middleware is a pass-through. Clients
 * sending the same key + same body within 24h get the cached response
 * replayed without re-executing the handler. Same key with different
 * body refuses with 422 problem-details `idempotency/key-reuse-mismatch`
 * (draft-ietf-httpapi-idempotency-key §4.3).
 *
 * Declared async so b.router's dispatcher awaits the entire chain before
 * checking `proceeded`. A sync wrapper that fires next() from inside an
 * async callback returns undefined before the callback runs; the router
 * sees `!proceeded` and bails on the route handler. The async wrapper
 * keeps the await pending until both inner middlewares finish, matching
 * the contract framework-shipped middlewares use implicitly.
 *
 * After each inner middleware the wrapper also checks `res.writableEnded`
 * — bodyParser's documented failure modes (413/415/400) write the
 * response directly and do NOT invoke the callback (see body-parser.js
 * header comment "Failure modes — all return responses, do NOT call
 * next(err)"). Awaiting bodyParser's Promise then checking writableEnded
 * ensures the wrapper resolves cleanly on those paths instead of hanging
 * the router on a callback that will never fire.
 *
 * Order matters at the route declaration: rate-limit runs FIRST
 * (block abuse from valid keys), then idempotency (replay cache
 * hits), then scope/auth (which the cached response already passed
 * on the original call).
 */
var b = require("../lib/vendor/blamejs");
var hsDb = require("../lib/db");

// Idempotent — error-handler.js also sets this. Whichever module loads
// first wins; subsequent calls with the same URI are no-ops. Ensures
// the middleware's problem+json error replies (missing-key / bad-key /
// key-reuse-mismatch) carry the hermitstash.com problem namespace
// instead of the framework default.
b.problemDetails.setBase("https://hermitstash.com/problems");

var bodyParser = b.middleware.bodyParser({
  json:       { limit: b.constants.BYTES.mib(2) },
  urlencoded: false,
  text:       false,
  raw:        false,
  multipart:  false,
});

var idempotencyKey = b.middleware.idempotencyKey({
  store: b.middleware.idempotencyKey.dbStore({
    db: hsDb.getDb(),
    // Defaults preserved: tableName="blamejs_idempotency_keys", init=true,
    // hashKeys=true (raw header value never reaches the DB), seal=true
    // (headers + body sealed via b.cryptoField once b.vault.init() has run).
  }),
  ttlMs: b.constants.TIME.hours(24),
  // Scope the replay-cache SLOT to the authenticated principal. The framework's
  // default scope resolves the actor via b.requestHelpers.extractActorContext,
  // which reads actor.userId — but HS sets req.user._id / req.apiKey._id (not
  // .userId), so the default collapses EVERY request to a single shared "anon"
  // slot. With one slot for all principals, one principal's Idempotency-Key
  // reuses another's slot: principal B is refused key K that principal A already
  // used (cross-actor denial). Bind the slot to HS's own principal id so each
  // principal has an isolated key namespace. Mounted after global auth
  // (attachUser / api-auth), so req.user / req.apiKey are set before this runs.
  scopeFn: function (req) {
    return (req.user && req.user._id) || (req.apiKey && req.apiKey._id) || "anon";
  },
  // Defense-in-depth against cross-principal DISCLOSURE: even within a slot, fold
  // the actor into the body fingerprint so a slot mismatch (should one ever occur)
  // reads as a 422 key-reuse rather than replaying another principal's stored
  // response — several of these endpoints return a one-time secret (e.g.
  // /admin/apikeys/create returns the raw key).
  bodyFingerprint: function (req) {
    var actor = (req.user && req.user._id) || (req.apiKey && req.apiKey._id) || "anon";
    return JSON.stringify({ actor: actor, body: (req.body !== undefined ? req.body : null) });
  },
});

module.exports = async function idempotencyChain(req, res, next) {
  var proceeded = false;
  await bodyParser(req, res, function () { proceeded = true; });
  if (!proceeded || res.writableEnded) return;

  proceeded = false;
  await idempotencyKey(req, res, function () { proceeded = true; });
  if (!proceeded || res.writableEnded) return;

  next();
};
