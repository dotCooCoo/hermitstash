const { describe, it } = require("node:test");
const assert = require("node:assert");
var { requireSyncAuth } = require("../../middleware/sync-guards");
var errors = require("../../app/shared/errors");

// requireSyncAuth gates POST /sync/rename, which is wrapped by blamejs
// apiEncrypt (req.apiEncryptSessionKey + an encrypting res.json). A denial
// must THROW an AppError at the boundary so the centralized error handler
// routes the problem document through the encrypting res.json — a direct
// b.problemDetails.send would ship the error cleartext via res.end on a
// session the client negotiated as encrypted. These tests pin that the gate
// throws the right subclass and does NOT write the response itself.
describe("sync-guards requireSyncAuth — denials throw, never write the response", function () {
  // Minimal res that records whether anything wrote to it. If the gate writes
  // here instead of throwing, the encrypting wrap is bypassed and _written flips.
  function runGate(mw, req) {
    var res = {
      _written: false,
      statusCode: 200,
      setHeader: function () {},
      getHeader: function () {},
      json: function () { this._written = true; },
      end: function () { this._written = true; },
      writeHead: function () { this._written = true; },
    };
    var nexted = false;
    return mw(req, res, function () { nexted = true; })
      .then(function () { return { thrown: null, res: res, nexted: nexted }; })
      .catch(function (e) { return { thrown: e, res: res, nexted: nexted }; });
  }

  it("missing sync/admin scope → ForbiddenError(403), nothing written", async function () {
    var r = await runGate(requireSyncAuth({}), { apiKey: { permissions: "" }, headers: {}, socket: {} });
    assert.ok(r.thrown instanceof errors.ForbiddenError, "should throw ForbiddenError");
    assert.strictEqual(r.thrown.statusCode, 403);
    assert.strictEqual(r.res._written, false, "must throw at the boundary, not write a cleartext response");
    assert.strictEqual(r.nexted, false);
  });

  it("absent apiKey → AuthenticationError(401)", async function () {
    var r = await runGate(requireSyncAuth({}), { apiKey: null, headers: {}, socket: {} });
    assert.ok(r.thrown instanceof errors.AuthenticationError, "should throw AuthenticationError");
    assert.strictEqual(r.thrown.statusCode, 401);
    assert.strictEqual(r.res._written, false);
  });

  it("requireBundle with no bundleId → ValidationError(400), nothing written", async function () {
    var r = await runGate(requireSyncAuth({ requireBundle: true }), { apiKey: { permissions: "sync" }, body: {}, headers: {}, socket: {} });
    assert.ok(r.thrown instanceof errors.ValidationError, "should throw ValidationError");
    assert.strictEqual(r.thrown.statusCode, 400);
    assert.strictEqual(r.res._written, false);
  });

  it("the thrown problem documents reproduce the prior wire shape via err.code", function () {
    // error-handler derives type slug + title from err.code; assert the codes
    // map to the same {type,title} the gate used to send verbatim.
    assert.strictEqual(new errors.ForbiddenError("x").code, "FORBIDDEN");
    assert.strictEqual(new errors.AuthenticationError("x").code, "AUTH_REQUIRED");
    assert.strictEqual(new errors.NotFoundError("x").code, "NOT_FOUND");
    assert.strictEqual(new errors.ValidationError("x").code, "VALIDATION_ERROR");
  });
});
