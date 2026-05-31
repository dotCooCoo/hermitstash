"use strict";
// b.consent recognized-purpose vocabulary (educational-only) + grant gating.

var helpers        = require("../helpers");
var b              = helpers.b;
var check          = helpers.check;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

async function run() {
  // ---- recognized-purpose vocabulary (pure, no DB) ----
  var edu = b.consent.recognizedPurpose("educational-only");
  check("recognizedPurpose(educational-only): present",            edu !== null);
  check("recognizedPurpose(educational-only): forbids legitimate_interests",
        edu.forbidsLawfulBasis.indexOf("legitimate_interests") !== -1);
  check("recognizedPurpose(educational-only): citation populated", typeof edu.citation === "string" && edu.citation.length > 0);
  check("recognizedPurpose(educational-only): commercial-use prohibited", edu.commercialUseProhibited === true);
  check("recognizedPurpose(marketing): null (free-form)",          b.consent.recognizedPurpose("marketing") === null);
  check("recognizedPurpose(unknown): null",                        b.consent.recognizedPurpose("nope-not-real") === null);
  // A free-form purpose colliding with an Object.prototype member must stay
  // free-form (null), not resolve to the prototype value (CWE-1321).
  check("recognizedPurpose(toString): null, not the prototype fn",  b.consent.recognizedPurpose("toString") === null);
  check("recognizedPurpose(constructor): null",                     b.consent.recognizedPurpose("constructor") === null);
  check("recognizedPurpose(__proto__): null",                       b.consent.recognizedPurpose("__proto__") === null);
  check("recognizedPurpose(hasOwnProperty): null",                  b.consent.recognizedPurpose("hasOwnProperty") === null);

  var purposes = b.consent.listPurposes();
  check("listPurposes: frozen array",                              Array.isArray(purposes) && Object.isFrozen(purposes));
  check("listPurposes: includes educational-only",                 purposes.indexOf("educational-only") !== -1);

  // ---- DB-backed grant gating ----
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-consent-purp-"));
  try {
    await setupTestDb(dir);

    // educational-only + legitimate_interests → refused (FERPA / SOPIPA).
    var threw = null;
    try { await b.consent.grant({ subjectId: "stu-1", purpose: "educational-only", lawfulBasis: "legitimate_interests", channel: "api" }); }
    catch (e) { threw = e; }
    check("grant educational-only + legitimate_interests refused", threw && /forbids lawfulBasis/.test(threw.message));

    // educational-only + a school-authorization basis → succeeds + isGranted.
    await b.consent.grant({ subjectId: "stu-1", purpose: "educational-only", lawfulBasis: "consent", channel: "api" });
    check("grant educational-only + consent succeeds (isGranted)",
          b.consent.isGranted({ subjectId: "stu-1", purpose: "educational-only" }) === true);

    // A free-form purpose under any lawful basis still grants (back-compat).
    await b.consent.grant({ subjectId: "stu-2", purpose: "marketing", lawfulBasis: "legitimate_interests", channel: "api" });
    check("free-form purpose still grants (back-compat)",
          b.consent.isGranted({ subjectId: "stu-2", purpose: "marketing" }) === true);

    // A free-form purpose colliding with an Object.prototype name is still
    // free-form — grant() must not enter the recognized-purpose branch.
    await b.consent.grant({ subjectId: "stu-3", purpose: "toString", lawfulBasis: "legitimate_interests", channel: "api" });
    check("Object-prototype-named purpose grants as free-form",
          b.consent.isGranted({ subjectId: "stu-3", purpose: "toString" }) === true);

    // withdraw → isGranted false for the same (subjectId, purpose).
    await b.consent.withdraw({ subjectId: "stu-1", purpose: "educational-only" });
    check("after withdraw isGranted false",
          b.consent.isGranted({ subjectId: "stu-1", purpose: "educational-only" }) === false);
  } finally {
    await teardownTestDb(dir);
  }
}

module.exports = { run: run };
