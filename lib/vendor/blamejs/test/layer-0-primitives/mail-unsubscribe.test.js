"use strict";
/**
 * b.mail.unsubscribe — RFC 8058 / RFC 2369 / RFC 2919 List-* header
 * builder + handler tests. Exercises the single-call
 * buildAllListHeaders bundle for List-Unsubscribe / List-Help /
 * List-Archive / List-Owner / List-Post / List-ID and the Tier-A
 * shape gates (throw at config-time on bad URL / mailto / list-id).
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testBuildHeadersBasic() {
  var h = b.mail.unsubscribe.buildHeaders({
    url:      "https://example.com/u?token=abc",
    mailto:   "unsub@example.com",
    oneClick: true,
  });
  check("buildHeaders renders List-Unsubscribe with both",
        h["List-Unsubscribe"].indexOf("https://example.com/u?token=abc") !== -1 &&
        h["List-Unsubscribe"].indexOf("mailto:unsub@example.com") !== -1);
  check("buildHeaders sets one-click post",
        h["List-Unsubscribe-Post"] === "List-Unsubscribe=One-Click");
}

function testBuildHeadersRefusesHttp() {
  var threw = false;
  try { b.mail.unsubscribe.buildHeaders({ url: "http://insecure.com/u" }); }
  catch (e) { threw = e.code === "mailunsubscribe/invalid-list-header-shape"; }
  check("buildHeaders refuses non-https URL", threw === true);
}

function testBuildHeadersRefusesEmpty() {
  var threw = false;
  try { b.mail.unsubscribe.buildHeaders({}); }
  catch (e) { threw = e.code === "mailunsubscribe/invalid-list-header-shape"; }
  check("buildHeaders refuses empty opts", threw === true);
}

function testBuildAllListHeadersFullBundle() {
  var h = b.mail.unsubscribe.buildAllListHeaders({
    unsubscribeUrl:    "https://example.com/u?t=xyz",
    unsubscribeMailto: "unsub@example.com",
    oneClick:          true,
    helpUrl:           "https://example.com/list-help",
    archiveUrl:        "https://example.com/archive",
    ownerEmail:        "owner@example.com",
    postEmail:         "list@example.com",
    listId:            "lst.example.com",
  });
  check("List-Unsubscribe present",
        typeof h["List-Unsubscribe"] === "string" &&
        h["List-Unsubscribe"].indexOf("https://example.com/u?t=xyz") !== -1);
  check("List-Unsubscribe-Post one-click",
        h["List-Unsubscribe-Post"] === "List-Unsubscribe=One-Click");
  check("List-Help renders angle-wrapped URL",
        h["List-Help"] === "<https://example.com/list-help>");
  check("List-Archive renders angle-wrapped URL",
        h["List-Archive"] === "<https://example.com/archive>");
  check("List-Owner renders mailto",
        h["List-Owner"] === "<mailto:owner@example.com>");
  check("List-Post renders mailto",
        h["List-Post"] === "<mailto:list@example.com>");
  check("List-ID wraps bare label-list in angle brackets",
        h["List-ID"] === "<lst.example.com>");
}

function testBuildAllListHeadersListPostNo() {
  var h = b.mail.unsubscribe.buildAllListHeaders({
    listId:    "ann.example.com",
    postEmail: "NO",
  });
  check("List-Post NO sentinel renders verbatim", h["List-Post"] === "NO");
}

function testBuildAllListHeadersListIdPhraseForm() {
  var h = b.mail.unsubscribe.buildAllListHeaders({
    listId: "Acme Announcements <ann.example.com>",
  });
  check("List-ID accepts Phrase <label-list> form",
        h["List-ID"] === "Acme Announcements <ann.example.com>");
}

function testBuildAllListHeadersListOwnerPhrase() {
  var h = b.mail.unsubscribe.buildAllListHeaders({
    listOwner: "Acme Owner <owner@example.com>",
  });
  check("List-Owner phrase form preserved",
        h["List-Owner"] === "Acme Owner <owner@example.com>");
}

function testBuildAllListHeadersRefusesBadListId() {
  var cases = [
    "single-label",                  // RFC 2919 §3 needs >= 2 labels
    "bad..double-dot",                // Empty label
    "BAD\rINJECTION.example.com",     // CR injection
    "starts-with-dash.-example.com",  // Bad LDH
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var threw = false;
    try { b.mail.unsubscribe.buildAllListHeaders({ listId: cases[i] }); }
    catch (e) { threw = e.code === "mailunsubscribe/invalid-list-header-shape"; }
    check("buildAllListHeaders refuses listId '" + cases[i] + "'", threw === true);
  }
}

function testBuildAllListHeadersRefusesBadHelpUrl() {
  var threw = false;
  try {
    b.mail.unsubscribe.buildAllListHeaders({
      helpUrl: "ftp://example.com/help",
    });
  } catch (e) { threw = e.code === "mailunsubscribe/invalid-list-header-shape"; }
  check("buildAllListHeaders refuses non-https helpUrl", threw === true);
}

function testBuildAllListHeadersRefusesBadOwnerEmail() {
  var threw = false;
  try {
    b.mail.unsubscribe.buildAllListHeaders({
      ownerEmail: "no-at-sign-here",
    });
  } catch (e) { threw = e.code === "mailunsubscribe/invalid-list-header-shape"; }
  check("buildAllListHeaders refuses ownerEmail without `@`", threw === true);
}

function testBuildAllListHeadersRefusesEmpty() {
  var threw = false;
  try { b.mail.unsubscribe.buildAllListHeaders({}); }
  catch (e) { threw = e.code === "mailunsubscribe/invalid-list-header-shape"; }
  check("buildAllListHeaders refuses zero List-* fields", threw === true);
}

function testBuildAllListHeadersRefusesCrlfInjection() {
  var threw = false;
  try {
    b.mail.unsubscribe.buildAllListHeaders({
      listOwner: "Owner <owner@example.com>\r\nX-Injected: yes",
    });
  } catch (e) { threw = e.code === "mailunsubscribe/invalid-list-header-shape"; }
  check("buildAllListHeaders refuses CRLF in listOwner", threw === true);
}

async function run() {
  testBuildHeadersBasic();
  testBuildHeadersRefusesHttp();
  testBuildHeadersRefusesEmpty();
  testBuildAllListHeadersFullBundle();
  testBuildAllListHeadersListPostNo();
  testBuildAllListHeadersListIdPhraseForm();
  testBuildAllListHeadersListOwnerPhrase();
  testBuildAllListHeadersRefusesBadListId();
  testBuildAllListHeadersRefusesBadHelpUrl();
  testBuildAllListHeadersRefusesBadOwnerEmail();
  testBuildAllListHeadersRefusesEmpty();
  testBuildAllListHeadersRefusesCrlfInjection();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
