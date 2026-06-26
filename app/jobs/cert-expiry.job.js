"use strict";

/**
 * Certificate Expiry Job — monitors mTLS client certificate lifetimes.
 *
 * Runs daily. For each API key with certExpiresAt:
 *   - Expired → log error
 *   - Expires within 7 days → log error + webhook
 *   - Expires within 30 days → auto-generate renewal enrollment code
 *
 * The client must still redeem the renewal code via "hermitstash-sync repair".
 */

var logger = require("../shared/logger");
var { TIME } = require("../../lib/constants");

async function run() {
  var apiKeysRepo = require("../data/repositories/apiKeys.repo");
  var db = require("../../lib/db");
  var allKeys = apiKeysRepo.findAll({}).filter(function (k) { return k.certExpiresAt && k.permissions && k.permissions.indexOf("sync") !== -1; });

  if (allKeys.length === 0) return { checked: 0 };

  var now = new Date();
  var day30 = new Date(now.getTime() + TIME.days(30));
  var day7 = new Date(now.getTime() + TIME.days(7));

  var expired = 0, expiringSoon = 0, renewed = 0;

  for (var i = 0; i < allKeys.length; i++) {
    var key = allKeys[i];
    var expiresAt = new Date(key.certExpiresAt);

    if (expiresAt < now) {
      // Already expired
      expired++;
      logger.error("[cert-expiry] Client certificate expired", { prefix: key.prefix, expiresAt: key.certExpiresAt, stashId: key.boundStashId });
      continue;
    }

    if (expiresAt < day7) {
      // Expires within 7 days — critical warning + webhook
      expiringSoon++;
      logger.error("[cert-expiry] Client certificate expires in less than 7 days", { prefix: key.prefix, expiresAt: key.certExpiresAt });
      try {
        var webhook = require("../domain/integrations/webhook.service");
        webhook.fire("cert_expiring", { prefix: key.prefix, expiresAt: key.certExpiresAt, daysLeft: Math.ceil((expiresAt - now) / TIME.days(1)) });
      } catch (_e) { /* webhook dispatch is best-effort — core alert already logged above */ }
    }

    if (expiresAt < day30) {
      // Expires within 30 days — auto-generate renewal enrollment code
      // Check if a pending renewal code already exists for this key
      var existingCodes = db.enrollmentCodes.find({ status: "pending" }).filter(function (c) { return c.originalKeyId === key._id && c.reissue; });
      if (existingCodes.length > 0) continue; // already has a pending renewal

      try {
        var mtlsCa = require("../../lib/mtls-ca");
        var { generateEnrollmentCode } = require("../../lib/cert-utils");

        await mtlsCa.initCA();
        var newCert = await mtlsCa.generateClientCert({ cn: key.prefix });
        if (!newCert) {
          logger.warn("[cert-expiry] generateClientCert returned no cert — skipping renewal", { prefix: key.prefix, stashId: key.boundStashId });
          continue;
        }

        var enrollment = generateEnrollmentCode();

        db.enrollmentCodes.insert({
          codeHash: enrollment.codeHash,
          apiKey: null, // cert-only renewal
          clientCert: newCert.cert,
          clientKey: newCert.key,
          caCert: newCert.ca,
          stashId: key.boundStashId || null,
          bundleId: key.boundBundleId || null,
          createdBy: "system",
          status: "pending",
          reissue: true,
          originalKeyId: key._id,
          // The new cert's lifetime, carried on the code so that when the client
          // redeems it (server-main.js /sync/enroll) the key's certExpiresAt
          // advances to the live cert — otherwise the realigned key drops out of
          // this sweep's `certExpiresAt &&` filter and is never monitored again.
          certExpiresAt: newCert.expiresAt || null,
          expiresAt: new Date(Date.now() + TIME.days(7)).toISOString(), // 7-day code validity for renewals
          createdAt: new Date().toISOString(),
        });

        // Do NOT rebind certFingerprint to the freshly-issued cert here. The
        // client is still presenting its CURRENT cert and may be offline or fail
        // to redeem the reissue code; rebinding server-side would make
        // enforceCertBinding (middleware/sync-guards.js) 403 the old cert on
        // EVERY /sync/* surface — including /sync/renew-cert and the enroll
        // redemption itself — hard-locking the client out of its own self-service
        // recovery. The binding is realigned only when the client actually
        // redeems the reissue code (server-main.js /sync/enroll) or renews via
        // /sync/renew-cert. The pre-staged code + cert_renewed alert below are the
        // job's entire job; the certIssuedAt/certExpiresAt columns track the LIVE
        // cert, so they're left on the current cert too.

        renewed++;
        logger.info("[cert-expiry] Auto-renewed certificate", { prefix: key.prefix, newExpiresAt: newCert.expiresAt });

        try {
          var webhook = require("../domain/integrations/webhook.service");
          webhook.fire("cert_renewed", { prefix: key.prefix, newExpiresAt: newCert.expiresAt });
        } catch (_e) { /* webhook dispatch is best-effort — renewal already succeeded + logged */ }
      } catch (e) {
        logger.error("[cert-expiry] Auto-renewal failed", { prefix: key.prefix, error: e.message });
      }
    }
  }

  if (expired > 0 || expiringSoon > 0 || renewed > 0) {
    logger.info("[cert-expiry] Check complete", { checked: allKeys.length, expired: expired, expiringSoon: expiringSoon, renewed: renewed });
  }

  return { checked: allKeys.length, expired: expired, expiringSoon: expiringSoon, renewed: renewed };
}

module.exports = { run: run };
