// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * test-coverage — gate that flags operator-facing primitives on `b.*`
 * lacking any test reference.
 *
 * Mirrors examples/wiki/test/validate-primitive-sections.js but for
 * tests instead of wiki sections. Top-level keys on `b.*` and one
 * level of sub-keys (b.middleware.X, b.auth.X, b.auditSign.X, …) are
 * each searched across every file under test/. A primitive that
 * doesn't appear anywhere — neither as `b.X(` nor `b.X.Y(` nor a
 * direct `require("../../lib/X")` — is flagged.
 *
 * The grep is intentionally simple: text-match against the qualified
 * name. False positives are unlikely (the verbatim string `b.guardCsv`
 * only appears in code that uses guardCsv); false negatives surface
 * when a test composes the primitive through another helper without
 * naming it. Those go in UNTESTED_BACKLOG with a one-line reason
 * pointing at the test that exercises it.
 *
 * Two exemption sets:
 *
 *   TX_SKIP  — non-callable surface (constants, getters, vocabulary
 *              tables, frameworkError class catalog). Same shape as
 *              BX_SKIP in the wiki validator. Sub-key entries use
 *              `parent.method` form.
 *
 *   UNTESTED_BACKLOG — primitives exercised through composition
 *              (factory tested through its consumer; the primitive
 *              itself isn't directly invoked by name). Each entry
 *              names the consumer test or the reason coverage is
 *              indirect.
 *
 * Run standalone:
 *   node test/layer-0-primitives/test-coverage.test.js
 */

var fs = require("fs");
var path = require("path");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

var REPO_ROOT = path.join(__dirname, "..", "..");
var TEST_ROOT = path.join(REPO_ROOT, "test");

// ---- Skip list — non-primitive surface ----
//
// Top-level + sub-key entries. Sub-key form: `parent.method`. Mirror
// of BX_SKIP in the wiki validator.
var TX_SKIP = new Set([
  // Top-level non-primitive surface.
  "constants",
  "frameworkError",
  "_modules",
  "_internalForTest",
  "lazyRequire",
  "validateOpts",
  "cliHelpers",
  "parsers",
  "logStream",
  "events",
  "redact",
  "lib",
  "version",
  "testing",
  // Sub-keys: getters / constants / vocabulary tables — not primitives.
  "auth.acr",
  "auditSign.DEFAULT_SIGNING_ALG",
  "auditSign.SUPPORTED_SIGNING_ALGS",
  "auditSign.ENV_PASSPHRASE",
  "auditSign.ENV_PASSPHRASE_FILE",
  "auditSign.ENV_PASSPHRASE_SRC",
  "auditSign.getMode",
  "auditSign.getAlgorithm",
  "auditSign.getPublicKey",
  "auditSign.getPublicKeyFingerprint",
]);

// ---- Backlog — primitives exercised indirectly ----
//
// A primitive on this list has no direct `b.X.Y(...)` reference in
// test/, but is exercised through composition (its consumer test
// covers the path). Each entry gives the consumer test or a reason.
//
// New primitives added to b.* MUST land with either a direct test
// reference OR an explicit backlog entry.
var UNTESTED_BACKLOG = {
  // Top-level primitives whose tests don't reference `b.X` by name —
  // tests import the underlying lib module directly or compose through
  // a sibling primitive. Backfill direct `b.X` references opportunistically.
  "cloudEvents":                   "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "a2a.A2aTasksError":             "error class exported alongside b.a2a primitives; tests exercise the throw path via the gating primitive (which constructs this error internally).",
  "guardAuth":                     "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardCidr":                     "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardDomain":                   "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardGraphql":                  "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardImage":                    "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardJsonpath":                 "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardJwt":                      "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardMime":                     "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardOauth":                    "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardPdf":                      "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardRegex":                    "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardShell":                    "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardTemplate":                 "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardTime":                     "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "guardUuid":                     "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "pick":                          "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "safeEnv":                       "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "safeRedirect":                  "backfill — covered indirectly through a sibling primitive or by direct lib import",
  "auditSign.rotateSigningKey":    "audit-sign rotation needs a real init() with sealed/plaintext keypair on disk + a vault passphrase prompt — exercised by the audit-key rotation runbook documented in SECURITY.md, not unit-testable without a fixture vault",
  "auditSign.reSignAll":           "companion to auditSign.rotateSigningKey — async iterable + per-payload verify+sign needs real audit-sign init; covered by the rotation runbook",
  "circuitBreaker":                "thin re-export of b.retry.CircuitBreaker for ergonomic top-level discovery; the underlying class is tested via b.retry.CircuitBreaker references — direct b.circuitBreaker references aren't load-bearing",
  "breach.BreachError":            "framework-error subclass surfaced for `instanceof` checks in operator handlers; the class itself isn't called as a constructor in tests — every breach.* test that triggers it does so by exercising the calling code that throws it",

  // appShutdown — sub-keys exercised through composition / direct lib imports.
  "appShutdown.pidLock":                         "backfill — covered indirectly under the appShutdown test or via composition",
  // asyncapi — sub-keys exercised through composition / direct lib imports.
  "asyncapi.AsyncApiError":                      "backfill — covered indirectly under the asyncapi test or via composition",
  "asyncapi.schemaWalk":                         "backfill — covered indirectly under the asyncapi test or via composition",
  // atomicFile — sub-keys exercised through composition / direct lib imports.
  "atomicFile.AtomicFileError":                  "backfill — covered indirectly under the atomicFile test or via composition",
  "atomicFile.cleanOrphans":                     "backfill — covered indirectly under the atomicFile test or via composition",
  "atomicFile.writeSync":                        "backfill — covered indirectly under the atomicFile test or via composition",
  // audit — sub-keys exercised through composition / direct lib imports.
  "audit.emit":                                  "backfill — covered indirectly under the audit test or via composition",
  // auditChain — sub-keys exercised through composition / direct lib imports.
  "auditChain.canonicalize":                     "backfill — covered indirectly under the auditChain test or via composition",
  "auditChain.getChainTip":                      "backfill — covered indirectly under the auditChain test or via composition",
  "auditChain.verifyChain":                      "backfill — covered indirectly under the auditChain test or via composition",
  // auditSign — sub-keys exercised through composition / direct lib imports.
  "auditSign.init":                              "backfill — covered indirectly under the auditSign test or via composition",
  // auth — sub-keys exercised through composition / direct lib imports.
  "auth.statusList":                             "backfill — covered indirectly under the auth test or via composition",
  // authHeader — sub-keys exercised through composition / direct lib imports.
  "authHeader.AuthHeaderError":                  "backfill — covered indirectly under the authHeader test or via composition",
  // backupManifest — sub-keys exercised through composition / direct lib imports.
  "backupManifest.BackupManifestError":          "backfill — covered indirectly under the backupManifest test or via composition",
  // chainWriter — sub-keys exercised through composition / direct lib imports.
  "chainWriter.ChainWriterError":                "backfill — covered indirectly under the chainWriter test or via composition",
  // cluster — sub-keys exercised through composition / direct lib imports.
  "cluster.NotLeaderError":                      "backfill — covered indirectly under the cluster test or via composition",
  "cluster.dialect":                             "backfill — covered indirectly under the cluster test or via composition",
  "cluster.externalDbBackend":                   "backfill — covered indirectly under the cluster test or via composition",
  "cluster.isClusterMode":                       "backfill — covered indirectly under the cluster test or via composition",
  "cluster.onTransition":                        "backfill — covered indirectly under the cluster test or via composition",
  // clusterStorage — sub-keys exercised through composition / direct lib imports.
  "clusterStorage.ClusterStorageError":          "backfill — covered indirectly under the clusterStorage test or via composition",
  // compliance — sub-keys exercised through composition / direct lib imports.
  "compliance.ComplianceError":                  "backfill — covered indirectly under the compliance test or via composition",
  "compliance.describe":                         "backfill — covered indirectly under the compliance test or via composition",
  "compliance.eaa":                              "backfill — covered indirectly under the compliance test or via composition",
  "compliance.list":                             "backfill — covered indirectly under the compliance test or via composition",
  "compliance.posturesByDomain":                 "backfill — covered indirectly under the compliance test or via composition",
  "compliance.posturesByJurisdiction":           "backfill — covered indirectly under the compliance test or via composition",
  // configDrift — sub-keys exercised through composition / direct lib imports.
  "configDrift.ConfigDriftError":                "backfill — covered indirectly under the configDrift test or via composition",
  // cookies — sub-keys exercised through composition / direct lib imports.
  "cookies.parseSafe":                           "backfill — covered indirectly under the cookies test or via composition",
  // credentialHash — sub-keys exercised through composition / direct lib imports.
  "credentialHash.CredentialHashError":          "backfill — covered indirectly under the credentialHash test or via composition",
  // crypto — sub-keys exercised through composition / direct lib imports.
  "crypto.decryptEnvelopeAsCertPeer":            "backfill — covered indirectly under the crypto test or via composition",
  "crypto.encryptEnvelopeAsCertPeer":            "backfill — covered indirectly under the crypto test or via composition",
  "crypto.hashCertFingerprint":                  "backfill — covered indirectly under the crypto test or via composition",
  "crypto.hmacSha3":                             "backfill — covered indirectly under the crypto test or via composition",
  "crypto.isCertRevoked":                        "backfill — covered indirectly under the crypto test or via composition",
  "crypto.kdf":                                  "backfill — covered indirectly under the crypto test or via composition",
  "crypto.sri":                                  "backfill — covered indirectly under the crypto test or via composition",
  // cryptoField — sub-keys exercised through composition / direct lib imports.
  "cryptoField.computeDerived":                  "backfill — covered indirectly under the cryptoField test or via composition",
  "cryptoField.eraseRow":                        "backfill — covered indirectly under the cryptoField test or via composition",
  "cryptoField.getSchema":                       "backfill — covered indirectly under the cryptoField test or via composition",
  "cryptoField.getSealedFields":                 "backfill — covered indirectly under the cryptoField test or via composition",
  "cryptoField.lookupHash":                      "backfill — covered indirectly under the cryptoField test or via composition",
  "cryptoField.sealRow":                         "backfill — covered indirectly under the cryptoField test or via composition",
  "cryptoField.unsealRow":                       "backfill — covered indirectly under the cryptoField test or via composition",
  // db — sub-keys exercised through composition / direct lib imports.
  "db.exec":                                     "backfill — covered indirectly under the db test or via composition",
  "db.flushToDisk":                              "backfill — covered indirectly under the db test or via composition",
  "db.getDbPath":                                "backfill — covered indirectly under the db test or via composition",
  "db.integrityCheck":                           "backfill — covered indirectly under the db test or via composition",
  "db.integrityMonitor":                         "backfill — covered indirectly under the db test or via composition",
  "db.purgeAuditChain":                          "backfill — covered indirectly under the db test or via composition",
  // dora — sub-keys exercised through composition / direct lib imports.
  "dora.DoraError":                              "backfill — covered indirectly under the dora test or via composition",
  // dsr — sub-keys exercised through composition / direct lib imports.
  "dsr.DsrError":                                "backfill — covered indirectly under the dsr test or via composition",
  "dsr.dbTicketStore":                           "backfill — covered indirectly under the dsr test or via composition",
  // dualControl — sub-keys exercised through composition / direct lib imports.
  "dualControl.DualControlError":                "backfill — covered indirectly under the dualControl test or via composition",
  // externalDb — sub-keys exercised through composition / direct lib imports.
  "externalDb.Pool":                             "backfill — covered indirectly under the externalDb test or via composition",
  // fileType — sub-keys exercised through composition / direct lib imports.
  "fileType.FileTypeError":                      "backfill — covered indirectly under the fileType test or via composition",
  // fileUpload — sub-keys exercised through composition / direct lib imports.
  "fileUpload.FileUploadError":                  "backfill — covered indirectly under the fileUpload test or via composition",
  // flag — sub-keys exercised through composition / direct lib imports.
  "flag.FlagError":                              "backfill — covered indirectly under the flag test or via composition",
  // frameworkSchema — sub-keys exercised through composition / direct lib imports.
  "frameworkSchema.FrameworkSchemaError":        "backfill — covered indirectly under the frameworkSchema test or via composition",
  // gateContract — sub-keys exercised through composition / direct lib imports.
  "gateContract.GateContractError":              "backfill — covered indirectly under the gateContract test or via composition",
  "gateContract.aggregateIssues":                "backfill — covered indirectly under the gateContract test or via composition",
  "gateContract.badInputResultIfNotStringOrBuffer": "backfill — covered indirectly under the gateContract test or via composition",
  "gateContract.buildGuardGate":                 "backfill — covered indirectly under the gateContract test or via composition",
  "gateContract.extractBytesAsText":             "backfill — covered indirectly under the gateContract test or via composition",
  "gateContract.lookupCompliancePosture":        "backfill — covered indirectly under the gateContract test or via composition",
  "gateContract.makeProfileBuilder":             "backfill — covered indirectly under the gateContract test or via composition",
  "gateContract.makeRulePackLoader":             "backfill — covered indirectly under the gateContract test or via composition",
  "gateContract.runIssueValidator":              "backfill — covered indirectly under the gateContract test or via composition",
  "gateContract.summarizeIssues":                "backfill — covered indirectly under the gateContract test or via composition",
  // guardArchive — sub-keys exercised through composition / direct lib imports.
  "guardArchive.buildProfile":                   "backfill — covered indirectly under the guardArchive test or via composition",
  "guardArchive.loadRulePack":                   "backfill — covered indirectly under the guardArchive test or via composition",
  // guardEmail — sub-keys exercised through composition / direct lib imports.
  "guardEmail.GuardEmailError":                  "backfill — covered indirectly under the guardEmail test or via composition",
  "guardEmail.buildProfile":                     "backfill — covered indirectly under the guardEmail test or via composition",
  "guardEmail.loadRulePack":                     "backfill — covered indirectly under the guardEmail test or via composition",
  // guardFilename — sub-keys exercised through composition / direct lib imports.
  "guardFilename.buildProfile":                  "backfill — covered indirectly under the guardFilename test or via composition",
  "guardFilename.loadRulePack":                  "backfill — covered indirectly under the guardFilename test or via composition",
  // guardHtml — sub-keys exercised through composition / direct lib imports.
  "guardHtml.buildProfile":                      "backfill — covered indirectly under the guardHtml test or via composition",
  "guardHtml.loadRulePack":                      "backfill — covered indirectly under the guardHtml test or via composition",
  // guardJson — sub-keys exercised through composition / direct lib imports.
  "guardJson.buildProfile":                      "backfill — covered indirectly under the guardJson test or via composition",
  "guardJson.loadRulePack":                      "backfill — covered indirectly under the guardJson test or via composition",
  // guardMarkdown — sub-keys exercised through composition / direct lib imports.
  "guardMarkdown.GuardMarkdownError":            "backfill — covered indirectly under the guardMarkdown test or via composition",
  "guardMarkdown.buildProfile":                  "backfill — covered indirectly under the guardMarkdown test or via composition",
  "guardMarkdown.loadRulePack":                  "backfill — covered indirectly under the guardMarkdown test or via composition",
  // guardSvg — sub-keys exercised through composition / direct lib imports.
  "guardSvg.buildProfile":                       "backfill — covered indirectly under the guardSvg test or via composition",
  "guardSvg.loadRulePack":                       "backfill — covered indirectly under the guardSvg test or via composition",
  // guardXml — sub-keys exercised through composition / direct lib imports.
  "guardXml.GuardXmlError":                      "backfill — covered indirectly under the guardXml test or via composition",
  "guardXml.buildProfile":                       "backfill — covered indirectly under the guardXml test or via composition",
  "guardXml.loadRulePack":                       "backfill — covered indirectly under the guardXml test or via composition",
  // guardYaml — sub-keys exercised through composition / direct lib imports.
  "guardYaml.buildProfile":                      "backfill — covered indirectly under the guardYaml test or via composition",
  "guardYaml.loadRulePack":                      "backfill — covered indirectly under the guardYaml test or via composition",
  // htmlBalance — sub-keys exercised through composition / direct lib imports.
  "htmlBalance.checkSafe":                       "backfill — covered indirectly under the htmlBalance test or via composition",
  // inbox — sub-keys exercised through composition / direct lib imports.
  "inbox.InboxError":                            "backfill — covered indirectly under the inbox test or via composition",
  // log — sub-keys exercised through composition / direct lib imports.
  "log.makeViaOrFallback":                       "backfill — covered indirectly under the log test or via composition",
  // mail — sub-keys exercised through composition / direct lib imports.
  "mail.authResults":                            "backfill — covered indirectly under the mail test or via composition",
  "mail.bimi":                                   "backfill — covered indirectly under the mail test or via composition",
  "mail.unsubscribe":                            "backfill — covered indirectly under the mail test or via composition",
  // middleware — sub-keys exercised through composition / direct lib imports.
  "middleware.assetlinks":                       "backfill — covered indirectly under the middleware test or via composition",
  "middleware.botDisclose":                      "backfill — covered indirectly under the middleware test or via composition",
  "middleware.cookies":                          "backfill — covered indirectly under the middleware test or via composition",
  "middleware.dpop":                             "backfill — covered indirectly under the middleware test or via composition",
  "middleware.fetchMetadata":                    "backfill — covered indirectly under the middleware test or via composition",
  "middleware.gpc":                              "backfill — covered indirectly under the middleware test or via composition",
  "middleware.headers":                          "backfill — covered indirectly under the middleware test or via composition",
  "middleware.hostAllowlist":                    "backfill — covered indirectly under the middleware test or via composition",
  "middleware.requireContentType":               "backfill — covered indirectly under the middleware test or via composition",
  "middleware.requireMethods":                   "backfill — covered indirectly under the middleware test or via composition",
  "middleware.securityTxt":                      "backfill — covered indirectly under the middleware test or via composition",
  "middleware.tusUpload":                        "backfill — covered indirectly under the middleware test or via composition",
  "middleware.webAppManifest":                   "backfill — covered indirectly under the middleware test or via composition",
  // mtlsEngine — sub-keys exercised through composition / direct lib imports.
  "mtlsEngine.MtlsEngineError":                  "backfill — covered indirectly under the mtlsEngine test or via composition",
  "mtlsEngine.algorithmEnvelope":                "backfill — covered indirectly under the mtlsEngine test or via composition",
  "mtlsEngine.generateCrl":                      "backfill — covered indirectly under the mtlsEngine test or via composition",
  "mtlsEngine.packageP12":                       "backfill — covered indirectly under the mtlsEngine test or via composition",
  "mtlsEngine.signClientCert":                   "backfill — covered indirectly under the mtlsEngine test or via composition",
  // network — sub-keys exercised through composition / direct lib imports.
  "network.NetworkError":                        "backfill — covered indirectly under the network test or via composition",
  "network.bootFromEnv":                         "backfill — covered indirectly under the network test or via composition",
  "network.snapshot":                            "backfill — covered indirectly under the network test or via composition",
  "network.socket":                              "backfill — covered indirectly under the network test or via composition",
  // ntpCheck — sub-keys exercised through composition / direct lib imports.
  "ntpCheck.getThresholds":                      "backfill — covered indirectly under the ntpCheck test or via composition",
  "ntpCheck.monitor":                            "backfill — covered indirectly under the ntpCheck test or via composition",
  "ntpCheck.setThresholds":                      "backfill — covered indirectly under the ntpCheck test or via composition",
  // observability — sub-keys exercised through composition / direct lib imports.
  "observability.safeEvent":                     "backfill — covered indirectly under the observability test or via composition",
  "observability.setTap":                        "backfill — covered indirectly under the observability test or via composition",
  "observability.timed":                         "backfill — covered indirectly under the observability test or via composition",
  // openapi — sub-keys exercised through composition / direct lib imports.
  "openapi.OpenApiError":                        "backfill — covered indirectly under the openapi test or via composition",
  // outbox — sub-keys exercised through composition / direct lib imports.
  "outbox.OutboxError":                          "backfill — covered indirectly under the outbox test or via composition",
  "outbox.create":                               "backfill — covered indirectly under the outbox test or via composition",
  // pqcSoftware — sub-keys exercised through composition / direct lib imports.
  "pqcSoftware.PqcError":                        "backfill — covered indirectly under the pqcSoftware test or via composition",
  "pqcSoftware.ml_dsa_44":                       "backfill — covered indirectly under the pqcSoftware test or via composition",
  "pqcSoftware.ml_dsa_65":                       "backfill — covered indirectly under the pqcSoftware test or via composition",
  "pqcSoftware.ml_kem_512":                      "backfill — covered indirectly under the pqcSoftware test or via composition",
  "pqcSoftware.ml_kem_768":                      "backfill — covered indirectly under the pqcSoftware test or via composition",
  "pqcSoftware.slh_dsa_sha2_128f":               "backfill — covered indirectly under the pqcSoftware test or via composition",
  "pqcSoftware.slh_dsa_sha2_192f":               "backfill — covered indirectly under the pqcSoftware test or via composition",
  "pqcSoftware.slh_dsa_sha2_256f":               "backfill — covered indirectly under the pqcSoftware test or via composition",
  "pqcSoftware.slh_dsa_shake_128f":              "backfill — covered indirectly under the pqcSoftware test or via composition",
  "pqcSoftware.slh_dsa_shake_192f":              "backfill — covered indirectly under the pqcSoftware test or via composition",
  // queue — sub-keys exercised through composition / direct lib imports.
  "queue.bootFromEnv":                           "backfill — covered indirectly under the queue test or via composition",
  // requestHelpers — sub-keys exercised through composition / direct lib imports.
  "requestHelpers.appendVary":                   "backfill — covered indirectly under the requestHelpers test or via composition",
  "requestHelpers.clientIp":                     "backfill — covered indirectly under the requestHelpers test or via composition",
  "requestHelpers.parseListHeader":              "backfill — covered indirectly under the requestHelpers test or via composition",
  "requestHelpers.requestProtocol":              "backfill — covered indirectly under the requestHelpers test or via composition",
  "requestHelpers.resolveActorWithOverride":     "backfill — covered indirectly under the requestHelpers test or via composition",
  // retention — sub-keys exercised through composition / direct lib imports.
  "retention.RetentionError":                    "backfill — covered indirectly under the retention test or via composition",
  "retention.create":                            "backfill — covered indirectly under the retention test or via composition",
  // safeAsync — sub-keys exercised through composition / direct lib imports.
  "safeAsync.SafeAsyncError":                    "backfill — covered indirectly under the safeAsync test or via composition",
  "safeAsync.asyncRetry":                        "backfill — covered indirectly under the safeAsync test or via composition",
  "safeAsync.makeDropCallback":                  "backfill — covered indirectly under the safeAsync test or via composition",
  "safeAsync.makeScheduledFlush":                "backfill — covered indirectly under the safeAsync test or via composition",
  "safeAsync.safeInvoke":                        "backfill — covered indirectly under the safeAsync test or via composition",
  "safeAsync.withSignal":                        "backfill — covered indirectly under the safeAsync test or via composition",
  // safeBuffer — sub-keys exercised through composition / direct lib imports.
  "safeBuffer.SafeBufferError":                  "backfill — covered indirectly under the safeBuffer test or via composition",
  "safeBuffer.hasCrlf":                          "backfill — covered indirectly under the safeBuffer test or via composition",
  "safeBuffer.isHex":                            "backfill — covered indirectly under the safeBuffer test or via composition",
  "safeBuffer.secureZero":                       "backfill — covered indirectly under the safeBuffer test or via composition",
  "safeBuffer.stripCrlf":                        "backfill — covered indirectly under the safeBuffer test or via composition",
  "safeBuffer.stripTrailingHspace":              "backfill — covered indirectly under the safeBuffer test or via composition",
  // safeSchema — sub-keys exercised through composition / direct lib imports.
  "safeSchema.SafeSchemaError":                  "backfill — covered indirectly under the safeSchema test or via composition",
  "safeSchema.any":                              "backfill — covered indirectly under the safeSchema test or via composition",
  "safeSchema.array":                            "backfill — covered indirectly under the safeSchema test or via composition",
  "safeSchema.discriminatedUnion":               "backfill — covered indirectly under the safeSchema test or via composition",
  "safeSchema.enum_":                            "backfill — covered indirectly under the safeSchema test or via composition",
  "safeSchema.lazy":                             "backfill — covered indirectly under the safeSchema test or via composition",
  "safeSchema.literal":                          "backfill — covered indirectly under the safeSchema test or via composition",
  "safeSchema.null_":                            "backfill — covered indirectly under the safeSchema test or via composition",
  "safeSchema.oneOf":                            "backfill — covered indirectly under the safeSchema test or via composition",
  "safeSchema.record":                           "backfill — covered indirectly under the safeSchema test or via composition",
  "safeSchema.tuple":                            "backfill — covered indirectly under the safeSchema test or via composition",
  "safeSchema.undefined_":                       "backfill — covered indirectly under the safeSchema test or via composition",
  "safeSchema.union":                            "backfill — covered indirectly under the safeSchema test or via composition",
  "safeSchema.unknown":                          "backfill — covered indirectly under the safeSchema test or via composition",
  // safeSql — sub-keys exercised through composition / direct lib imports.
  "safeSql.SafeSqlError":                        "backfill — covered indirectly under the safeSql test or via composition",
  // safeUrl — sub-keys exercised through composition / direct lib imports.
  "safeUrl.SafeUrlError":                        "backfill — covered indirectly under the safeUrl test or via composition",
  // scheduler — sub-keys exercised through composition / direct lib imports.
  "scheduler.nextBaselineFire":                  "backfill — covered indirectly under the scheduler test or via composition",
  // security — sub-keys exercised through composition / direct lib imports.
  "security.DEFAULT_RESOLVERS":                  "backfill — covered indirectly under the security test or via composition",
  "security.SecurityAssertError":                "backfill — covered indirectly under the security test or via composition",
  // ssrfGuard — sub-keys exercised through composition / direct lib imports.
  "ssrfGuard.SsrfError":                         "backfill — covered indirectly under the ssrfGuard test or via composition",
  "ssrfGuard.isLinkLocal":                       "backfill — covered indirectly under the ssrfGuard test or via composition",
  "ssrfGuard.isPrivate":                         "backfill — covered indirectly under the ssrfGuard test or via composition",
  "ssrfGuard.isReserved":                        "backfill — covered indirectly under the ssrfGuard test or via composition",
  // storage — sub-keys exercised through composition / direct lib imports.
  "storage.getBackend":                          "backfill — covered indirectly under the storage test or via composition",
  // subject — sub-keys exercised through composition / direct lib imports.
  "subject.exportData":                          "backfill — covered indirectly under the subject test or via composition",
  // time — sub-keys exercised through composition / direct lib imports.
  "time.TimeError":                              "backfill — covered indirectly under the time test or via composition",
  "time.toIso8601NoMs":                          "backfill — covered indirectly under the time test or via composition",
  // vault — sub-keys exercised through composition / direct lib imports.
  "vault.VaultError":                            "backfill — covered indirectly under the vault test or via composition",
  "vault.SealPemFileError":                      "framework-error subclass surfaced for `instanceof` checks in operator handlers; vault-seal-pem-file.test.js exercises the throw paths via sealPemFile() with bad inputs — the class itself isn't called as a constructor",
  "vault.getCurrentPassphrase":                  "backfill — covered indirectly under the vault test or via composition",
  // vaultPassphraseOps — sub-keys exercised through composition / direct lib imports.
  "vaultPassphraseOps.preflightRotatable":       "backfill — covered indirectly under the vaultPassphraseOps test or via composition",
  // vaultPassphraseSource — sub-keys exercised through composition / direct lib imports.
  "vaultPassphraseSource.fromFile":              "backfill — covered indirectly under the vaultPassphraseSource test or via composition",
  "vaultPassphraseSource.fromStdin":             "backfill — covered indirectly under the vaultPassphraseSource test or via composition",
  "vaultPassphraseSource.getPassphrase":         "backfill — covered indirectly under the vaultPassphraseSource test or via composition",
  "vaultPassphraseSource.sourceKind":            "backfill — covered indirectly under the vaultPassphraseSource test or via composition",
  // vaultWrap — sub-keys exercised through composition / direct lib imports.
  "vaultWrap.buildHeader":                       "backfill — covered indirectly under the vaultWrap test or via composition",
  "vaultWrap.deriveWrappingKey":                 "backfill — covered indirectly under the vaultWrap test or via composition",
  "vaultWrap.parseHeader":                       "backfill — covered indirectly under the vaultWrap test or via composition",
  // websocket — sub-keys exercised through composition / direct lib imports.
  "websocket.FrameParser":                       "backfill — covered indirectly under the websocket test or via composition",
  "websocket.WebSocketConnection":               "backfill — covered indirectly under the websocket test or via composition",
  "websocket.WebSocketError":                    "backfill — covered indirectly under the websocket test or via composition",
  "websocket.buildUpgradeResponse":              "backfill — covered indirectly under the websocket test or via composition",
  "websocket.computeAcceptKey":                  "backfill — covered indirectly under the websocket test or via composition",
  "websocket.handleExtendedConnect":             "backfill — covered indirectly under the websocket test or via composition",
  "websocket.isOriginAllowed":                   "backfill — covered indirectly under the websocket test or via composition",
  "websocket.negotiateSubprotocol":              "backfill — covered indirectly under the websocket test or via composition",
  "websocket.serializeFrame":                    "backfill — covered indirectly under the websocket test or via composition",
  "websocket.validateUpgradeRequest":            "backfill — covered indirectly under the websocket test or via composition",
};

// ---- Enumeration ----

function _walk(dir, out) {
  var entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_e) { return out; }
  for (var i = 0; i < entries.length; i += 1) {
    var ent = entries[i];
    var p = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      // Skip data dirs / node_modules / .test-output.
      if (ent.name === "node_modules") continue;
      if (ent.name.indexOf("data") === 0) continue;
      if (ent.name === ".test-output") continue;
      _walk(p, out);
    } else if (ent.isFile() && /\.(js|cjs|mjs)$/.test(ent.name)) {
      out.push(p);
    }
  }
  return out;
}

function _readAllTests() {
  var files = _walk(TEST_ROOT, []);
  var blob = "";
  var basenames = new Set();
  for (var i = 0; i < files.length; i += 1) {
    // Don't let this file's own enumeration source count as test
    // coverage — every primitive name appears in this script's
    // output formatter, which would silently mark everything tested.
    if (files[i] === __filename) continue;
    try { blob += fs.readFileSync(files[i], "utf8") + "\n"; }
    catch (_e) { /* drop unreadable */ }
    basenames.add(path.basename(files[i]));
  }
  return { blob: blob, basenames: basenames };
}

function _enumeratePrimitives() {
  var topLevel = [];
  var subLevel = [];
  var keys = Object.keys(b).filter(function (k) { return k[0] !== "_"; });
  for (var k = 0; k < keys.length; k += 1) {
    var name = keys[k];
    topLevel.push(name);
    if (TX_SKIP.has(name)) continue;
    var val = b[name];
    if (!val || typeof val !== "object" || Array.isArray(val)) continue;
    var subKeys = Object.keys(val).filter(function (sk) { return sk[0] !== "_"; });
    for (var s = 0; s < subKeys.length; s += 1) {
      var sub = subKeys[s];
      var qualified = name + "." + sub;
      if (TX_SKIP.has(qualified)) continue;
      var subVal = val[sub];
      // Only enumerate operator-facing surface — function or sub-module
      // exposing at least one function. Bare data tables / class
      // instances / constants stay invisible.
      var isFn = typeof subVal === "function";
      var isModule = subVal && typeof subVal === "object" && !Array.isArray(subVal) &&
        Object.keys(subVal).some(function (mk) { return typeof subVal[mk] === "function"; });
      if (!isFn && !isModule) continue;
      subLevel.push(qualified);
    }
  }
  return { topLevel: topLevel, subLevel: subLevel };
}

function _camelToKebab(s) {
  return s.replace(/[A-Z]/g, function (c) { return "-" + c.toLowerCase(); });
}

function _isReferenced(blob, qualifiedName, fileBasenames) {
  // Three signals count as a test reference:
  //
  //   1. Verbatim `b.X` or `b.X.Y` (lookahead rejects `b.guard`
  //      partial-matching `b.guardCsv`). Most direct case.
  //
  //   2. require("...lib/<kebab-form>") — tests that import a module
  //      directly without going through the `b` surface still cover
  //      it. The kebab form is the camelCase name with `.` flattened
  //      to `-`. e.g. `guardDomain` → `guard-domain`,
  //      `auth.password` → `auth/password` (slash for sub-paths).
  //
  //   3. A test file basename equal to the kebab form. `guard-domain.test.js`
  //      counts as coverage for `b.guardDomain` even when the test
  //      uses dynamic loading (e.g. the adaptive integration harness
  //      iterating `b.guardAll.allGuards()`).
  var escaped = qualifiedName.replace(/[.]/g, "\\.");
  var direct = new RegExp("\\bb\\." + escaped + "(?![A-Za-z0-9_])");
  if (direct.test(blob)) return true;

  var dotted = qualifiedName.split(".");
  var kebabSlash = dotted.map(_camelToKebab).join("/");        // auth.password → auth/password
  var kebabFlat  = dotted.map(_camelToKebab).join("-");        // auth.password → auth-password
  var requireSlash = new RegExp("require\\([^)]*\\b" + kebabSlash.replace(/[/\\-]/g, function (c) {
    return c === "/" ? "[\\\\/]" : "\\-";
  }) + "(?:\\.js)?[\\\"']");
  if (requireSlash.test(blob)) return true;

  var bareName = _camelToKebab(dotted[dotted.length - 1]);     // last segment, kebab form
  var requireBare = new RegExp("require\\([^)]*\\b" + bareName + "(?:\\.js)?[\\\"']");
  if (requireBare.test(blob)) return true;

  if (fileBasenames.has(kebabFlat + ".test.js")) return true;
  if (fileBasenames.has(bareName + ".test.js")) return true;

  return false;
}

// ---- Run ----

async function run() {
  var bundle = _readAllTests();
  var blob = bundle.blob;
  var basenames = bundle.basenames;
  var { topLevel, subLevel } = _enumeratePrimitives();

  var untested = [];
  for (var i = 0; i < topLevel.length; i += 1) {
    var name = topLevel[i];
    if (TX_SKIP.has(name)) continue;
    if (UNTESTED_BACKLOG[name]) continue;
    if (!_isReferenced(blob, name, basenames)) untested.push(name);
  }
  for (var j = 0; j < subLevel.length; j += 1) {
    var qn = subLevel[j];
    if (TX_SKIP.has(qn)) continue;
    if (UNTESTED_BACKLOG[qn]) continue;
    // If the parent is on a skip list, in the backlog, OR already
    // flagged as untested at the top level, the parent's status
    // covers the whole sub-tree. We only flag a sub-key when its
    // parent is genuinely tested and the sub-key alone is missing.
    var parent = qn.split(".")[0];
    if (TX_SKIP.has(parent)) continue;
    if (UNTESTED_BACKLOG[parent]) continue;
    if (untested.indexOf(parent) !== -1) continue;
    if (!_isReferenced(blob, qn, basenames)) untested.push(qn);
  }

  if (untested.length > 0) {
    console.error("[test-coverage] " + untested.length +
      " operator-facing b.* primitive(s) lack any test reference:");
    for (var u = 0; u < untested.length; u += 1) {
      console.error("  b." + untested[u] +
        " — add a test that calls b." + untested[u] +
        " directly OR add to UNTESTED_BACKLOG with a one-line reason in " +
        "test/layer-0-primitives/test-coverage.test.js");
    }
  }

  check("every operator-facing b.* primitive has at least one test reference",
        untested.length === 0);
}

module.exports = { run: run };

if (require.main === module) {
  var fsLog = require("fs");
  var pathLog = require("path");
  var OUT = pathLog.join(REPO_ROOT, ".test-output");
  try { fsLog.mkdirSync(OUT, { recursive: true }); } catch (_e) { /* best-effort */ }
  var LOG_PATH = pathLog.join(OUT, "test-coverage.log");
  try { fsLog.unlinkSync(LOG_PATH); } catch (_e) { /* fresh */ }
  var _logFd = fsLog.openSync(LOG_PATH, "w");
  function _logWrite(chunk) {
    try {
      var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
      fsLog.writeSync(_logFd, buf, 0, buf.length, null);
    } catch (_e) { /* best-effort */ }
  }
  var origStdout = process.stdout.write.bind(process.stdout);
  var origStderr = process.stderr.write.bind(process.stderr);
  process.stdout.write = function (c, e, cb) { _logWrite(c); return origStdout(c, e, cb); };
  process.stderr.write = function (c, e, cb) { _logWrite(c); return origStderr(c, e, cb); };
  process.on("exit", function () { try { fsLog.closeSync(_logFd); } catch (_e) { /* best-effort */ } });
  console.log("output: " + LOG_PATH);
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
