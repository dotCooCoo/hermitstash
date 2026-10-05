// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.frameworkError
 * @nav    Primitives
 * @title  Framework Error
 * @slug   framework-error
 *
 * @intro
 *   Every error the framework throws is built here, so an operator catching
 *   one finds the same fields whichever primitive raised it: a
 *   <code>name</code>, a stable <code>code</code> like
 *   <code>auth/replayed</code>, an <code>isFrameworkError</code> flag and a
 *   per-class flag such as <code>isAuthError</code>.
 *
 *   The field that decides what happens next is <code>permanent</code>. A retry
 *   layer reads it to tell a failure worth trying again from one that will
 *   fail the same way forever: a timeout is transient, a malformed
 *   signature is not. Retrying a permanent failure is a loop, and giving up
 *   on a transient one is an outage, so each class declares which of its
 *   failures are which rather than leaving the caller to guess from a
 *   message.
 *
 *   The namespace exports the base class, the three functions that mint
 *   classes, and the classes themselves, one per primitive that throws.
 *   Operators catch them; only a primitive author mints one.
 *
 * @section Two constructor orders, one factory order
 *   <code>defineClass</code> builds a class taking
 *   <code>(code, message)</code>. <code>defineMessageFirstClass</code>
 *   builds one taking <code>(message, code)</code>, matching a class that
 *   was written by hand before the generator existed.
 *
 *   Both attach a <code>factory(code, message)</code>, in that order, for
 *   both kinds. So code that has to raise a class it was handed calls the
 *   factory: <code>new errorClass(code, msg)</code> on a message-first
 *   class puts the code in the message and the message in the code, and
 *   nothing complains, because both are strings.
 *
 * @card
 *   The error classes every primitive throws, each with a stable code, a
 *   per-class flag, and a permanent field a retry layer reads to tell a
 *   failure worth retrying from one that never will be.
 */

var observability = require("./observability");

class FrameworkError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "FrameworkError";
    this.code = code || "framework/invalid";
    this.isFrameworkError = true;
  }
}

/**
 * @primitive b.frameworkError.defineMessageFirstClass
 * @signature b.frameworkError.defineMessageFirstClass(name, defaultCode, opts?)
 * @since     0.20.31
 * @status    stable
 * @related   b.frameworkError.defineClass, b.frameworkError.messageFirstFactory
 *
 * Mint an error class whose constructor takes `(message, code)`, with
 * `code` falling back to `defaultCode` when the caller gives none. Use it
 * only to keep a class that was written by hand before the generator
 * existed; a new class uses `b.frameworkError.defineClass`, whose order
 * matches the rest of the framework.
 *
 * The class carries `factory(code, message)`, code first, the same as
 * every other class here. That is on purpose: code handed an error class
 * calls the factory and does not have to know which order the constructor
 * takes.
 *
 * `opts.permanent` marks every instance permanent, for a class whose
 * failures are never worth retrying.
 *
 * @opts
 *   permanent: boolean,   // mark every instance permanent
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var MyError = b.frameworkError.defineMessageFirstClass("MyError", "my/invalid");
 *   new MyError("that did not parse").code;              // → "my/invalid"
 *   new MyError("that did not parse", "my/bad-input").code;   // → "my/bad-input"
 *   MyError.factory("my/bad-input", "that did not parse").message;
 *   // → "that did not parse"
 */
function defineMessageFirstClass(name, defaultCode, opts) {
  opts = opts || {};
  var flagKey = "is" + name;
  var permanent = !!opts.permanent;
  var Built = class extends FrameworkError {
    constructor(message, code) {
      super(message);
      this.name = name;
      this.code = code || defaultCode;
      if (permanent) this.permanent = true;
      this[flagKey] = true;
    }
  };
  Object.defineProperty(Built, "name", { value: name, configurable: true });
  return messageFirstFactory(Built);
}

/**
 * @primitive b.frameworkError.messageFirstFactory
 * @signature b.frameworkError.messageFirstFactory(errorClass)
 * @since     0.20.31
 * @status    stable
 * @related   b.frameworkError.defineMessageFirstClass, b.frameworkError.defineClass
 *
 * Attach a `factory(code, message)` to a class whose constructor takes
 * `(message, code)`, and answer the same class.
 *
 * It exists so a hand-written error class can be passed to code that raises
 * whatever class it was handed. That code calls `errorClass.factory(code,
 * msg)`; without a factory it would call the constructor and put the code
 * where the message goes.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   class MyError extends b.frameworkError.FrameworkError {}
 *   b.frameworkError.messageFirstFactory(MyError) === MyError;   // → true
 *   typeof MyError.factory;                                      // → "function"
 */
function messageFirstFactory(errorClass) {
  errorClass.factory = function (code, message, arg3, arg4) {
    return new errorClass(message, code, arg3, arg4);
  };
  return errorClass;
}

/**
 * @primitive b.frameworkError.defineClass
 * @signature b.frameworkError.defineClass(name, opts?)
 * @since     0.1.92
 * @status    stable
 * @related   b.frameworkError.defineMessageFirstClass, b.frameworkError.messageFirstFactory
 *
 * Mint an error class for a primitive. It extends the base class, its
 * constructor takes `(code, message, arg3, arg4)`, and it carries a
 * `factory(code, message, arg3, arg4)` so code handed the class can raise
 * one without calling `new`.
 *
 * An instance carries `name`, `code`, `message`, `isFrameworkError`, and a
 * flag named after the class, so `err.isApiKeyError` answers without an
 * `instanceof` across a module boundary.
 *
 * What `arg3` and `arg4` mean is what the options choose, and one option
 * at most:
 *
 * With none, `arg3` is `permanent`, so each call site says whether that
 * failure is worth retrying. `alwaysPermanent` makes every instance
 * permanent and ignores `arg3`, for a class whose failures are all
 * configuration or malformed input. `withStatusCode` keeps `arg3` as
 * `permanent` and takes an HTTP status in `arg4`. `withCause` puts the
 * underlying error in `arg3` as `cause`, for a class that wraps a failure
 * from somewhere else. `permanentClassifier` takes a status in `arg3`,
 * keeps it as `statusCode`, and calls the function with `(code, status)` to
 * decide `permanent`, which is how a transport tells a 400 from a 503
 * without every call site repeating the rule. `transientCodes` is that same
 * rule when the decision is the code alone: every code it lists is transient
 * and every other code of the class is permanent.
 *
 * They are mutually exclusive and combining them throws here, at the mint,
 * rather than producing a class whose third argument means two things.
 *
 * @opts
 *   alwaysPermanent:     boolean,        // every instance is permanent; arg3 ignored
 *   withStatusCode:      boolean,        // arg4 is an HTTP status
 *   withCause:           boolean,        // arg3 is the underlying error
 *   permanentClassifier: function,       // (code, status) → boolean; arg3 is the status
 *   transientCodes:      Array<string>,  // these codes are transient, the rest permanent
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var MyError = b.frameworkError.defineClass("MyError", { alwaysPermanent: true });
 *   var err = new MyError("my/bad-input", "that did not parse");
 *   err.code;          // → "my/bad-input"
 *   err.permanent;     // → true
 *   err.isMyError;     // → true
 */
function defineClass(name, opts) {
  if (typeof name !== "string" || name.length === 0) {
    throw new Error("defineClass: name must be a non-empty string");
  }
  opts = opts || {};
  var alwaysPermanent = !!opts.alwaysPermanent;
  var withStatusCode  = !!opts.withStatusCode;
  var withCause       = !!opts.withCause;
  var permanentClassifier = typeof opts.permanentClassifier === "function" ? opts.permanentClassifier : null;
  var declaredTransient = null;
  if (opts.transientCodes !== undefined) {
    if (permanentClassifier) {
      throw new Error("defineClass: transientCodes is mutually exclusive with permanentClassifier");
    }
    var badList = !Array.isArray(opts.transientCodes) ||
      opts.transientCodes.length === 0 ||
      opts.transientCodes.some(function (c) { return typeof c !== "string" || c.length === 0; });
    if (badList) {
      throw new Error("defineClass: transientCodes must be a non-empty array of " +
        "non-empty code strings");
    }
    var transientSet = Object.create(null);
    opts.transientCodes.forEach(function (c) { transientSet[c] = true; });
    permanentClassifier = function (code) { return transientSet[code] !== true; };
    declaredTransient = transientSet;
  }
  if (alwaysPermanent && (withStatusCode || withCause)) {
    throw new Error("defineClass: alwaysPermanent is mutually exclusive with withStatusCode / withCause");
  }
  if (permanentClassifier && (alwaysPermanent || withStatusCode || withCause)) {
    throw new Error("defineClass: permanentClassifier is mutually exclusive with alwaysPermanent / withStatusCode / withCause");
  }
  var flagKey = "is" + name;

  var GeneratedError = class extends FrameworkError {
    constructor(code, message, arg3, arg4) {
      super(message, code);
      this.name = name;
      this[flagKey] = true;
      if (alwaysPermanent) {
        this.permanent = true;
      } else if (permanentClassifier) {
        this.statusCode = arg3;
        this.permanent = !!permanentClassifier(code, arg3);
        if (declaredTransient !== null && declaredTransient[code] === true) {
          this.transient = true;
        }
      } else if (withCause) {
        this.cause = arg3;
      } else {
        this.permanent = !!arg3;
        if (withStatusCode) this.statusCode = arg4;
      }
      observability.safeEvent("error.construct", 1, { class: name });
    }
  };
  Object.defineProperty(GeneratedError, "name", { value: name, configurable: true });
  GeneratedError.factory = function (code, message, arg3, arg4) {
    return new GeneratedError(code, message, arg3, arg4);
  };
  return GeneratedError;
}

var ObjectStoreError      = defineClass("ObjectStoreError",      { withStatusCode: true });
var LogStreamError        = defineClass("LogStreamError",        { withStatusCode: true });
var QueueError            = defineClass("QueueError");
var RedisError            = defineClass("RedisError");
var ExternalDbError       = defineClass("ExternalDbError");
var DbQueryError          = defineClass("DbQueryError");
var ClusterError          = defineClass("ClusterError");
var ClusterProviderError  = defineClass("ClusterProviderError");
var HandlerError          = defineClass("HandlerError",          { withCause: true });
var StorageError          = defineClass("StorageError");
var AuthError             = defineClass("AuthError",             { alwaysPermanent: true });
var Argon2Error           = defineClass("Argon2Error", {
  transientCodes: ["argon2/busy", "argon2/queue-timeout"],
});
var JobsError             = defineClass("JobsError");
var SchedulerError        = defineClass("SchedulerError");
var SessionError          = defineClass("SessionError");
var SlugError             = defineClass("SlugError",             { alwaysPermanent: true });
var WebhookError          = defineClass("WebhookError",          { alwaysPermanent: true });
var WebhookDispatcherError = defineClass("WebhookDispatcherError", { alwaysPermanent: true });
var ApiKeyError           = defineClass("ApiKeyError",           { alwaysPermanent: true });
var PermissionsError      = defineClass("PermissionsError",      { alwaysPermanent: true });
var CacheError            = defineClass("CacheError",            { alwaysPermanent: true });
var SeederError           = defineClass("SeederError",           { alwaysPermanent: true });
var I18nError             = defineClass("I18nError",             { alwaysPermanent: true });
var NotifyError           = defineClass("NotifyError",           { alwaysPermanent: true });
var TestingError          = defineClass("TestingError",          { alwaysPermanent: true });
var LockoutError          = defineClass("LockoutError",          { alwaysPermanent: true });
var FileUploadError       = defineClass("FileUploadError",       { alwaysPermanent: true });
var StaticServeError      = defineClass("StaticServeError",      { withStatusCode: true });
var GateContractError     = defineClass("GateContractError",     { alwaysPermanent: true });
var GuardCsvError         = defineClass("GuardCsvError",         { alwaysPermanent: true });
var GuardTextError        = defineClass("GuardTextError",        { alwaysPermanent: true });
var GuardAllError         = defineClass("GuardAllError",         { alwaysPermanent: true });
var GuardHtmlError        = defineClass("GuardHtmlError",        { alwaysPermanent: true });
var GuardSvgError         = defineClass("GuardSvgError",         { alwaysPermanent: true });
var GuardFilenameError    = defineClass("GuardFilenameError",    { alwaysPermanent: true });
var GuardSqlError         = defineClass("GuardSqlError",         { alwaysPermanent: true });
var GuardArchiveError     = defineClass("GuardArchiveError",     { alwaysPermanent: true });
var GuardJsonError        = defineClass("GuardJsonError",        { alwaysPermanent: true });
var GuardYamlError        = defineClass("GuardYamlError",        { alwaysPermanent: true });
var GuardXmlError         = defineClass("GuardXmlError",         { alwaysPermanent: true });
var GuardMarkdownError    = defineClass("GuardMarkdownError",    { alwaysPermanent: true });
var GuardEmailError       = defineClass("GuardEmailError",       { alwaysPermanent: true });
var GuardDomainError      = defineClass("GuardDomainError",      { alwaysPermanent: true });
var GuardUuidError        = defineClass("GuardUuidError",        { alwaysPermanent: true });
var GuardCidrError        = defineClass("GuardCidrError",        { alwaysPermanent: true });
var GuardCountryError     = defineClass("GuardCountryError",     { alwaysPermanent: true });
var GuardTimeError        = defineClass("GuardTimeError",        { alwaysPermanent: true });
var GuardMimeError        = defineClass("GuardMimeError",        { alwaysPermanent: true });
var GuardJwtError         = defineClass("GuardJwtError",         { alwaysPermanent: true });
var GuardOauthError       = defineClass("GuardOauthError",       { alwaysPermanent: true });
var GuardGraphqlError     = defineClass("GuardGraphqlError",     { alwaysPermanent: true });
var GuardShellError       = defineClass("GuardShellError",       { alwaysPermanent: true });
var GuardRegexError       = defineClass("GuardRegexError",       { alwaysPermanent: true });
var GuardJsonpathError    = defineClass("GuardJsonpathError",    { alwaysPermanent: true });
var GuardTemplateError    = defineClass("GuardTemplateError",    { alwaysPermanent: true });
var GuardImageError       = defineClass("GuardImageError",       { alwaysPermanent: true });
var GuardPdfError         = defineClass("GuardPdfError",         { alwaysPermanent: true });
var GuardAuthError        = defineClass("GuardAuthError",        { alwaysPermanent: true });
var DoraError             = defineClass("DoraError",             { alwaysPermanent: true });
var ComplianceError       = defineClass("ComplianceError",       { alwaysPermanent: true });
var PrivacyError          = defineClass("PrivacyError",          { alwaysPermanent: true });
var DsaError              = defineClass("DsaError",              { alwaysPermanent: true });
var PiplError             = defineClass("PiplError",             { alwaysPermanent: true });
var SmtpPolicyError       = defineClass("SmtpPolicyError",       { alwaysPermanent: true });
var MailAuthError         = defineClass("MailAuthError",         { alwaysPermanent: true });
var MailArfError          = defineClass("MailArfError",          { alwaysPermanent: true });
var MailBimiError         = defineClass("MailBimiError",         { alwaysPermanent: true });
var SseError              = defineClass("SseError",              { alwaysPermanent: true });
var McpError              = defineClass("McpError",              { alwaysPermanent: true });
var AiInputError          = defineClass("AiInputError",          { alwaysPermanent: true });
var AiOutputError         = defineClass("AiOutputError",         { alwaysPermanent: true });
var AiPromptError         = defineClass("AiPromptError",         { alwaysPermanent: true });
var A2aError              = defineClass("A2aError",              { alwaysPermanent: true });
var GraphqlFederationError = defineClass("GraphqlFederationError", { alwaysPermanent: true });
var Fda21Cfr11Error       = defineClass("Fda21Cfr11Error",       { alwaysPermanent: true });
var AuditDailyReviewError = defineClass("AuditDailyReviewError", { alwaysPermanent: true });
var AuditSegregationError = defineClass("AuditSegregationError", { alwaysPermanent: true });
var AuditChainOriginError = defineClass("AuditChainOriginError", { alwaysPermanent: true });
var DdlChangeControlError = defineClass("DdlChangeControlError", { alwaysPermanent: true });
var LegalHoldError        = defineClass("LegalHoldError",        { alwaysPermanent: true });
var WormViolationError    = defineClass("WormViolationError",    { alwaysPermanent: true });
var SandboxError          = defineClass("SandboxError",          { alwaysPermanent: true });
var DlpError              = defineClass("DlpError",              { alwaysPermanent: true });
var AuthBotChallengeError = defineClass("AuthBotChallengeError", { alwaysPermanent: true });
var BotChallengeError     = defineClass("BotChallengeError",     { alwaysPermanent: true });
var SessionDeviceBindingError = defineClass("SessionDeviceBindingError", { alwaysPermanent: true });
var AcmeError             = defineClass("AcmeError",             { withStatusCode: true });

var HpkeError             = defineClass("HpkeError",             { alwaysPermanent: true });
var TlsExporterError      = defineClass("TlsExporterError",      { alwaysPermanent: true });
var HttpSigError          = defineClass("HttpSigError",          { alwaysPermanent: true });
var HttpClientError       = defineClass("HttpClientError",       { withStatusCode: true });
var KeychainError         = defineClass("KeychainError",         { alwaysPermanent: true });
var WatcherError          = defineClass("WatcherError",          { alwaysPermanent: true });
var LocalDbThinError      = defineClass("LocalDbThinError",      { alwaysPermanent: true });
var RouterError           = defineClass("RouterError",           { alwaysPermanent: true });
var WorkerPoolError       = defineClass("WorkerPoolError",       { alwaysPermanent: true });
var ArgParserError        = defineClass("ArgParserError",        { alwaysPermanent: true });
var DaemonError           = defineClass("DaemonError",           { alwaysPermanent: true });
var SelfUpdateError       = defineClass("SelfUpdateError",       { alwaysPermanent: true });
var MailUnsubscribeError  = defineClass("MailUnsubscribeError",  { alwaysPermanent: true });
var FidoMds3Error         = defineClass("FidoMds3Error",         { alwaysPermanent: true });
var PublicSuffixError     = defineClass("PublicSuffixError",     { alwaysPermanent: true });
var MailMdnError          = defineClass("MailMdnError",          { alwaysPermanent: true });
var ProblemDetailsError   = defineClass("ProblemDetailsError",   { alwaysPermanent: true });
var IdempotencyError      = defineClass("IdempotencyError",      { alwaysPermanent: true });

module.exports = {
  FrameworkError:         FrameworkError,
  defineClass:            defineClass,
  messageFirstFactory:    messageFirstFactory,
  defineMessageFirstClass: defineMessageFirstClass,
  MailUnsubscribeError:   MailUnsubscribeError,
  ObjectStoreError:       ObjectStoreError,
  LogStreamError:         LogStreamError,
  QueueError:             QueueError,
  RedisError:             RedisError,
  ExternalDbError:        ExternalDbError,
  DbQueryError:           DbQueryError,
  ClusterError:           ClusterError,
  ClusterProviderError:   ClusterProviderError,
  HandlerError:           HandlerError,
  StorageError:           StorageError,
  AuthError:              AuthError,
  Argon2Error:            Argon2Error,
  JobsError:              JobsError,
  SchedulerError:         SchedulerError,
  SessionError:           SessionError,
  SlugError:              SlugError,
  WebhookError:           WebhookError,
  WebhookDispatcherError: WebhookDispatcherError,
  ApiKeyError:            ApiKeyError,
  PermissionsError:       PermissionsError,
  CacheError:             CacheError,
  SeederError:            SeederError,
  I18nError:              I18nError,
  NotifyError:            NotifyError,
  TestingError:           TestingError,
  LockoutError:           LockoutError,
  FileUploadError:        FileUploadError,
  StaticServeError:       StaticServeError,
  GateContractError:      GateContractError,
  GuardCsvError:          GuardCsvError,
  GuardTextError:         GuardTextError,
  GuardAllError:          GuardAllError,
  GuardHtmlError:         GuardHtmlError,
  GuardSvgError:          GuardSvgError,
  GuardFilenameError:     GuardFilenameError,
  GuardSqlError:          GuardSqlError,
  GuardArchiveError:      GuardArchiveError,
  GuardJsonError:         GuardJsonError,
  GuardYamlError:         GuardYamlError,
  GuardXmlError:          GuardXmlError,
  GuardMarkdownError:     GuardMarkdownError,
  GuardEmailError:        GuardEmailError,
  GuardDomainError:       GuardDomainError,
  GuardUuidError:         GuardUuidError,
  GuardCidrError:         GuardCidrError,
  GuardCountryError:      GuardCountryError,
  GuardTimeError:         GuardTimeError,
  GuardMimeError:         GuardMimeError,
  GuardJwtError:          GuardJwtError,
  GuardOauthError:        GuardOauthError,
  GuardGraphqlError:      GuardGraphqlError,
  GuardShellError:        GuardShellError,
  GuardRegexError:        GuardRegexError,
  GuardJsonpathError:     GuardJsonpathError,
  GuardTemplateError:     GuardTemplateError,
  GuardImageError:        GuardImageError,
  GuardPdfError:          GuardPdfError,
  GuardAuthError:         GuardAuthError,
  DoraError:              DoraError,
  ComplianceError:        ComplianceError,
  PrivacyError:           PrivacyError,
  DsaError:               DsaError,
  PiplError:              PiplError,
  SmtpPolicyError:        SmtpPolicyError,
  MailAuthError:          MailAuthError,
  MailArfError:           MailArfError,
  MailBimiError:          MailBimiError,
  SseError:               SseError,
  McpError:               McpError,
  AiInputError:           AiInputError,
  AiOutputError:          AiOutputError,
  AiPromptError:          AiPromptError,
  A2aError:               A2aError,
  GraphqlFederationError: GraphqlFederationError,
  Fda21Cfr11Error:        Fda21Cfr11Error,
  AuditDailyReviewError:  AuditDailyReviewError,
  AuditChainOriginError:  AuditChainOriginError,
  AuditSegregationError:  AuditSegregationError,
  DdlChangeControlError:  DdlChangeControlError,
  LegalHoldError:         LegalHoldError,
  WormViolationError:     WormViolationError,
  SandboxError:           SandboxError,
  DlpError:               DlpError,
  AuthBotChallengeError:  AuthBotChallengeError,
  BotChallengeError:      BotChallengeError,
  SessionDeviceBindingError: SessionDeviceBindingError,
  AcmeError:              AcmeError,
  HpkeError:              HpkeError,
  TlsExporterError:       TlsExporterError,
  HttpSigError:           HttpSigError,
  HttpClientError:        HttpClientError,
  KeychainError:          KeychainError,
  WatcherError:           WatcherError,
  LocalDbThinError:       LocalDbThinError,
  RouterError:            RouterError,
  WorkerPoolError:        WorkerPoolError,
  ArgParserError:         ArgParserError,
  DaemonError:            DaemonError,
  SelfUpdateError:        SelfUpdateError,
  FidoMds3Error:          FidoMds3Error,
  PublicSuffixError:      PublicSuffixError,
  MailMdnError:           MailMdnError,
  ProblemDetailsError:    ProblemDetailsError,
  IdempotencyError:       IdempotencyError,
};
