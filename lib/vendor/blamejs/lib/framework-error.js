// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var observability = require("./observability");

class FrameworkError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "FrameworkError";
    this.code = code || "framework/invalid";
    this.isFrameworkError = true;
  }
}

function defineClass(name, opts) {
  if (typeof name !== "string" || name.length === 0) {
    throw new Error("defineClass: name must be a non-empty string");
  }
  opts = opts || {};
  var alwaysPermanent = !!opts.alwaysPermanent;
  var withStatusCode  = !!opts.withStatusCode;
  var withCause       = !!opts.withCause;
  var permanentClassifier = typeof opts.permanentClassifier === "function" ? opts.permanentClassifier : null;
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
