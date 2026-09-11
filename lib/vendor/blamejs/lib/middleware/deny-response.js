// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
var problemDetails = require("../problem-details");
var safeAsync = require("../safe-async");
var validateOpts = require("../validate-opts");

function _isFn(x) { return typeof x === "function"; }

function denyResponse(req, res, ctx) {
  var info = (ctx.info && typeof ctx.info === "object") ? ctx.info : {};

  if (_isFn(ctx.onDeny)) {
    try {
      var returned = safeAsync.containRejection(ctx.onDeny(req, res, info), ctx.onThrow);
      if (res.writableEnded || res.headersSent) return returned;
    } catch (e) {
      if (_isFn(ctx.onThrow)) {
        try { ctx.onThrow(e); } catch (_e) { /* drop-silent */ }
      }
      if (res.writableEnded || res.headersSent) return undefined;
    }
  }

  if (res.writableEnded || res.headersSent || !_isFn(res.writeHead)) return undefined;

  var extra = (ctx.headers && typeof ctx.headers === "object") ? ctx.headers : null;

  if (ctx.problem) {
    var fields = { status: ctx.status };
    if (ctx.problemType) {
      fields.type = ctx.problemType;
    } else if (typeof ctx.problemCode === "string" && ctx.problemCode.length > 0) {
      fields.type = problemDetails.getBase() + "/" +
        ctx.problemCode.replace(/[^A-Za-z0-9\-._/]/g, "-");
    }
    if (ctx.problemTitle)  fields.title  = ctx.problemTitle;
    if (ctx.problemDetail) fields.detail = ctx.problemDetail;
    if (ctx.problemExt && typeof ctx.problemExt === "object") {
      var ek = Object.keys(ctx.problemExt);
      for (var i = 0; i < ek.length; i += 1) {
        if (problemDetails.RESERVED_FIELDS.indexOf(ek[i]) === -1) {
          fields[ek[i]] = ctx.problemExt[ek[i]];
        }
      }
    }
    var problem;
    try {
      problem = problemDetails.create(fields);
    } catch (_e) {
      problem = problemDetails.create({ status: ctx.status });
    }
    if (extra) {
      var hk = Object.keys(extra);
      for (var h = 0; h < hk.length; h += 1) {
        res.setHeader(hk[h], extra[hk[h]]);
      }
    }
    problemDetails.respond(res, problem, req);
    return undefined;
  }

  var head = validateOpts.assignOwnEnumerable({ "Content-Type": ctx.contentType }, extra);
  var denyOut = (ctx.body === undefined || ctx.body === null) ? ""
    : (typeof ctx.body === "string" ? ctx.body : JSON.stringify(ctx.body));
  if (ctx.body !== undefined && ctx.body !== null && req && typeof req.apiEncryptEncode === "function") {
    try { denyOut = JSON.stringify(req.apiEncryptEncode(ctx.body)); } catch (_e) { /* plaintext kept */ }
  }
  res.writeHead(ctx.status, head);
  res.end(denyOut);
  return undefined;
}

function methodNotAllowed(res, allow) {
  var bodyMsg = "Method Not Allowed";
  res.writeHead(C.HTTP.STATUS.METHOD_NOT_ALLOWED, {
    "Allow":          allow,
    "Content-Type":   "text/plain; charset=utf-8",
    "Content-Length": Buffer.byteLength(bodyMsg),
  });
  res.end(bodyMsg);
}

module.exports = {
  denyResponse:     denyResponse,
  methodNotAllowed: methodNotAllowed,
};
