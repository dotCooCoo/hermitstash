// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: b.guardSmtpCommand.validate
 *
 * libFuzzer / jazzer.js harness. Targets the SMTP command-line
 * validator's smuggling + injection defenses:
 *   - CVE-2023-51764 (Postfix SMTP smuggling)
 *   - CVE-2023-51765 (Sendmail SMTP smuggling)
 *   - CVE-2023-51766 (Exim SMTP smuggling)
 *   - CVE-2026-32178 (.NET System.Net.Mail header injection class)
 *   - CVE-2021-38371 (Exim STARTTLS response injection)
 *   - CVE-2021-33515 (Dovecot lib-smtp STARTTLS command injection)
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var line = data.toString("utf8");
  try {
    b.guardSmtpCommand.validate(line);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("guard-smtp-command/") === 0) return;
    throw e;
  }
};
