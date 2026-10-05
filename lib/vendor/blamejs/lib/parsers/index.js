// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.parsers
 * @nav    Validation
 * @title  Parsers
 * @slug   parsers
 *
 * @intro
 *   The configuration and document formats the framework parses, each with
 *   the features that make a parser an attack surface absent rather than
 *   switched off.
 *
 *   A parser is where untrusted bytes first become structure, and the
 *   dangerous parts are the ones a format added for convenience. XML has
 *   external entities, which read files off the server and make requests
 *   from it. YAML has tags that construct arbitrary objects, and anchors
 *   that expand into gigabytes from a few lines. TOML, INI and env files
 *   have no such feature, but they do have duplicate keys and keys named
 *   after a prototype.
 *
 *   None of it is behind an option. There is no way to ask
 *   <code>b.parsers.xml</code> to resolve an external entity, because a
 *   flag that can be turned on is a flag that gets turned on. Each
 *   refusal carries its own code, so an operator reading a log can tell
 *   which one fired: a <code>DOCTYPE</code> of any kind is
 *   <code>xml/doctype</code>, which takes out both entity resolution and
 *   entity expansion; a YAML tag is <code>yaml/tags-banned</code> and an
 *   anchor is <code>yaml/anchors-banned</code>; a key named after a
 *   prototype is <code>yaml/poisoned-key</code>,
 *   <code>ini/forbidden-key</code> or <code>env/poisoned-key</code>; and a
 *   repeated TOML key is <code>toml/duplicate-key</code> rather than a
 *   silent last-one-wins.
 *
 *   The members are <code>xml</code>, <code>yaml</code>,
 *   <code>toml</code>, <code>ini</code> and <code>env</code>, plus
 *   <code>json</code> and <code>multipart</code>, which are the
 *   request-body readers <code>b.middleware.bodyParser</code> mounts.
 *
 * @card
 *   Parse XML, YAML, TOML, INI, env files, JSON bodies and multipart
 *   uploads with the features that make each format an attack surface
 *   absent rather than switched off.
 */

var safeEnv  = require("./safe-env");
var safeIni  = require("./safe-ini");
var safeToml = require("./safe-toml");
var safeXml  = require("./safe-xml");
var safeYaml = require("./safe-yaml");
var bodyParser = require("../middleware/body-parser");

module.exports = {
  xml:       safeXml,
  toml:      safeToml,
  yaml:      safeYaml,
  env:       safeEnv,
  ini:       safeIni,
  json:      bodyParser.parseJson,
  multipart: bodyParser.parseMultipart,
};
