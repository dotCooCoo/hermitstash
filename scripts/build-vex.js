#!/usr/bin/env node
'use strict';

// Release-time VEX builder. Reads vex/statements.json, expands each
// entry into a CSAF 2.1 §3.2.3 vulnerability statement via b.vex.statement
// (handles cveId / ids[] / cweId / justification flags / product_status),
// wraps them in a b.vex.document, and writes the serialized JSON to
//
//   <outDir>/hermitstash-vX.Y.Z.vex.json
//
// Empty statements array = no output, exit 0. Operators add statements
// as transitive-CVE assessments accumulate; the file is committed source.
//
// Usage:
//   node scripts/build-vex.js [--out <dir>] [--date <iso>]
//
// CI:
//   .github/workflows/docker-publish.yml runs this after the image is
//   built + signed, then attaches the output as a cosign attestation
//   on the GHCR image manifest (predicate type
//   https://docs.oasis-open.org/csaf/csaf-vex/v2.1/).

var fs = require('node:fs');
var path = require('node:path');
var b = require('../lib/vendor/blamejs');

var REPO_ROOT = path.resolve(__dirname, '..');
var INPUT_PATH = path.join(REPO_ROOT, 'vex', 'statements.json');

// Image platforms the Docker build emits. Keep in sync with
// .github/workflows/docker-publish.yml `build-and-push` step's
// `platforms:` value.
var PLATFORMS = ['linux-amd64', 'linux-arm64'];
var HAS_CONTAINER = true;

function parseArgs(argv) {
  var opts = { outDir: path.join(REPO_ROOT, 'build'), dateIso: null };
  for (var i = 0; i < argv.length; i++) {
    if (argv[i] === '--out' && argv[i + 1]) { opts.outDir = path.resolve(argv[++i]); continue; }
    if (argv[i] === '--date' && argv[i + 1]) { opts.dateIso = argv[++i]; continue; }
  }
  return opts;
}

function readInput() {
  if (!fs.existsSync(INPUT_PATH)) {
    return { statements: [] };
  }
  var raw = fs.readFileSync(INPUT_PATH, 'utf8');
  var parsed = b.safeJson.parse(raw, { maxBytes: b.constants.BYTES.mib(1) });
  if (!parsed || !Array.isArray(parsed.statements)) {
    throw new Error('vex/statements.json missing top-level "statements" array');
  }
  return parsed;
}

function readVersion() {
  // Static literal require so bundlers/SEA can trace it (no require(variable)).
  return require('../lib/constants').version;
}

function expandProductScope(scope, version) {
  var all = PLATFORMS.map(function (p) { return 'hermitstash@' + version + ':' + p; });
  if (HAS_CONTAINER) all.push('hermitstash@' + version + ':container');
  if (scope === 'all' || scope == null) return all;
  if (!Array.isArray(scope)) {
    throw new Error('productScope must be "all" or an array; got ' + typeof scope);
  }
  // Operator-supplied product IDs pass through verbatim — they may
  // reference a different release version (e.g. a CVE first surfaced
  // in 1.8.x but assessed at 1.10.x).
  return scope;
}

function buildStatements(entries, version) {
  var out = [];
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    var productIds = expandProductScope(e.productScope, version);
    try {
      out.push(b.vex.statement({
        cveId:           e.cveId,
        cweId:           e.cweId,
        ids:             e.ids,
        status:          e.status,
        productIds:      productIds,
        justification:   e.justification,
        impactStatement: e.impactStatement,
        references:      e.references,
        firstReleased:   e.firstReleased,
        lastUpdated:     e.lastUpdated,
      }));
    } catch (err) {
      var label = e.cveId || (e.ids && e.ids[0] && e.ids[0].text) || ('#' + i);
      throw new Error('statement ' + label + ': ' + err.message);
    }
  }
  return out;
}

function main() {
  var args = parseArgs(process.argv.slice(2));
  var version = readVersion();
  var tag = 'v' + version;
  var input = readInput();

  if (!input.statements.length) {
    process.stderr.write(
      '[build-vex] vex/statements.json has no statements — skipping VEX emission for ' + tag + '.\n' +
      '[build-vex] Add CVE assessments to vex/statements.json when there are CVEs worth statementing.\n'
    );
    return 0;
  }

  var statements = buildStatements(input.statements, version);
  var dateIso = args.dateIso || new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

  var doc = b.vex.document({
    documentId:         'hermitstash-' + tag + '-vex',
    title:              'HermitStash ' + tag + ' — CSAF 2.1 VEX',
    publisher: {
      category:  'vendor',
      name:      'dotCooCoo',
      namespace: 'https://github.com/dotCooCoo/hermitstash',
    },
    trackingId:         'hermitstash@' + version,
    trackingVersion:    '1',
    currentReleaseDate: dateIso,
    initialReleaseDate: dateIso,
    statements:         statements,
    tlp:                input.tlp || 'CLEAR',
  });

  fs.mkdirSync(args.outDir, { recursive: true });
  var outPath = path.join(args.outDir, 'hermitstash-' + tag + '.vex.json');
  fs.writeFileSync(outPath, b.vex.serialize(doc) + '\n', { mode: 0o644 });
  process.stderr.write(
    '[build-vex] Wrote ' + path.relative(REPO_ROOT, outPath) + ' ' +
    '(' + statements.length + ' statement' + (statements.length === 1 ? '' : 's') + ').\n'
  );
  return 0;
}

if (require.main === module) {
  try {
    process.exit(main());
  } catch (err) {
    process.stderr.write('[build-vex] ' + err.message + '\n');
    process.exit(1);
  }
}

module.exports = { main, buildStatements, expandProductScope };
