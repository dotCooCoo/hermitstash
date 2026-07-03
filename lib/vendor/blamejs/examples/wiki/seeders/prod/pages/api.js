// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Auto-generated API index. The body is built at seeder-load time by
// walking every other page's body for primitive headings via
// lib/symbol-index. Page seeders are loaded in order, so this file
// imports the rest of the seeder list (minus itself) before computing.
//
// The page renders: a one-line summary, an alphabetical primitive
// table grouped by namespace, and a JSON snapshot accessible at
// /dist/symbol-index.json (written by buildApp at boot).

var symbolIndex = require("../../../lib/symbol-index");

// Lazy-load every other seeder. require() the index module so we get
// the same array routes/seeders use; filter ourselves out so we don't
// recursively try to harvest our own (empty) signatures.
function _harvest() {
  var allPages = require("./_index");
  var others = allPages.filter(function (p) { return p && p.slug !== "api"; });
  return symbolIndex.build(others);
}

function _renderBody() {
  var manifest = _harvest();
  var groups = symbolIndex.groupByNamespace(manifest);
  var nsList = Object.keys(groups).sort();

  var lines = [
    '<h1>API index</h1>',
    '<p>Every operator-facing primitive documented in this wiki, alphabetical by namespace. Use the search box in the sidebar (or <kbd>/</kbd> + start typing) for fuzzy autocomplete.</p>',
    '<p class="muted">Auto-generated from <code>&lt;h2&gt;</code> / <code>&lt;h3&gt;</code> headings on every wiki page. ' + manifest.length + ' primitives across ' + nsList.length + ' namespaces.</p>',
    '<aside class="callout callout-tip">',
    '<p class="callout-title">JSON manifest</p>',
    '<p>The same data is served as JSON at <code><a href="/symbols.json">/symbols.json</a></code> for tooling that wants to consume the index programmatically.</p>',
    '</aside>',
  ];

  for (var i = 0; i < nsList.length; i++) {
    var ns = nsList[i];
    var entries = groups[ns];
    lines.push('<h2 id="ns-' + ns + '">b.' + ns + '</h2>');
    lines.push('<table>');
    lines.push('<thead><tr><th>Primitive</th><th>Documented in</th></tr></thead>');
    lines.push('<tbody>');
    for (var j = 0; j < entries.length; j++) {
      var e = entries[j];
      lines.push(
        '<tr>' +
        '<td><a href="/' + e.page + '#' + e.anchor + '"><code>' + e.sigBare + '</code></a></td>' +
        '<td><a href="/' + e.page + '">' + e.title + '</a></td>' +
        '</tr>'
      );
    }
    lines.push('</tbody>');
    lines.push('</table>');
  }
  return lines.join("\n");
}

// Compute body lazily — _index.js requires every page module; api.js
// is in that same require()-on-load chain. Resolving symbol harvest
// at module-load time would create a circular dependency. Instead, the
// migrations seeder calls the body function at seed time (post all
// modules loaded). Page consumers (route handler) read .body as a
// string directly from the DB column the migrations populate.
//
// To keep the contract identical to other pages — { slug, title, body:string } —
// we expose body as a getter that materializes on first access.
var _bodyCache = null;
module.exports = {
  slug:  "api",
  title: "API index",
  get body() {
    if (_bodyCache === null) _bodyCache = _renderBody();
    return _bodyCache;
  },
};
