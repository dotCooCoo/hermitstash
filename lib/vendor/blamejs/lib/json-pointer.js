"use strict";
/**
 * @module b.jsonPointer
 * @nav    Data
 * @title  JSON Pointer
 *
 * @intro
 *   Reference a single value within a JSON document by path (RFC 6901) —
 *   <code>/foo/0/bar</code> walks <code>doc.foo[0].bar</code>. A pointer
 *   is a sequence of <code>/</code>-prefixed reference tokens; the empty
 *   string points at the whole document. The two escapes
 *   (<code>~1</code> → <code>/</code>, <code>~0</code> → <code>~</code>)
 *   let a token contain a literal slash or tilde.
 *
 *   <code>get</code> returns the referenced value or throws when the path
 *   does not resolve; <code>parse</code> exposes the decoded reference
 *   tokens. It is the path language JSON Patch (<code>b.jsonPatch</code>)
 *   builds on.
 *
 * @card
 *   JSON Pointer (RFC 6901) — reference a value inside a JSON document by
 *   <code>/path/0/token</code>, with the <code>~1</code> / <code>~0</code>
 *   escapes. The path language behind JSON Patch.
 */

var { defineClass } = require("./framework-error");

var JsonPointerError = defineClass("JsonPointerError", { alwaysPermanent: true });

var ARRAY_INDEX_RE = /^(?:0|[1-9][0-9]*)$/;                  // no leading zeros (RFC 6901 §4)

/**
 * @primitive b.jsonPointer.parse
 * @signature b.jsonPointer.parse(pointer)
 * @since     0.12.58
 * @status    stable
 * @related   b.jsonPointer.get, b.jsonPatch.apply
 *
 * Decode an RFC 6901 JSON Pointer string into its array of reference
 * tokens, unescaping <code>~1</code> → <code>/</code> and <code>~0</code>
 * → <code>~</code>. The empty string yields an empty array (the whole
 * document); a non-empty pointer must begin with <code>/</code>.
 *
 * @example
 *   b.jsonPointer.parse("/a~1b/m~0n");
 *   // → ["a/b", "m~n"]
 */
function parse(pointer) {
  if (typeof pointer !== "string") throw new JsonPointerError("json-pointer/bad-pointer", "jsonPointer: pointer must be a string");
  if (pointer === "") return [];
  if (pointer.charAt(0) !== "/") throw new JsonPointerError("json-pointer/bad-pointer", "jsonPointer: a non-empty pointer must start with '/'");
  return pointer.split("/").slice(1).map(function (tok) {
    // RFC 6901 §3: the only valid `~` escapes are ~0 and ~1; a tilde
    // followed by anything else (or at end of token) is malformed.
    if (/~(?![01])/.test(tok)) throw new JsonPointerError("json-pointer/bad-pointer", "jsonPointer: invalid '~' escape (only ~0 and ~1 are allowed)");
    return tok.replace(/~1/g, "/").replace(/~0/g, "~");      // ~1 before ~0 (RFC 6901 §4)
  });
}

// Resolve a token against the current node; returns { found, value }.
function _step(node, token) {
  if (Array.isArray(node)) {
    if (!ARRAY_INDEX_RE.test(token)) return { found: false };   // allow:regex-no-length-cap — anchored linear index regex (no backtracking); tokens are short JSON Pointer segments
    var idx = Number(token);
    if (idx >= node.length) return { found: false };
    return { found: true, value: node[idx] };
  }
  if (node !== null && typeof node === "object") {
    if (!Object.prototype.hasOwnProperty.call(node, token)) return { found: false };
    return { found: true, value: node[token] };
  }
  return { found: false };
}

/**
 * @primitive b.jsonPointer.get
 * @signature b.jsonPointer.get(doc, pointer)
 * @since     0.12.58
 * @status    stable
 * @related   b.jsonPointer.parse, b.jsonPatch.apply
 *
 * Return the value an RFC 6901 pointer references within a JSON document,
 * walking object keys and array indices. Throws
 * <code>json-pointer/not-found</code> when a token does not resolve (a
 * missing key, an out-of-range or non-numeric array index, or descending
 * into a primitive). The whole document is returned for the empty
 * pointer.
 *
 * @example
 *   b.jsonPointer.get({ foo: ["a", "b"] }, "/foo/1");
 *   // → "b"
 */
function get(doc, pointer) {
  var tokens = parse(pointer);
  var cur = doc;
  for (var i = 0; i < tokens.length; i += 1) {
    var r = _step(cur, tokens[i]);
    if (!r.found) throw new JsonPointerError("json-pointer/not-found", "jsonPointer.get: pointer does not resolve at token '" + tokens[i] + "'");
    cur = r.value;
  }
  return cur;
}

module.exports = {
  parse:            parse,
  get:              get,
  ARRAY_INDEX_RE:   ARRAY_INDEX_RE,
  JsonPointerError: JsonPointerError,
};
