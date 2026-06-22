// codebase-patterns:allow-file raw-byte-literal — formatSize display tier thresholds (1024/1048576/1073741824) and partial-expansion bounded loop count
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var { escapeHtml: escHtml } = require("./vendor/blamejs").template;
// Script-context JSON serializer: escapes < > & and the U+2028 / U+2029 line
// separators so a server value embedded in an inline <script> can't break out
// of the script context (DOM-XSS). Exposed to templates as the
// {{{__scriptJson(value)}}} helper — the correct sink for inline-script data
// (the HTML escaper {{ }} is wrong for script context; raw {{{ }}} is unsafe).
var { stringifyForScript } = require("./vendor/blamejs").safeJson;

var viewsDir = nodePath.join(__dirname, "..", "views");
var cache = {};

function formatSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(0) + " KB";
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB";
  return (bytes / 1073741824).toFixed(2) + " GB";
}

/**
 * Compile a template into a reusable function.
 * Uses new Function() for template compilation — this is intentional and safe
 * since templates are server-side files, not user input.
 */
function compile(viewName) {
  if (cache[viewName]) return cache[viewName];

  var filePath = nodePath.join(viewsDir, viewName + ".html");
  if (!nodeFs.existsSync(filePath)) throw new Error("View not found: " + viewName);

  var template = nodeFs.readFileSync(filePath, "utf8");

  // Process partials (recursive — partials may include other partials).
  // Bounded to 16 passes to prevent infinite loops if a partial includes itself.
  var passes = 0;
  while (/\{\{>\s*\w+\s*\}\}/.test(template) && passes < 16) {
    template = template.replace(/\{\{>\s*(\w+)\s*\}\}/g, function (_, name) {
      var partialPath = nodePath.join(viewsDir, "partials", name + ".html");
      if (nodeFs.existsSync(partialPath)) return nodeFs.readFileSync(partialPath, "utf8");
      return "";
    });
    passes++;
  }

  // Build function body
  var body = "var __out = '';\n";
  var i = 0;
  var len = template.length;

  while (i < len) {
    var codeStart = template.indexOf("{%", i);
    var rawStart = template.indexOf("{{{", i);
    var exprStart = template.indexOf("{{", i);

    var nextTag = len;
    var tagType = null;

    if (codeStart !== -1 && codeStart < nextTag) { nextTag = codeStart; tagType = "code"; }
    if (rawStart !== -1 && rawStart < nextTag) { nextTag = rawStart; tagType = "raw"; }
    if (exprStart !== -1 && exprStart < nextTag) { nextTag = exprStart; tagType = "expr"; }
    if (rawStart !== -1 && rawStart === nextTag && tagType === "expr") { tagType = "raw"; }

    if (nextTag > i) {
      body += "__out += " + JSON.stringify(template.slice(i, nextTag)) + ";\n";
    }

    if (tagType === null) break;

    if (tagType === "raw") {
      var end = template.indexOf("}}}", nextTag + 3);
      if (end === -1) break;
      body += "__out += (" + template.slice(nextTag + 3, end).trim() + ");\n";
      i = end + 3;
    } else if (tagType === "expr") {
      var end2 = template.indexOf("}}", nextTag + 2);
      if (end2 === -1) break;
      body += "__out += __esc(" + template.slice(nextTag + 2, end2).trim() + ");\n";
      i = end2 + 2;
    } else if (tagType === "code") {
      var end3 = template.indexOf("%}", nextTag + 2);
      if (end3 === -1) break;
      body += template.slice(nextTag + 2, end3).trim() + "\n";
      i = end3 + 2;
    }
  }

  body += "return __out;\n";

  // Templates are trusted server-side files, not user input
  var fn = new Function("__data", "__esc", "__formatSize", "__scriptJson", // eslint-disable-line no-new-func
    "with(__data) {\n" + body + "\n}"
  );
  cache[viewName] = fn;
  return fn;
}

function render(viewName, data) {
  var fn = compile(viewName);
  return fn(data || {}, escHtml, formatSize, stringifyForScript);
}

function sendHtml(res, viewName, data, statusCode) {
  try {
    var html = render(viewName, data);
    res.writeHead(statusCode || 200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(html);
  } catch (err) {
    require("../app/shared/logger").error("Template error in " + viewName, { error: err.message });
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("Internal Server Error");
  }
}

module.exports = { render, sendHtml, formatSize };
