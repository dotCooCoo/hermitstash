const fs = require("fs");
const path = require("path");
const { escHtml } = require("./sanitize");

const viewsDir = path.join(__dirname, "..", "views");
const cache = {};

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

  var filePath = path.join(viewsDir, viewName + ".html");
  if (!fs.existsSync(filePath)) throw new Error("View not found: " + viewName);

  var template = fs.readFileSync(filePath, "utf8");

  // Process partials
  template = template.replace(/\{\{>\s*(\w+)\s*\}\}/g, function (_, name) {
    var partialPath = path.join(viewsDir, "partials", name + ".html");
    if (fs.existsSync(partialPath)) return fs.readFileSync(partialPath, "utf8");
    return "";
  });

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
  var fn = new Function("__data", "__esc", "__formatSize", // eslint-disable-line no-new-func
    "with(__data) {\n" + body + "\n}"
  );
  cache[viewName] = fn;
  return fn;
}

function render(viewName, data) {
  try {
    var fn = compile(viewName);
    return fn(data || {}, escHtml, formatSize);
  } catch (err) {
    console.error("Template error in", viewName, ":", err.message);
    return "<h1>Template Error</h1><pre>" + escHtml(err.message) + "</pre>";
  }
}

function sendHtml(res, viewName, data, statusCode) {
  var html = render(viewName, data);
  res.writeHead(statusCode || 200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}

module.exports = { render, sendHtml, formatSize };
