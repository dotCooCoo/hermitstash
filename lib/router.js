const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

// Pre-compile route patterns at registration time (not per-request)
function compilePattern(pattern) {
  var keys = [];
  var regexStr = pattern.replace(/:([^/]+)/g, function (_, key) { keys.push(key); return "([^/]+)"; }).replace(/\//g, "\\/");
  return { pattern: pattern, regex: new RegExp("^" + regexStr + "$"), keys: keys };
}

const MIME_TYPES = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "application/javascript",
  ".json": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
};

class Router {
  constructor() {
    this.routes = [];
    this.middleware = [];
  }

  use(fn) {
    this.middleware.push(fn);
  }

  get(pattern, ...handlers) {
    this.routes.push({ method: "GET", ...compilePattern(pattern), handlers });
  }

  post(pattern, ...handlers) {
    this.routes.push({ method: "POST", ...compilePattern(pattern), handlers });
  }

  _match(route, pathname) {
    const match = pathname.match(route.regex);
    if (!match) return null;
    const params = {};
    route.keys.forEach((key, i) => (params[key] = match[i + 1]));
    return params;
  }

  async handle(req, res) {
    const parsed = new URL(req.url, `http://${req.headers.host}`);
    req.pathname = parsed.pathname;
    req.query = Object.fromEntries(parsed.searchParams);

    // Run middleware
    for (const mw of this.middleware) {
      let next = false;
      try {
        await mw(req, res, () => (next = true));
      } catch (mwErr) {
        console.error("[MW ERROR]", mw.name || "anonymous", req.method, req.url, mwErr.message, mwErr.stack ? mwErr.stack.split("\n").slice(0, 3).join(" | ") : "");
        throw mwErr;
      }
      if (!next || res.writableEnded) return;
    }

    // Match route
    for (const route of this.routes) {
      if (route.method !== req.method) continue;
      const params = this._match(route, req.pathname);
      if (!params) continue;
      req.params = params;

      for (const handler of route.handlers) {
        if (res.writableEnded) return;
        // Support middleware-style handlers (req, res, next) in route chains
        if (handler.length >= 3) {
          let proceeded = false;
          await handler(req, res, () => (proceeded = true));
          if (!proceeded) return; // middleware didn't call next — stop chain
        } else {
          await handler(req, res);
        }
      }
      return;
    }

    // Not found
    if (this.notFoundHandler) {
      this.notFoundHandler(req, res);
    } else {
      res.writeHead(404, { "Content-Type": "text/html" });
      res.end("<h1>404 Not Found</h1>");
    }
  }

  getReservedSlugs() {
    var slugs = new Set();
    for (var i = 0; i < this.routes.length; i++) {
      var parts = this.routes[i].pattern.split("/").filter(Boolean);
      if (parts.length > 0 && !parts[0].startsWith(":")) {
        slugs.add(parts[0].toLowerCase());
      }
    }
    return slugs;
  }

  onNotFound(handler) {
    this.notFoundHandler = handler;
  }

  onError(handler) {
    this.errorHandler = handler;
  }

  listen(port, cb, tlsOptions, host) {
    var self = this;
    var requestHandler = (req, res) => {
      // Add helpers to res
      res.json = (data) => {
        res.writeHead(res.statusCode || 200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(data));
      };
      res.redirect = (url) => {
        // Allow relative paths and trusted external domains (OAuth providers)
        var safe = "/";
        if (typeof url === "string") {
          if (url.startsWith("/") && !url.startsWith("//")) safe = url;
          else try { var u = new URL(url); if (["accounts.google.com","oauth2.googleapis.com"].includes(u.hostname)) safe = url; } catch (_e) {}
        }
        res.writeHead(302, { Location: safe });
        res.end();
      };
      res.status = (code) => {
        res.statusCode = code;
        return res;
      };

      self.handle(req, res).catch((err) => {
        console.error("[ROUTE ERROR]", req.method, req.url, err.message, err.stack ? err.stack.split("\n").slice(0, 5).join(" | ") : "");
        if (self.errorHandler) {
          try { self.errorHandler(err, req, res); } catch (_) {
            if (!res.writableEnded) {
              res.writeHead(500, { "Content-Type": "text/plain" });
              res.end("Internal Server Error");
            }
          }
        } else {
          if (!res.writableEnded) {
            res.writeHead(500, { "Content-Type": "text/plain" });
            res.end("Internal Server Error");
          }
        }
      });
    };
    var server;
    if (tlsOptions) {
      server = require("node:https").createServer(tlsOptions, requestHandler);
    } else {
      server = http.createServer(requestHandler);
    }
    if (host) server.listen(port, host, cb);
    else server.listen(port, cb);
    server.timeout = 300000;
    return server;
  }
}

// Static file serving middleware
function serveStatic(dir) {
  const root = path.resolve(dir);
  return (req, res, next) => {
    if (req.method !== "GET") return next();
    const rel = req.pathname;
    // Reject null bytes
    if (rel.includes("\0")) return next();
    const filePath = path.resolve(path.join(root, rel));

    // Prevent directory traversal (resolve normalizes all .. and encoding)
    if (!filePath.startsWith(root)) return next();

    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) return next();

    const ext = path.extname(filePath).toLowerCase();
    const mime = MIME_TYPES[ext] || "application/octet-stream";

    const stat = fs.statSync(filePath);
    // Versioned assets (?v=hash) get long immutable cache; others get short cache
    var hasVersion = req.url && req.url.includes("?v=");
    var cacheControl = hasVersion ? "public, max-age=31536000, immutable" : "public, max-age=3600";
    res.writeHead(200, {
      "Content-Type": mime,
      "Content-Length": stat.size,
      "Cache-Control": cacheControl,
    });
    fs.createReadStream(filePath).pipe(res);
  };
}

module.exports = { Router, serveStatic };
