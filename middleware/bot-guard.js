/**
 * Bot guard — thin wrapper around b.middleware.botGuard.
 *
 * The framework primitive does the browser-fingerprint check (accept-language,
 * sec-fetch-mode, plus a regex against known automation-library UAs:
 * curl, wget, python-requests, axios, Go-http-client, node-fetch, java,
 * libwww-perl, Ruby, Apache-HttpClient). skipPaths covers paths where a
 * non-browser caller is expected: sync clients (mTLS Bearer), public upload
 * endpoints, OAuth callbacks, framework-defined .well-known paths, health
 * probes, and PWA static files.
 *
 * onlyForHtml causes the fingerprint check to skip /api/* by URL prefix.
 * HermitStash doesn't use /api/* paths, so only the explicit skip list
 * exempts authenticated endpoints (admin, sync, files, vault, etc.) —
 * these are Bearer-authed so they don't need the browser fingerprint.
 */
var b = require("../lib/vendor/blamejs");

// The framework's onlyForHtml=true skips the fingerprint check for /api/*
// paths AND for non-document requests (sec-fetch-dest != document). HS doesn't
// use the /api/* prefix, so the only paths exempted are the ones explicitly
// listed below — operator-facing maintenance/probe endpoints that legitimate
// non-browser callers hit, plus the public upload + sync API endpoints whose
// own middleware (mTLS + Bearer + rate-limit) handles non-browser auth.
//
// Routes NOT in this list still get the bot-guard treatment for page-nav
// (sec-fetch-dest=document) requests; in-page XHR/fetch already passes through
// because the framework skips the fingerprint when sec-fetch-dest !== document.
module.exports = b.middleware.botGuard({
  mode: "block",
  onlyForHtml: true,
  problemDetails: true, // emit the 403 as RFC 9457 application/problem+json, not a text/plain "Forbidden"
  skipPaths: [
    "/health",          // health probes
    "/sitemap.xml",     // crawlers
    "/manifest.json",   // PWA manifest
    "/robots.txt",      // crawlers
    "/sync/",           // sync clients (mTLS + Bearer auth — fingerprinting adds nothing)
    "/drop/",           // public upload endpoints (init/file/chunk/finalize)
    "/stash/",          // stash upload portal POST handlers (Bearer or session)
    "/.well-known/",    // RFC-defined paths (blamejs-pubkey, apple-app-site-assn)
    "/auth/google",     // OAuth callback (no browser session yet)
    "/files/",          // sync client file download (Bearer + mTLS)
    "/admin/",          // admin APIs (Bearer + admin scope — auth is the gate, not fingerprint)
    "/teams/",          // teams API (Bearer + scope)
    "/vault/",          // vault APIs (Bearer + session)
    "/users/",          // user-management APIs (Bearer + admin or session)
    "/passkey/",        // WebAuthn endpoints (session)
  ],
});
