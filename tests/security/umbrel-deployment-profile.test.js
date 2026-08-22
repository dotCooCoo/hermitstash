// The Umbrel deployment profile, asserted as a whole.
//
// Every defect this app has shipped to Umbrel had the same shape: a condition
// that only holds there — plain HTTP, reached through an app proxy on a
// container network, with no domain of its own — and a suite that tested each
// piece under its own convenient configuration. The pieces passed. The
// deployment did not.
//
// So the fixture here is the environment the published compose file sets, and
// every assertion runs under it at once. A behaviour that only breaks when
// TRUST_PROXY names a container network AND the request arrives over plain HTTP
// AND the origin is an http one is exactly the behaviour that reaches an
// operator otherwise.
//
// The last test compares the fixture against the compose file in the app-store
// fork, when that fork is checked out beside this repo. It is the drift guard:
// these assertions are only worth anything while the profile they encode is the
// profile that ships.

require("../helpers/isolate-db");
const { describe, it } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

// ---- the profile ---------------------------------------------------------
//
// Mirrors hermitstash/docker-compose.yml in getumbrel/umbrel-apps. DEVICE_NAME
// stands in for umbrel's ${DEVICE_DOMAIN_NAME}, which is a .local name.

const UMBREL = {
  TZ: "Etc/UTC",
  TRUST_PROXY: "10.21.0.0/16",          // umbrel_main_network — where app_proxy connects from
  RP_ORIGIN: "http://umbrel.local:3081",
  EMAIL_VERIFICATION: "false",
  UMASK: "022",
};

// The address app_proxy actually connects from — inside the declared network.
const APP_PROXY_PEER = "10.21.0.3";
// A peer outside it, standing for anything that is not the app proxy.
const OUTSIDE_PEER = "203.0.113.9";

process.env.TZ = UMBREL.TZ;
process.env.TRUST_PROXY = UMBREL.TRUST_PROXY;
process.env.RP_ORIGIN = UMBREL.RP_ORIGIN;

// The stock listing sets no additional origins, and this file asserts that the
// accepted set is exactly one. Saying so explicitly is the difference between a
// fixture and an assumption: inheriting the variable from the surrounding shell
// would fail the assertion on a machine whose code is perfectly correct.
delete process.env.ADDITIONAL_ORIGINS;

const clientIp = require("../../lib/client-ip");
const securityHeaders = require("../../middleware/security-headers");
const originPolicy = require("../../app/security/origin-policy");

// A request as it arrives from app_proxy: plain HTTP, forwarded headers set.
function proxiedReq(over) {
  over = over || {};
  const headers = Object.assign({
    "x-forwarded-for": over.clientAddr || "192.0.2.50",
    "x-forwarded-proto": "http",
    host: "umbrel.local:3081",
  }, over.headers || {});
  return {
    headers: headers,
    method: over.method || "GET",
    pathname: over.pathname || "/",
    socket: { encrypted: false, remoteAddress: over.peer || APP_PROXY_PEER },
  };
}

function headersFrom(req) {
  const out = {};
  const res = {
    statusCode: 200,
    setHeader: function (k, v) { out[k] = v; },
    getHeader: function (k) { return out[k]; },
    removeHeader: function (k) { delete out[k]; },
    writeHead: function () { return res; },
    end: function () {},
  };
  securityHeaders(req, res, function () {});
  return out;
}

describe("Umbrel profile — the proxy is trusted, so a client is a client", function () {

  it("accepts the container network as a trusted proxy", function () {
    // The listing shipped TRUST_PROXY="true" once. The setting takes addresses,
    // so "true" was discarded at boot and every request was attributed to
    // app_proxy: one rate-limit bucket for the whole device, the proxy in the
    // audit log, and the admin fence matched against the proxy.
    const parsed = clientIp.parseCidrList(UMBREL.TRUST_PROXY);
    assert.deepStrictEqual(parsed.invalid, [], "the profile's CIDR must be usable");
    assert.strictEqual(parsed.valid.length, 1);
  });

  it("refuses the value that broke it, rather than half-accepting it", function () {
    const parsed = clientIp.parseCidrList("true");
    assert.strictEqual(parsed.valid.length, 0);
    assert.strictEqual(parsed.invalid.length, 1);
    assert.strictEqual(parsed.invalid[0].entry, "true");
  });

  it("resolves the caller behind app_proxy, not app_proxy", function () {
    const ip = clientIp.getIp(proxiedReq({ clientAddr: "192.0.2.50" }));
    assert.strictEqual(ip, "192.0.2.50");
  });

  it("still refuses a forwarded address from a peer outside the network", function () {
    // Otherwise anything that can reach the port can forge its own address.
    const ip = clientIp.getIp(proxiedReq({ clientAddr: "192.0.2.50", peer: OUTSIDE_PEER }));
    assert.strictEqual(ip, OUTSIDE_PEER);
  });
});

describe("Umbrel profile — plain HTTP is the transport, and nothing may assume otherwise", function () {

  it("omits Secure from the session cookie", function () {
    // A browser discards a Secure cookie that arrives over plain HTTP. Setting
    // it means the session cookie never lands — and, on the logout path, that
    // the expiry never lands either, so signing out cannot clear the cookie.
    assert.strictEqual(clientIp.isSecureRequest(proxiedReq()), false);
  });

  it("withholds HSTS", function () {
    // RFC 6797 §8.1: a user agent ignores an HSTS header received over
    // insecure transport. Sending one here is inert at best.
    assert.strictEqual(headersFrom(proxiedReq())["Strict-Transport-Security"], undefined);
  });

  it("does not conclude HTTPS from the configured origin", function () {
    // The profile's RP_ORIGIN is http, but the bug this guards against read the
    // scheme the operator NAMED rather than the one the browser USED — so it
    // would fire on any deployment that set an https origin for passkeys.
    assert.match(UMBREL.RP_ORIGIN, /^http:/);
    assert.strictEqual(clientIp.isSecureRequest(proxiedReq()), false);
  });

  it("still sets the hardening headers that do not depend on TLS", function () {
    const h = headersFrom(proxiedReq());
    assert.ok(h["Content-Security-Policy"], "CSP");
    assert.strictEqual(h["X-Content-Type-Options"], "nosniff");
  });
});

describe("Umbrel profile — the device's own hostname is the origin", function () {

  it("treats the configured http origin as the canonical one", function () {
    // Reaching the app on a second name — a tailnet name, say — refused every
    // sign-in, upload and settings change while ordinary pages kept loading.
    // The device's own name has to be in the accepted set to begin with.
    assert.strictEqual(originPolicy.getOrigin(), UMBREL.RP_ORIGIN);
    assert.ok(originPolicy.acceptedOrigins().indexOf(UMBREL.RP_ORIGIN) !== -1,
      "the configured origin must be accepted for state-changing requests");
  });

  it("accepts nothing else while no additional origin is declared", function () {
    // The stock listing declares none, so the set is exactly one. A second
    // entry appearing here without ADDITIONAL_ORIGINS being set would mean
    // something widened CSRF acceptance for every Umbrel install.
    assert.deepStrictEqual(originPolicy.acceptedOrigins(), [UMBREL.RP_ORIGIN]);
  });
});

describe("Umbrel profile — a public page stays findable", function () {

  const b = require("../../lib/vendor/blamejs");
  const botGuard = require("../../middleware/bot-guard");

  // Drive the real guard and report whether the request got through.
  function passes(headers) {
    const req = b.testing.mockReq({ method: "GET", pathname: "/", headers: headers });
    const res = b.testing.mockRes();
    let nexted = false;
    botGuard(req, res, function () { nexted = true; });
    return nexted;
  }

  const CHROME = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

  it("serves a crawler that sends no Accept-Language", function () {
    // Every major search-engine crawler omits it — Google documents that
    // Googlebot does. Reading its absence as a bot signal answered 403 to all
    // of them, and to uptime monitors and link previewers, while a browser was
    // served normally — so the refusal was invisible from the device.
    assert.ok(passes({ "user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" }));
  });

  it("serves a browser that sends no Sec-Fetch-Mode", function () {
    // Those headers go only to a secure context, and this profile is plain
    // HTTP — so on Umbrel a real browser never sends them.
    assert.ok(passes({ "user-agent": CHROME, "accept-language": "en-GB,en;q=0.9" }));
  });

  it("still refuses a request carrying no User-Agent at all", function () {
    // The filter has to keep doing its job; this is what it is for.
    assert.strictEqual(passes({}), false);
  });
});

describe("Umbrel profile — the timezone the compose file sets", function () {

  it("resolves without being reported invalid", function () {
    // The container reported every zone invalid, including this one, because it
    // checked the value against zone files the base image does not carry. The
    // zone was applied correctly throughout; only the warning was wrong.
    const resolved = Intl.DateTimeFormat().resolvedOptions().timeZone;
    assert.ok(resolved, "a timezone must resolve");
    assert.doesNotThrow(function () {
      new Intl.DateTimeFormat("en-US", { timeZone: UMBREL.TZ }).format(new Date(0));
    }, "the profile's zone must be formattable");
  });
});

describe("Umbrel profile — the fixture still matches what ships", function () {

  it("agrees with the app-store compose file, when the fork is checked out", function () {
    // The assertions above are worth nothing if the listing drifts away from
    // them. This is the only place that notices.
    const composePath = path.join(
      __dirname, "..", "..", "..",
      "hermitstash-forks", "umbrel-apps", "hermitstash", "docker-compose.yml");
    if (!fs.existsSync(composePath)) return; // fork not checked out beside the repo

    const compose = fs.readFileSync(composePath, "utf8");
    const readEnv = function (key) {
      const m = compose.match(new RegExp("^\\s*" + key + ":\\s*\"?([^\"\\n]*)\"?\\s*$", "m"));
      return m ? m[1].trim() : null;
    };

    assert.strictEqual(readEnv("TRUST_PROXY"), UMBREL.TRUST_PROXY,
      "TRUST_PROXY drifted between the listing and this fixture");
    assert.strictEqual(readEnv("TZ"), UMBREL.TZ,
      "TZ drifted between the listing and this fixture");
    assert.strictEqual(readEnv("EMAIL_VERIFICATION"), UMBREL.EMAIL_VERIFICATION,
      "EMAIL_VERIFICATION drifted between the listing and this fixture");

    // RP_ORIGIN carries umbrel's own template variable, so only its shape is
    // comparable: it must stay plain HTTP on the published port.
    const rp = readEnv("RP_ORIGIN");
    assert.ok(rp && rp.indexOf("http://") === 0,
      "RP_ORIGIN must stay plain HTTP — the whole profile above assumes it");
    assert.ok(rp.indexOf(":3081") !== -1,
      "RP_ORIGIN must name the port the listing publishes");
  });
});
