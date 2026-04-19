var https = require("https");
var { URL } = require("url");
var config = require("./config");
var { agent: pqcAgent } = require("./pqc-agent");

var { generateBytes } = require("./crypto");

var GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
var GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
var GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo";

function getCallbackUrl() {
  // Use manual override if set, then canonical origin
  if (config.google.callbackURL) return config.google.callbackURL;
  var origin = config.rpOrigin || "http://localhost:" + (config.port || 3000);
  return origin + "/auth/google/callback";
}

function getAuthUrl(state, req) {
  var params = new URLSearchParams({
    client_id: config.google.clientID,
    redirect_uri: getCallbackUrl(req),
    response_type: "code",
    scope: "openid email profile",
    access_type: "offline",
    prompt: "select_account",
    state: state,
  });
  return `${GOOGLE_AUTH_URL}?${params}`;
}

function generateState() {
  return generateBytes(32).toString("base64url");
}

function httpsPost(url, body) {
  return new Promise((resolve, reject) => {
    var parsed = new URL(url);
    var postData = typeof body === "string" ? body : new URLSearchParams(body).toString();
    var options = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: "POST",
      agent: pqcAgent,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(postData),
      },
    };
    var req = https.request(options, (res) => {
      var data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve(data); }
      });
    });
    req.on("error", reject);
    req.write(postData);
    req.end();
  });
}

function httpsGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    var parsed = new URL(url);
    var options = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: "GET",
      agent: pqcAgent,
      headers,
    };
    var req = https.request(options, (res) => {
      var data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve(data); }
      });
    });
    req.on("error", reject);
    req.end();
  });
}

async function exchangeCode(code, req) {
  var tokenData = await httpsPost(GOOGLE_TOKEN_URL, {
    code,
    client_id: config.google.clientID,
    client_secret: config.google.clientSecret,
    redirect_uri: getCallbackUrl(req),
    grant_type: "authorization_code",
  });

  if (!tokenData.access_token) {
    throw new Error("Failed to exchange code: " + (tokenData.error_description || tokenData.error || "unknown error"));
  }

  var userInfo = await httpsGet(GOOGLE_USERINFO_URL, {
    Authorization: `Bearer ${tokenData.access_token}`,
  });

  // Reject unverified emails — prevents account hijacking via unverified Google accounts
  if (userInfo.email_verified === false) {
    throw new Error("Google email not verified");
  }

  return {
    googleId: userInfo.sub || userInfo.id,
    email: (userInfo.email || "").toLowerCase(),
    displayName: userInfo.name || userInfo.email,
    avatar: userInfo.picture || "",
  };
}

module.exports = { getAuthUrl, exchangeCode, generateState, getCallbackUrl };
