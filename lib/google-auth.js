var config = require("./config");
var b = require("./vendor/blamejs");
var C = require("./constants");

var GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
var GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
var GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo";

function getCallbackUrl() {
  // Use manual override if set, then canonical origin
  if (config.google.callbackURL) return config.google.callbackURL;
  var origin = config.rpOrigin || "http://localhost:" + (config.port || 3000); // allow:raw-time-literal — TCP port fallback, not duration
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
  return b.crypto.generateBytes(C.BYTES.bytes(32)).toString("base64url");
}

function _parseJsonResponseOrText(res) {
  var data = res.body ? res.body.toString("utf8") : "";
  try { return b.safeJson.parse(data); }
  catch (_e) { return data; }
}

function httpsPost(url, body) {
  var postData = typeof body === "string" ? body : new URLSearchParams(body).toString();
  return b.httpClient.request({
    method:    "POST",
    url:       url,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body:      postData,
    timeoutMs: C.TIME.seconds(15),
  }).then(_parseJsonResponseOrText);
}

function httpsGet(url, headers) {
  return b.httpClient.request({
    method:    "GET",
    url:       url,
    headers:   headers || {},
    timeoutMs: C.TIME.seconds(15),
  }).then(_parseJsonResponseOrText);
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

  // Reject unverified emails — prevents account hijacking via unverified Google
  // accounts. Require POSITIVE verification: a missing / undefined / null
  // email_verified (a malformed or non-conformant userinfo response) must NOT
  // pass — only an explicit boolean true (or its string form) is accepted.
  if (userInfo.email_verified !== true && userInfo.email_verified !== "true") {
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
