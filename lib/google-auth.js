const https = require("https");
const { URL } = require("url");
const config = require("./config");
const { agent: pqcAgent } = require("./pqc-agent");

const { generateBytes } = require("./crypto");

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo";

function getCallbackUrl() {
  // Use manual override if set, then canonical origin
  if (config.google.callbackURL) return config.google.callbackURL;
  var origin = config.rpOrigin || "http://localhost:" + (config.port || 3000);
  return origin + "/auth/google/callback";
}

function getAuthUrl(state, req) {
  const params = new URLSearchParams({
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
    const parsed = new URL(url);
    const postData = typeof body === "string" ? body : new URLSearchParams(body).toString();
    const options = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: "POST",
      agent: pqcAgent,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(postData),
      },
    };
    const req = https.request(options, (res) => {
      let data = "";
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
    const parsed = new URL(url);
    const options = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: "GET",
      agent: pqcAgent,
      headers,
    };
    const req = https.request(options, (res) => {
      let data = "";
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
  const tokenData = await httpsPost(GOOGLE_TOKEN_URL, {
    code,
    client_id: config.google.clientID,
    client_secret: config.google.clientSecret,
    redirect_uri: getCallbackUrl(req),
    grant_type: "authorization_code",
  });

  if (!tokenData.access_token) {
    throw new Error("Failed to exchange code: " + (tokenData.error_description || tokenData.error || "unknown error"));
  }

  const userInfo = await httpsGet(GOOGLE_USERINFO_URL, {
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
