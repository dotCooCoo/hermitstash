/**
 * Code layer — developer-set values that the admin UI does not touch.
 * Paths, versions, theme, and animation values live here.
 *
 * User-facing text (siteName, dropTitle, etc.) lives in config.js
 * and is changeable via the admin settings UI.
 */

var fs = require("fs");
var path = require("path");
var { sha3Hash } = require("./crypto");

/**
 * Compute a full SHA3-512 content hash for cache-busting.
 * Falls back to a timestamp if the file is missing (dev/build scenarios).
 */
function fileHash(relativePath) {
  try {
    var fullPath = path.join(__dirname, "..", "public", relativePath);
    var content = fs.readFileSync(fullPath);
    return sha3Hash(content);
  } catch (_e) {
    return Date.now().toString(36);
  }
}

var cssHash = fileHash("css/style.css");
var jsHash = fileHash("js/animations.js");
var apiJsHash = fileHash("js/api.js");
var vaultPqHash = fileHash("js/vault-pq.js");
var helpersHash = fileHash("js/helpers.js");
var webauthnHash = fileHash("js/webauthn-helpers.js");

// ---- Crypto prefixes (used by vault, field-crypto, session) ----
var VAULT_PREFIX = "vault:";

// ---- Hash salt prefixes (used by field-crypto, crypto.js) ----
var HASH_PREFIX = {
  EMAIL: "hs-email:",
  SHARE_ID: "hs-share:",
  IP: "hs-ip:",
  BLOCKED_IP: "hs-blockedip:",
  SLUG: "hs-slug:",
  ACCESS_CODE: "hs-access-code:",
};

// ---- Time constants (ms) ----
var TIME = {
  FIVE_MIN:    300000,
  TEN_MIN:     600000,
  THIRTY_MIN:  1800000,
  ONE_HOUR:    3600000,
  ONE_DAY:     86400000,
};

// ---- Encryption format markers ----
var FORMAT = {
  XCHACHA20: 0x02,  // version byte for XChaCha20-Poly1305 (storage/db)
};

module.exports = {
  version: "1.2.6",
  cssVersion: cssHash,
  jsVersion: jsHash,
  apiJsVersion: apiJsHash,
  vaultPqVersion: vaultPqHash,
  helpersVersion: helpersHash,
  webauthnVersion: webauthnHash,

  // Asset paths — change here to update everywhere
  paths: {
    logo: "/img/logos/white.svg",
    logoDark: "/img/logos/black.svg",
    logoColor: "/img/logos/purple.svg",
    favicon16: "/img/icons/favicon-16x16.png",
    favicon32: "/img/icons/favicon-32x32.png",
    appleTouchIcon: "/img/icons/apple-touch-icon.png",
    icon192: "/img/icons/icon-192.png",
    icon512: "/img/icons/icon-512.png",
    ogImage: "/img/og-image.png",
    manifest: "/manifest.json",
    css: "/css/style.css",
    js: "/js/animations.js",
  },

  // Theme — visual constants not editable by admin
  theme: {
    color: "#8B5CF6",
    bgColor: "#0f0f0f",
  },

  // Crypto / prefixes
  VAULT_PREFIX: VAULT_PREFIX,
  HASH_PREFIX: HASH_PREFIX,
  TIME: TIME,
  FORMAT: FORMAT,

  // Animation — timing, easing, thresholds
  animation: {
    scrollThreshold: 0.12,
    scrollMargin: "0px 0px -60px 0px",
    fadeInDuration: "0.8s",
    fadeInEasing: "cubic-bezier(0.34, 1.56, 0.64, 1)",
    staggerDelay: 0.1,
    counterDuration: 1500,
    parallaxSpeed: 0.3,
    rotatePerspective: "1000px",
  },
};
