/**
 * GitHub badge data — stargazer count + latest release tag, cached for 1h.
 *
 * Powers the navbar maintainer pills (mbadges.html). On first read after
 * cache expiry, kicks off a background refresh and returns the stale cache
 * synchronously so template render never blocks on network. If the upstream
 * fetch fails (offline, rate-limited, ENOTFOUND, etc.), the previous value
 * is preserved — the navbar gracefully degrades to its last known state
 * rather than erasing badge data.
 *
 * No outbound calls until the first request arrives. Operators running
 * air-gapped never trigger network I/O; the badges fall back to icon-only
 * after the initial fetch attempt fails.
 */

var C = require("./constants");
var logger = require("../app/shared/logger");

var REPO_OWNER = "dotCooCoo";
var REPO_NAME  = "hermitstash";
var REFRESH_MS = C.TIME.ONE_HOUR;
var FETCH_TIMEOUT_MS = 5000;

// Initial state. `current` may be `null` until the first fetch lands; the
// template handles missing values by rendering shield-only fallbacks.
var state = {
  stars:         null,
  latestVersion: null,
  fetchedAt:     0,
  refreshing:    false,
};

function isStale() {
  return Date.now() - state.fetchedAt > REFRESH_MS;
}

async function fetchJson(path) {
  var url = "https://api.github.com" + path;
  var ctrl = new AbortController();
  var timer = setTimeout(function () { ctrl.abort(); }, FETCH_TIMEOUT_MS);
  try {
    var headers = {
      "User-Agent": "hermitstash/" + C.version,
      "Accept": "application/vnd.github+json",
    };
    if (process.env.GITHUB_TOKEN) headers.Authorization = "Bearer " + process.env.GITHUB_TOKEN;
    var res = await fetch(url, { headers: headers, signal: ctrl.signal });
    if (!res.ok) throw new Error("github api " + path + " → HTTP " + res.status);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

async function refresh() {
  if (state.refreshing) return;
  state.refreshing = true;
  try {
    var [repo, release] = await Promise.all([
      fetchJson("/repos/" + REPO_OWNER + "/" + REPO_NAME).catch(function () { return null; }),
      fetchJson("/repos/" + REPO_OWNER + "/" + REPO_NAME + "/releases/latest").catch(function () { return null; }),
    ]);
    if (repo && typeof repo.stargazers_count === "number") state.stars = repo.stargazers_count;
    if (release && typeof release.tag_name === "string") {
      state.latestVersion = String(release.tag_name).replace(/^v/, "");
    }
    state.fetchedAt = Date.now();
  } catch (err) {
    logger.warn("github badge refresh failed", { error: err.message });
  } finally {
    state.refreshing = false;
  }
}

/**
 * Synchronous read for template render. Returns the latest cached snapshot;
 * triggers a background refresh if stale (does NOT await it).
 */
function read() {
  if (isStale()) refresh();
  return {
    stars:         state.stars,
    latestVersion: state.latestVersion,
    behindLatest:  !!(state.latestVersion && state.latestVersion !== C.version),
    repoUrl:       "https://github.com/" + REPO_OWNER + "/" + REPO_NAME,
    releaseUrl:    "https://github.com/" + REPO_OWNER + "/" + REPO_NAME + "/releases/tag/v" + C.version,
    latestUrl:     "https://github.com/" + REPO_OWNER + "/" + REPO_NAME + "/releases/latest",
  };
}

module.exports = { read: read, _refreshForTest: refresh, _resetForTest: function () { state = { stars: null, latestVersion: null, fetchedAt: 0, refreshing: false }; } };
