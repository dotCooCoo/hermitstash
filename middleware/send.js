var config = require("../lib/config");
var C = require("../lib/constants");
var { sendHtml } = require("../lib/template");
var { getOrigin } = require("../app/security/origin-policy");
var githubBadges = require("../lib/github-badges");

/**
 * Renders a view with brand + assets + site state auto-injected.
 */
function send(res, view, data, status) {
  var merged = Object.assign({}, data, { apiKey: res._apiKey || "", csrfToken: (res.req && res.req.csrfToken) || "", nonce: res._cspNonce || "" }, {
    brand: {
      siteName: config.siteName,
      logo: config.customLogo || C.paths.logo,
      logoDark: config.customLogo || C.paths.logoDark,
      logoColor: config.customLogo || C.paths.logoColor,
      // Surfaced for navbar version badge under showMaintainerSupport.
      // Templates render `v{{brand.version}}` linking to the matching
      // GitHub release page so visitors can see + audit which version
      // they're talking to.
      version:  C.version,
      // Cached GH stargazer count + latest release for the navbar
      // shield pills. Synchronous read; refresh is fired-and-forgotten
      // in the background and never blocks a render.
      github:   githubBadges.read(),
    },
    assets: {
      css: C.paths.css + "?v=" + C.cssVersion,
      js: C.paths.js + "?v=" + C.jsVersion,
      apiJs: "/js/api.js?v=" + C.apiJsVersion,
      vaultPq: "/js/vault-pq.js?v=" + C.vaultPqVersion,
      helpers: "/js/helpers.js?v=" + C.helpersVersion,
      webauthn: "/js/webauthn-helpers.js?v=" + C.webauthnVersion,
      favicon16: C.paths.favicon16,
      favicon32: C.paths.favicon32,
      appleTouchIcon: C.paths.appleTouchIcon,
      manifest: C.paths.manifest,
      ogImage: C.paths.ogImage,
      themeColor: C.theme.color,
    },
    site: {
      origin: getOrigin(),
      announcement: config.announcementBanner || "",
      maintenance: config.maintenanceMode || false,
      themeAccentColor: config.themeAccentColor || "",
      themeBgColor: config.themeBgColor || "",
      themeFont: config.themeFont || "",
      showMaintainerSupport: config.showMaintainerSupport || false,
      analyticsScript: config.analyticsScript || "",
    },
  });
  sendHtml(res, view, merged, status);
}

function host() {
  return getOrigin();
}

module.exports = { send, host };
