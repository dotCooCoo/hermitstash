var config = require("../lib/config");
var C = require("../lib/constants");
var { sendHtml } = require("../lib/template");
var { getOrigin } = require("../app/security/origin-policy");

/**
 * Renders a view with brand + assets + site state auto-injected.
 */
function send(res, view, data, status) {
  var merged = Object.assign({}, data, { apiKey: res._apiKey || "", csrfToken: (res.req && res.req.csrfToken) || "" }, {
    brand: {
      siteName: config.siteName,
      logo: config.customLogo || C.paths.logo,
      logoDark: config.customLogo || C.paths.logoDark,
      logoColor: config.customLogo || C.paths.logoColor,
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
    },
  });
  sendHtml(res, view, merged, status);
}

function host() {
  return getOrigin();
}

module.exports = { send, host };
