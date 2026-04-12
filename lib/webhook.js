/**
 * Webhook dispatcher — fires HTTP POST to registered webhook URLs.
 */
var https = require("https");
var { hmacSha3 } = require("./crypto");
var { agent: pqcAgent } = require("./pqc-agent");
var { webhooks } = require("./db");
var { isPrivateHost, isPrivateIp, validateOutboundUrl } = require("../app/security/ssrf-policy");

function fire(eventName, payload) {
  var hooks = webhooks.find({ active: "true" });
  for (var i = 0; i < hooks.length; i++) {
    var hook = hooks[i];
    var hookEvents = hook.events || "*";
    var events = hookEvents.split(",").map(function(e) { return e.trim(); });
    if (events[0] !== "*" && events.indexOf(eventName) === -1) continue;

    // SSRF protection — validate scheme, credentials, resolve DNS, check resolved IPs
    var check = validateOutboundUrl(hook.url);
    if (!check.valid) continue;
    var u = check.url;

    (function (h, u) {
      isPrivateHost(u.hostname).then(function (result) {
        if (result && result.blocked) return;

        var body = JSON.stringify({ event: eventName, data: payload, timestamp: new Date().toISOString() });
        var signature = h.secret ? hmacSha3(h.secret, body) : "";
        try {
          var req = https.request(h.url, { method: "POST", agent: pqcAgent, headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body), "X-Webhook-Signature": signature }, timeout: 5000 }, function() {});
          req.on("error", function() {});
          req.write(body);
          req.end();
          webhooks.update({ _id: h._id }, { $set: { lastTriggered: new Date().toISOString() } });
        } catch(_e) {}
      });
    })(hook, u);
  }
}

module.exports = { fire: fire };
