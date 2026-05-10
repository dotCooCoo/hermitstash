var clientIp = require("../lib/client-ip");
var { blockedIps } = require("../lib/db");

module.exports = function ipCheck(req, res, next) {
  var ip = clientIp.getIp(req);
  if (ip && blockedIps.findOne({ ip: ip })) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    return res.end("Access denied");
  }
  next();
};
