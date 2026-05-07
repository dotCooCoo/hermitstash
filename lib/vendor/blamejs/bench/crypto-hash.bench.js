"use strict";
// bench crypto.sha3Hash on small + medium + large inputs.

var crypto = require("../lib/crypto");

var small  = Buffer.from("hello world");
var medium = Buffer.alloc(1024).fill(0x41);
var large  = Buffer.alloc(64 * 1024).fill(0x41);

module.exports = {
  name: "crypto-hash",
  benchmarks: {
    "sha3Hash 11 bytes":       function () { crypto.sha3Hash(small); },
    "sha3Hash 1 KB":           function () { crypto.sha3Hash(medium); },
    "sha3Hash 64 KB":          function () { crypto.sha3Hash(large); },
    "generateBytes 32":        function () { crypto.generateBytes(32); },
    "generateBytes 256":       function () { crypto.generateBytes(256); },
  },
};
