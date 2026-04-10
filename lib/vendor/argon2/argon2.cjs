// argon2 v0.44.0 — MIT License (c) Ranieri Althoff — https://github.com/ranisalt/node-argon2
var __getOwnPropNames = Object.getOwnPropertyNames;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};

// node_modules/@phc/format/index.js
var require_format = __commonJS({
  "node_modules/@phc/format/index.js"(exports2, module2) {
    var idRegex = /^[a-z0-9-]{1,32}$/;
    var nameRegex = /^[a-z0-9-]{1,32}$/;
    var valueRegex = /^[a-zA-Z0-9/+.-]+$/;
    var b64Regex = /^([a-zA-Z0-9/+.-]+|)$/;
    var decimalRegex = /^((-)?[1-9]\d*|0)$/;
    var versionRegex = /^v=(\d+)$/;
    function objToKeyVal(obj) {
      return objectKeys(obj).map((k) => [k, obj[k]].join("=")).join(",");
    }
    function keyValtoObj(str) {
      const obj = {};
      str.split(",").forEach((ps) => {
        const pss = ps.split("=");
        if (pss.length < 2) {
          throw new TypeError(`params must be in the format name=value`);
        }
        obj[pss.shift()] = pss.join("=");
      });
      return obj;
    }
    function objectKeys(object) {
      return Object.keys(object);
    }
    function objectValues(object) {
      if (typeof Object.values === "function") return Object.values(object);
      return objectKeys(object).map((k) => object[k]);
    }
    function serialize(opts) {
      const fields = [""];
      if (typeof opts !== "object" || opts === null) {
        throw new TypeError("opts must be an object");
      }
      if (typeof opts.id !== "string") {
        throw new TypeError("id must be a string");
      }
      if (!idRegex.test(opts.id)) {
        throw new TypeError(`id must satisfy ${idRegex}`);
      }
      fields.push(opts.id);
      if (typeof opts.version !== "undefined") {
        if (typeof opts.version !== "number" || opts.version < 0 || !Number.isInteger(opts.version)) {
          throw new TypeError("version must be a positive integer number");
        }
        fields.push(`v=${opts.version}`);
      }
      if (typeof opts.params !== "undefined") {
        if (typeof opts.params !== "object" || opts.params === null) {
          throw new TypeError("params must be an object");
        }
        const pk = objectKeys(opts.params);
        if (!pk.every((p) => nameRegex.test(p))) {
          throw new TypeError(`params names must satisfy ${nameRegex}`);
        }
        pk.forEach((k) => {
          if (typeof opts.params[k] === "number") {
            opts.params[k] = opts.params[k].toString();
          } else if (Buffer.isBuffer(opts.params[k])) {
            opts.params[k] = opts.params[k].toString("base64").split("=")[0];
          }
        });
        const pv = objectValues(opts.params);
        if (!pv.every((v) => typeof v === "string")) {
          throw new TypeError("params values must be strings");
        }
        if (!pv.every((v) => valueRegex.test(v))) {
          throw new TypeError(`params values must satisfy ${valueRegex}`);
        }
        const strpar = objToKeyVal(opts.params);
        fields.push(strpar);
      }
      if (typeof opts.salt !== "undefined") {
        if (!Buffer.isBuffer(opts.salt)) {
          throw new TypeError("salt must be a Buffer");
        }
        fields.push(opts.salt.toString("base64").split("=")[0]);
        if (typeof opts.hash !== "undefined") {
          if (!Buffer.isBuffer(opts.hash)) {
            throw new TypeError("hash must be a Buffer");
          }
          fields.push(opts.hash.toString("base64").split("=")[0]);
        }
      }
      const phcstr = fields.join("$");
      return phcstr;
    }
    function deserialize(phcstr) {
      if (typeof phcstr !== "string" || phcstr === "") {
        throw new TypeError("pchstr must be a non-empty string");
      }
      if (phcstr[0] !== "$") {
        throw new TypeError("pchstr must contain a $ as first char");
      }
      const fields = phcstr.split("$");
      fields.shift();
      let maxf = 5;
      if (!versionRegex.test(fields[1])) maxf--;
      if (fields.length > maxf) {
        throw new TypeError(
          `pchstr contains too many fileds: ${fields.length}/${maxf}`
        );
      }
      const id = fields.shift();
      if (!idRegex.test(id)) {
        throw new TypeError(`id must satisfy ${idRegex}`);
      }
      let version;
      if (versionRegex.test(fields[0])) {
        version = parseInt(fields.shift().match(versionRegex)[1], 10);
      }
      let hash;
      let salt;
      if (b64Regex.test(fields[fields.length - 1])) {
        if (fields.length > 1 && b64Regex.test(fields[fields.length - 2])) {
          hash = Buffer.from(fields.pop(), "base64");
          salt = Buffer.from(fields.pop(), "base64");
        } else {
          salt = Buffer.from(fields.pop(), "base64");
        }
      }
      let params;
      if (fields.length > 0) {
        const parstr = fields.pop();
        params = keyValtoObj(parstr);
        if (!objectKeys(params).every((p) => nameRegex.test(p))) {
          throw new TypeError(`params names must satisfy ${nameRegex}`);
        }
        const pv = objectValues(params);
        if (!pv.every((v) => valueRegex.test(v))) {
          throw new TypeError(`params values must satisfy ${valueRegex}`);
        }
        const pk = objectKeys(params);
        pk.forEach((k) => {
          params[k] = decimalRegex.test(params[k]) ? parseInt(params[k], 10) : params[k];
        });
      }
      if (fields.length > 0) {
        throw new TypeError(`pchstr contains unrecognized fileds: ${fields}`);
      }
      const phcobj = { id };
      if (version) phcobj.version = version;
      if (params) phcobj.params = params;
      if (salt) phcobj.salt = salt;
      if (hash) phcobj.hash = hash;
      return phcobj;
    }
    module2.exports = {
      serialize,
      deserialize
    };
  }
});

// node_modules/node-gyp-build/node-gyp-build.js
var require_node_gyp_build = __commonJS({
  "node_modules/node-gyp-build/node-gyp-build.js"(exports2, module2) {
    var fs = require("fs");
    var path = require("path");
    var os = require("os");
    var runtimeRequire = typeof __webpack_require__ === "function" ? __non_webpack_require__ : require;
    var vars = process.config && process.config.variables || {};
    var prebuildsOnly = !!process.env.PREBUILDS_ONLY;
    var abi = process.versions.modules;
    var runtime = isElectron() ? "electron" : isNwjs() ? "node-webkit" : "node";
    var arch = process.env.npm_config_arch || os.arch();
    var platform = process.env.npm_config_platform || os.platform();
    var libc = process.env.LIBC || (isAlpine(platform) ? "musl" : "glibc");
    var armv = process.env.ARM_VERSION || (arch === "arm64" ? "8" : vars.arm_version) || "";
    var uv = (process.versions.uv || "").split(".")[0];
    module2.exports = load;
    function load(dir) {
      return runtimeRequire(load.resolve(dir));
    }
    load.resolve = load.path = function(dir) {
      dir = path.resolve(dir || ".");
      try {
        var name = runtimeRequire(path.join(dir, "package.json")).name.toUpperCase().replace(/-/g, "_");
        if (process.env[name + "_PREBUILD"]) dir = process.env[name + "_PREBUILD"];
      } catch (err) {
      }
      if (!prebuildsOnly) {
        var release = getFirst(path.join(dir, "build/Release"), matchBuild);
        if (release) return release;
        var debug = getFirst(path.join(dir, "build/Debug"), matchBuild);
        if (debug) return debug;
      }
      var prebuild = resolve(dir);
      if (prebuild) return prebuild;
      var nearby = resolve(path.dirname(process.execPath));
      if (nearby) return nearby;
      var target = [
        "platform=" + platform,
        "arch=" + arch,
        "runtime=" + runtime,
        "abi=" + abi,
        "uv=" + uv,
        armv ? "armv=" + armv : "",
        "libc=" + libc,
        "node=" + process.versions.node,
        process.versions.electron ? "electron=" + process.versions.electron : "",
        typeof __webpack_require__ === "function" ? "webpack=true" : ""
        // eslint-disable-line
      ].filter(Boolean).join(" ");
      throw new Error("No native build was found for " + target + "\n    loaded from: " + dir + "\n");
      function resolve(dir2) {
        var tuples = readdirSync(path.join(dir2, "prebuilds")).map(parseTuple);
        var tuple = tuples.filter(matchTuple(platform, arch)).sort(compareTuples)[0];
        if (!tuple) return;
        var prebuilds = path.join(dir2, "prebuilds", tuple.name);
        var parsed = readdirSync(prebuilds).map(parseTags);
        var candidates = parsed.filter(matchTags(runtime, abi));
        var winner = candidates.sort(compareTags(runtime))[0];
        if (winner) return path.join(prebuilds, winner.file);
      }
    };
    function readdirSync(dir) {
      try {
        return fs.readdirSync(dir);
      } catch (err) {
        return [];
      }
    }
    function getFirst(dir, filter) {
      var files = readdirSync(dir).filter(filter);
      return files[0] && path.join(dir, files[0]);
    }
    function matchBuild(name) {
      return /\.node$/.test(name);
    }
    function parseTuple(name) {
      var arr = name.split("-");
      if (arr.length !== 2) return;
      var platform2 = arr[0];
      var architectures = arr[1].split("+");
      if (!platform2) return;
      if (!architectures.length) return;
      if (!architectures.every(Boolean)) return;
      return { name, platform: platform2, architectures };
    }
    function matchTuple(platform2, arch2) {
      return function(tuple) {
        if (tuple == null) return false;
        if (tuple.platform !== platform2) return false;
        return tuple.architectures.includes(arch2);
      };
    }
    function compareTuples(a, b) {
      return a.architectures.length - b.architectures.length;
    }
    function parseTags(file) {
      var arr = file.split(".");
      var extension = arr.pop();
      var tags = { file, specificity: 0 };
      if (extension !== "node") return;
      for (var i = 0; i < arr.length; i++) {
        var tag = arr[i];
        if (tag === "node" || tag === "electron" || tag === "node-webkit") {
          tags.runtime = tag;
        } else if (tag === "napi") {
          tags.napi = true;
        } else if (tag.slice(0, 3) === "abi") {
          tags.abi = tag.slice(3);
        } else if (tag.slice(0, 2) === "uv") {
          tags.uv = tag.slice(2);
        } else if (tag.slice(0, 4) === "armv") {
          tags.armv = tag.slice(4);
        } else if (tag === "glibc" || tag === "musl") {
          tags.libc = tag;
        } else {
          continue;
        }
        tags.specificity++;
      }
      return tags;
    }
    function matchTags(runtime2, abi2) {
      return function(tags) {
        if (tags == null) return false;
        if (tags.runtime && tags.runtime !== runtime2 && !runtimeAgnostic(tags)) return false;
        if (tags.abi && tags.abi !== abi2 && !tags.napi) return false;
        if (tags.uv && tags.uv !== uv) return false;
        if (tags.armv && tags.armv !== armv) return false;
        if (tags.libc && tags.libc !== libc) return false;
        return true;
      };
    }
    function runtimeAgnostic(tags) {
      return tags.runtime === "node" && tags.napi;
    }
    function compareTags(runtime2) {
      return function(a, b) {
        if (a.runtime !== b.runtime) {
          return a.runtime === runtime2 ? -1 : 1;
        } else if (a.abi !== b.abi) {
          return a.abi ? -1 : 1;
        } else if (a.specificity !== b.specificity) {
          return a.specificity > b.specificity ? -1 : 1;
        } else {
          return 0;
        }
      };
    }
    function isNwjs() {
      return !!(process.versions && process.versions.nw);
    }
    function isElectron() {
      if (process.versions && process.versions.electron) return true;
      if (process.env.ELECTRON_RUN_AS_NODE) return true;
      return typeof window !== "undefined" && window.process && window.process.type === "renderer";
    }
    function isAlpine(platform2) {
      return platform2 === "linux" && fs.existsSync("/etc/alpine-release");
    }
    load.parseTags = parseTags;
    load.matchTags = matchTags;
    load.compareTags = compareTags;
    load.parseTuple = parseTuple;
    load.matchTuple = matchTuple;
    load.compareTuples = compareTuples;
  }
});

// node_modules/node-gyp-build/index.js
var require_node_gyp_build2 = __commonJS({
  "node_modules/node-gyp-build/index.js"(exports2, module2) {
    var runtimeRequire = typeof __webpack_require__ === "function" ? __non_webpack_require__ : require;
    if (typeof runtimeRequire.addon === "function") {
      module2.exports = runtimeRequire.addon.bind(runtimeRequire);
    } else {
      module2.exports = require_node_gyp_build();
    }
  }
});

// node_modules/argon2/argon2.cjs
var require_argon2 = __commonJS({
  "node_modules/argon2/argon2.cjs"(exports2, module2) {
    var { randomBytes, timingSafeEqual } = require("node:crypto");
    var { promisify } = require("node:util");
    var { deserialize, serialize } = require_format();
    var gypBuild = require_node_gyp_build2();
    var { hash: bindingsHash } = gypBuild(__dirname);
    var generateSalt = promisify(randomBytes);
    var argon2d = 0;
    var argon2i = 1;
    var argon2id = 2;
    module2.exports.argon2d = argon2d;
    module2.exports.argon2i = argon2i;
    module2.exports.argon2id = argon2id;
    var types = Object.freeze({ argon2d, argon2i, argon2id });
    var names = Object.freeze({
      [types.argon2d]: "argon2d",
      [types.argon2i]: "argon2i",
      [types.argon2id]: "argon2id"
    });
    var defaults = {
      hashLength: 32,
      timeCost: 3,
      memoryCost: 1 << 16,
      parallelism: 4,
      type: argon2id,
      version: 19
    };
    async function hash(password, options) {
      let { raw, salt, ...rest } = { ...defaults, ...options };
      if (rest.hashLength > 2 ** 32 - 1) {
        throw new RangeError("Hash length is too large");
      }
      if (rest.memoryCost > 2 ** 32 - 1) {
        throw new RangeError("Memory cost is too large");
      }
      if (rest.timeCost > 2 ** 32 - 1) {
        throw new RangeError("Time cost is too large");
      }
      if (rest.parallelism > 2 ** 24 - 1) {
        throw new RangeError("Parallelism is too large");
      }
      salt = salt ?? await generateSalt(16);
      const {
        hashLength,
        secret = Buffer.alloc(0),
        type,
        version,
        memoryCost: m,
        timeCost: t,
        parallelism: p,
        associatedData: data = Buffer.alloc(0)
      } = rest;
      const hash2 = await bindingsHash({
        password: Buffer.from(password),
        salt,
        secret,
        data,
        hashLength,
        m,
        t,
        p,
        version,
        type
      });
      if (raw) {
        return hash2;
      }
      return serialize({
        id: names[type],
        version,
        params: { m, t, p, ...data.byteLength > 0 ? { data } : {} },
        salt,
        hash: hash2
      });
    }
    module2.exports.hash = hash;
    function needsRehash(digest, options = {}) {
      const { memoryCost, timeCost, parallelism, version } = {
        ...defaults,
        ...options
      };
      const {
        version: v,
        params: { m, t, p }
      } = deserialize(digest);
      return +v !== +version || +m !== +memoryCost || +t !== +timeCost || +p !== +parallelism;
    }
    module2.exports.needsRehash = needsRehash;
    async function verify(digest, password, options = {}) {
      const { id, ...rest } = deserialize(digest);
      if (!(id in types)) {
        return false;
      }
      const {
        version = 16,
        params: { m, t, p, data = "" },
        salt,
        hash: hash2
      } = rest;
      const { secret = Buffer.alloc(0) } = options;
      return timingSafeEqual(
        await bindingsHash({
          password: Buffer.from(password),
          salt,
          secret,
          data: Buffer.from(data, "base64"),
          hashLength: hash2.byteLength,
          m: +m,
          t: +t,
          p: +p,
          version: +version,
          type: types[id]
        }),
        hash2
      );
    }
    module2.exports.verify = verify;
  }
});

// _bundle-argon2.cjs
module.exports = require_argon2();
