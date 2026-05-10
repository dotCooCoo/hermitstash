"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = require("../../");

function _threw(fn) {
  try { fn(); return null; }
  catch (e) { return e; }
}

function run() {
  // ---- create() shape ----
  check("b.argParser exposed",          typeof b.argParser === "object");
  check("b.argParser.create function",  typeof b.argParser.create === "function");
  check("b.argParser.parseRaw function", typeof b.argParser.parseRaw === "function");

  // ---- Minimal create + parse ----
  var ap = b.argParser.create({
    programName: "demo",
    description: "demo tool",
    flags: [
      { name: "verbose", alias: "v", type: "boolean", description: "Verbose" },
    ],
    commands: [
      {
        name: "hello",
        description: "say hi",
        flags: [
          { name: "name", type: "string", required: true, description: "Greeting name" },
          { name: "loud", type: "boolean", default: false },
        ],
        handler: function () { return "ok"; },
      },
      {
        name: "build",
        flags: [
          { name: "out",  type: "string", default: "./dist" },
          { name: "tag",  type: "list" },
          { name: "size", type: "number", default: 10 },
        ],
      },
    ],
  });

  // ---- help() ----
  var helpText = ap.help();
  check("help() includes program name", helpText.indexOf("demo") !== -1);
  check("help() includes description",  helpText.indexOf("demo tool") !== -1);
  check("help() lists 'hello' command", helpText.indexOf("hello") !== -1);
  check("help() lists '--verbose' top-level flag", helpText.indexOf("--verbose") !== -1);
  check("help('hello') includes --name flag",
        ap.help("hello").indexOf("--name") !== -1);
  check("help('hello') marks required",
        ap.help("hello").indexOf("required") !== -1);
  check("help('build') shows default for --out",
        ap.help("build").indexOf("default") !== -1);

  var helpMissingCmd = _threw(function () { ap.help("nope"); });
  check("help('unknown') throws", !!helpMissingCmd && helpMissingCmd.isArgParserError);

  // ---- parse: command + required string ----
  var r1 = ap.parse(["hello", "--name", "alice"]);
  check("parse(hello --name alice): command",      r1.command === "hello");
  check("parse(hello --name alice): name=alice",   r1.flags.name === "alice");
  check("parse(hello --name alice): loud default", r1.flags.loud === false);
  check("parse(hello --name alice): handler attached",
        typeof r1.handler === "function");

  // ---- parse: --flag=value form ----
  var r2 = ap.parse(["hello", "--name=bob", "--loud"]);
  check("parse(--name=bob --loud): name=bob", r2.flags.name === "bob");
  check("parse(--name=bob --loud): loud=true", r2.flags.loud === true);

  // ---- parse: alias short flag ----
  var r3 = ap.parse(["-v", "hello", "--name", "x"]);
  check("parse(-v hello ...): verbose=true", r3.flags.verbose === true);

  // ---- parse: missing required throws ----
  var missingReq = _threw(function () { ap.parse(["hello"]); });
  check("missing required --name throws ArgParserError",
        !!missingReq && missingReq.isArgParserError &&
        /required/.test(missingReq.message));

  // ---- parse: unknown flag throws ----
  var unknownFlag = _threw(function () { ap.parse(["hello", "--name", "x", "--bogus"]); });
  check("unknown flag throws", !!unknownFlag && unknownFlag.isArgParserError &&
        /unknown flag/.test(unknownFlag.message));

  // ---- parse: unknown command throws ----
  var unknownCmd = _threw(function () { ap.parse(["nope"]); });
  check("unknown command throws", !!unknownCmd && unknownCmd.isArgParserError &&
        /unknown command/.test(unknownCmd.message));

  // ---- parse: type coercion ----
  var rNum = ap.parse(["build", "--size", "42"]);
  check("number type coerces",        rNum.flags.size === 42);
  check("number type default applied (build --tag x): default size=10",
        ap.parse(["build", "--tag", "a"]).flags.size === 10);

  var badNum = _threw(function () { ap.parse(["build", "--size", "notnum"]); });
  check("bad number value throws", !!badNum && badNum.isArgParserError);

  // ---- parse: list type accumulates repeated flags ----
  var rList = ap.parse(["build", "--tag", "a", "--tag", "b", "--tag", "c"]);
  check("list flag accumulates",
        Array.isArray(rList.flags.tag) && rList.flags.tag.length === 3 &&
        rList.flags.tag[0] === "a" && rList.flags.tag[2] === "c");

  // ---- parse: list comma form ----
  var rListCsv = ap.parse(["build", "--tag", "x,y"]);
  check("list flag comma-split",
        Array.isArray(rListCsv.flags.tag) && rListCsv.flags.tag.length === 2 &&
        rListCsv.flags.tag[1] === "y");

  // ---- parse: -- terminator -> positionals ----
  var rPos = ap.parse(["hello", "--name", "z", "--", "--not-a-flag", "x"]);
  check("after -- everything is positional",
        rPos.positionals.length === 2 &&
        rPos.positionals[0] === "--not-a-flag");

  // ---- parse: --help in argv ----
  var rHelp = ap.parse(["hello", "--help"]);
  check("--help requested",          rHelp.helpRequested === true);
  check("--help command-context msg", typeof rHelp.helpText === "string" &&
        rHelp.helpText.indexOf("hello") !== -1);

  var rHelpTop = ap.parse(["--help"]);
  check("top-level --help requested", rHelpTop.helpRequested === true);

  // ---- parse: 'help' as a command ----
  var rHelpCmd = ap.parse(["help", "hello"]);
  check("'help <cmd>' returns helpText for that command",
        rHelpCmd.helpRequested === true &&
        rHelpCmd.helpText.indexOf("hello") !== -1 &&
        rHelpCmd.helpText.indexOf("--name") !== -1);

  // ---- prototype-pollution defense (config-time) ----
  var protoFlagThrew = _threw(function () {
    b.argParser.create({ flags: [{ name: "__proto__", type: "string" }] });
  });
  check("__proto__ flag name forbidden at create",
        !!protoFlagThrew && protoFlagThrew.isArgParserError);

  var ctorFlagThrew = _threw(function () {
    b.argParser.create({ flags: [{ name: "constructor", type: "string" }] });
  });
  check("constructor flag name forbidden at create",
        !!ctorFlagThrew && ctorFlagThrew.isArgParserError);

  // ---- prototype-pollution defense (parse-time argv) ----
  var protoArgvThrew = _threw(function () {
    ap.parse(["hello", "--__proto__", "x"]);
  });
  check("argv --__proto__ rejected at parse",
        !!protoArgvThrew && protoArgvThrew.isArgParserError);

  // parsed.flags must not inherit Object.prototype keys
  var rClean = ap.parse(["hello", "--name", "x"]);
  check("parsed.flags has null prototype",
        Object.getPrototypeOf(rClean.flags) === null);

  // ---- create-time validation: bad type ----
  var badTypeThrew = _threw(function () {
    b.argParser.create({ flags: [{ name: "x", type: "magic" }] });
  });
  check("bad flag type throws", !!badTypeThrew && badTypeThrew.isArgParserError);

  // ---- create-time validation: bad alias shape ----
  var badAliasThrew = _threw(function () {
    b.argParser.create({ flags: [{ name: "x", alias: "xx" }] });
  });
  check("multi-char alias throws", !!badAliasThrew && badAliasThrew.isArgParserError);

  // ---- create-time validation: duplicate flag ----
  var dupFlagThrew = _threw(function () {
    b.argParser.create({ flags: [{ name: "x" }, { name: "x" }] });
  });
  check("duplicate flag throws", !!dupFlagThrew && dupFlagThrew.isArgParserError);

  // ---- create-time validation: duplicate command ----
  var dupCmdThrew = _threw(function () {
    b.argParser.create({ commands: [{ name: "a" }, { name: "a" }] });
  });
  check("duplicate command throws", !!dupCmdThrew && dupCmdThrew.isArgParserError);

  // ---- create-time validation: bad command name shape ----
  var badCmdNameThrew = _threw(function () {
    b.argParser.create({ commands: [{ name: "1nope" }] });
  });
  check("bad command name throws", !!badCmdNameThrew && badCmdNameThrew.isArgParserError);

  // ---- argv validation ----
  var argvNotArrayThrew = _threw(function () { ap.parse("hello"); });
  check("argv-not-array throws", !!argvNotArrayThrew && argvNotArrayThrew.isArgParserError);

  var argvBadElemThrew = _threw(function () { ap.parse(["hello", 42]); });
  check("argv element non-string throws",
        !!argvBadElemThrew && argvBadElemThrew.isArgParserError);

  // ---- flag-only parser (no commands) ----
  var ap2 = b.argParser.create({
    programName: "noargs",
    flags: [
      { name: "out",  type: "string", default: "stdout" },
      { name: "json", type: "boolean" },
    ],
  });
  var rFlag = ap2.parse(["--json", "file.txt"]);
  check("flag-only parser: --json", rFlag.flags.json === true);
  check("flag-only parser: positional", rFlag.positionals.length === 1 &&
        rFlag.positionals[0] === "file.txt");
  check("flag-only parser: default applied", rFlag.flags.out === "stdout");

  // ---- parseRaw shape parity (cli.js delegate path) ----
  var raw = b.argParser.parseRaw(["a", "b", "--flag", "value"]);
  check("parseRaw: positional count", raw.pos.length === 2);
  check("parseRaw: --flag value",     raw.flags.flag === "value");

  var rawBool = b.argParser.parseRaw(["--only"]);
  check("parseRaw: bare flag is boolean", rawBool.flags.only === true);

  var rawEq = b.argParser.parseRaw(["--key=val"]);
  check("parseRaw: --key=val",        rawEq.flags.key === "val");

  var rawTerm = b.argParser.parseRaw(["--", "--ignored"]);
  check("parseRaw: -- terminator",    rawTerm.pos.length === 1 &&
        rawTerm.pos[0] === "--ignored");

  var rawShort = b.argParser.parseRaw(["-v"]);
  check("parseRaw: -v shortcut",      rawShort.flags.v === true);

  var rawProtoThrew = _threw(function () { b.argParser.parseRaw(["--__proto__", "x"]); });
  check("parseRaw: __proto__ rejected",
        !!rawProtoThrew && rawProtoThrew.isArgParserError);

  // parseRaw flags map has null prototype
  check("parseRaw: flags has null prototype",
        Object.getPrototypeOf(rawShort.flags) === null);

  // ---- exit:false help round-trip ----
  var rExit = ap.parse(["--help"], { exit: false });
  check("parse({exit:false}) returns helpText",
        rExit.helpRequested === true && typeof rExit.helpText === "string");

  // ---- value-missing error ----
  var missingVal = _threw(function () { ap.parse(["hello", "--name"]); });
  check("value-missing throws", !!missingVal && missingVal.isArgParserError &&
        /requires a value/.test(missingVal.message));

  // ---- boolean explicit forms ----
  var ap3 = b.argParser.create({ flags: [{ name: "yes", type: "boolean" }] });
  check("boolean --yes=true", ap3.parse(["--yes=true"]).flags.yes === true);
  check("boolean --yes=false", ap3.parse(["--yes=false"]).flags.yes === false);
  check("boolean --yes=no", ap3.parse(["--yes=no"]).flags.yes === false);
  var badBool = _threw(function () { ap3.parse(["--yes=maybe"]); });
  check("bad boolean throws", !!badBool && badBool.isArgParserError);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve(run()).then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
