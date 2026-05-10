"use strict";
/**
 * @module b.argParser
 * @nav    Production
 * @title  Arg Parser
 *
 * @intro
 *   Reusable command-line argument parser for tools sitting on top of
 *   the framework. Operators declare a parser declaratively (top-level
 *   flags + named commands + per-command flags) and call `.parse(argv)`
 *   to get a typed result, or `.help()` to render usage text.
 *
 *   Throws ArgParserError on invalid input (unknown flag, missing
 *   required, type-coercion failure, prototype-pollution attempt) so a
 *   bad CLI invocation fails at parse-time with a clear message instead
 *   of running a subcommand with garbage. `--` ends flag parsing;
 *   `--help` / `-h` is reserved and renders top-level or per-command
 *   usage. Flag names `__proto__` / `constructor` / `prototype` are
 *   refused as a prototype-pollution defense, even though parsed flags
 *   live in an Object.create(null) bag.
 *
 *   Type coercion: `string` (as-is), `number` (Number(), rejects NaN),
 *   `boolean` (presence + accepts "true"/"false"/"1"/"0"/"yes"/"no"),
 *   `list` (repeated flags or single comma-separated value). Defaults
 *   apply before required-checks, so a flag with both `required: true`
 *   and a `default` is always satisfied. Aliases are single ASCII
 *   letters (`-d ./app.db` ≡ `--db ./app.db`); multi-char aliases are
 *   flag names, not aliases.
 *
 *   `parseRaw(argv)` is the framework-internal minimal splitter used by
 *   `lib/cli.js` subcommand handlers — same prototype-pollution defense
 *   and `--` terminator semantics, but no command/flag schema.
 *
 * @card
 *   Reusable command-line argument parser for tools sitting on top of the framework.
 */

var { defineClass } = require("./framework-error");

var ArgParserError = defineClass("ArgParserError", { alwaysPermanent: true });

var SUPPORTED_TYPES = ["string", "number", "boolean", "list"];

// Names operators can never use for a flag. Prototype-pollution defense:
// even though the parser internally uses Object.create(null), downstream
// callers spreading parsed.flags into a normal object would otherwise
// overwrite the prototype.
var FORBIDDEN_NAMES = ["__proto__", "constructor", "prototype"];

function _isPlainNonEmpty(s) {
  return typeof s === "string" && s.length > 0;
}

function _validateFlagName(name) {
  if (!_isPlainNonEmpty(name)) {
    throw new ArgParserError("argParser/flag-name-invalid",
      "flag name must be a non-empty string");
  }
  if (FORBIDDEN_NAMES.indexOf(name) !== -1) {
    throw new ArgParserError("argParser/flag-name-forbidden",
      "flag name '" + name + "' is reserved");
  }
  // ASCII-only kebab-/snake-case identifier. Keeps every flag name safe
  // to embed in help text and prevents `--foo$bar=baz` style oddities.
  if (!/^[a-zA-Z][a-zA-Z0-9_-]*$/.test(name)) {
    throw new ArgParserError("argParser/flag-name-shape",
      "flag name '" + name + "' must match [a-zA-Z][a-zA-Z0-9_-]*");
  }
}

function _validateAlias(alias, ownerName) {
  if (alias === undefined || alias === null) return;
  if (typeof alias !== "string" || alias.length !== 1 || !/^[a-zA-Z]$/.test(alias)) {
    throw new ArgParserError("argParser/alias-shape",
      "flag '" + ownerName + "' alias must be a single letter [a-zA-Z]");
  }
}

function _validateFlagSpec(spec, ownerLabel) {
  if (!spec || typeof spec !== "object") {
    throw new ArgParserError("argParser/flag-spec-invalid",
      ownerLabel + ": flag spec must be an object");
  }
  _validateFlagName(spec.name);
  _validateAlias(spec.alias, spec.name);
  var type = spec.type || "string";
  if (SUPPORTED_TYPES.indexOf(type) === -1) {
    throw new ArgParserError("argParser/flag-type-unsupported",
      ownerLabel + ": flag '" + spec.name +
      "' type '" + type + "' must be one of " + SUPPORTED_TYPES.join(", "));
  }
  if (spec.description !== undefined && typeof spec.description !== "string") {
    throw new ArgParserError("argParser/flag-description-invalid",
      ownerLabel + ": flag '" + spec.name + "' description must be a string");
  }
}

function _coerceValue(spec, raw, label) {
  var type = spec.type || "string";
  if (type === "string") return String(raw);
  if (type === "number") {
    var n = Number(raw);
    if (!isFinite(n)) {
      throw new ArgParserError("argParser/value-not-number",
        label + " '" + spec.name + "' expected a number, got " + JSON.stringify(raw));
    }
    return n;
  }
  if (type === "boolean") {
    if (raw === true) return true;
    if (raw === false) return false;
    var s = String(raw).toLowerCase();
    if (s === "true" || s === "1" || s === "yes")  return true;
    if (s === "false" || s === "0" || s === "no")  return false;
    throw new ArgParserError("argParser/value-not-boolean",
      label + " '" + spec.name + "' expected boolean, got " + JSON.stringify(raw));
  }
  if (type === "list") {
    // Caller may pass a single comma-separated string; split here.
    var s2 = String(raw);
    return s2.indexOf(",") === -1 ? [s2] : s2.split(",");
  }
  // Unreachable: validated at create-time.
  throw new ArgParserError("argParser/type-unreachable",
    "unsupported flag type '" + type + "'");
}

function _buildFlagIndex(flagSpecs, ownerLabel) {
  var byName = Object.create(null);
  var byAlias = Object.create(null);
  for (var i = 0; i < flagSpecs.length; i++) {
    var spec = flagSpecs[i];
    _validateFlagSpec(spec, ownerLabel);
    if (byName[spec.name]) {
      throw new ArgParserError("argParser/flag-duplicate",
        ownerLabel + ": flag '" + spec.name + "' declared twice");
    }
    byName[spec.name] = spec;
    if (spec.alias) {
      if (byAlias[spec.alias]) {
        throw new ArgParserError("argParser/alias-duplicate",
          ownerLabel + ": alias '-" + spec.alias + "' declared twice");
      }
      byAlias[spec.alias] = spec;
    }
  }
  return { byName: byName, byAlias: byAlias, list: flagSpecs.slice() };
}

function _renderFlagsBlock(specs, indent) {
  if (!specs || specs.length === 0) return "";
  var pad = "";
  for (var k = 0; k < indent; k++) pad += " ";
  var lines = [];
  // Compute the column where descriptions align.
  var labels = specs.map(function (s) {
    var head = "--" + s.name;
    if (s.alias) head = "-" + s.alias + ", " + head;
    if (s.type && s.type !== "boolean") head += " <" + s.type + ">";
    return head;
  });
  var maxLabel = 0;
  labels.forEach(function (l) { if (l.length > maxLabel) maxLabel = l.length; });
  for (var i = 0; i < specs.length; i++) {
    var spec = specs[i];
    var label = labels[i];
    var trail = "";
    while (label.length + trail.length < maxLabel + 2) trail += " ";
    var desc = spec.description || "";
    var meta = [];
    if (spec.required) meta.push("required");
    if (spec.default !== undefined) meta.push("default " + JSON.stringify(spec.default));
    if (meta.length > 0) desc = (desc ? desc + " " : "") + "(" + meta.join(", ") + ")";
    lines.push(pad + label + trail + desc);
  }
  return lines.join("\n");
}

function _renderHelp(parser) {
  var lines = [];
  var prog = parser.programName || "program";
  if (parser.description) lines.push(parser.description);
  if (parser.commands.list.length > 0) {
    lines.push("Usage: " + prog + " <command> [flags]");
  } else {
    lines.push("Usage: " + prog + " [flags] [args]");
  }
  if (parser.flags.list.length > 0) {
    lines.push("");
    lines.push("Flags:");
    lines.push(_renderFlagsBlock(parser.flags.list, 2));
  }
  if (parser.commands.list.length > 0) {
    lines.push("");
    lines.push("Commands:");
    var nameWidth = 0;
    parser.commands.list.forEach(function (c) {
      if (c.name.length > nameWidth) nameWidth = c.name.length;
    });
    parser.commands.list.forEach(function (c) {
      var pad = "";
      while (c.name.length + pad.length < nameWidth + 2) pad += " ";
      lines.push("  " + c.name + pad + (c.description || ""));
    });
  }
  return lines.join("\n");
}

function _renderCommandHelp(parser, command) {
  var lines = [];
  var prog = parser.programName || "program";
  lines.push("Usage: " + prog + " " + command.name + " [flags]");
  if (command.description) {
    lines.push("");
    lines.push(command.description);
  }
  // Merged: command-level flags override / extend top-level flags.
  var merged = {};
  parser.flags.list.forEach(function (s) { merged[s.name] = s; });
  command.flags.list.forEach(function (s) { merged[s.name] = s; });
  var allSpecs = Object.keys(merged).map(function (n) { return merged[n]; });
  if (allSpecs.length > 0) {
    lines.push("");
    lines.push("Flags:");
    lines.push(_renderFlagsBlock(allSpecs, 2));
  }
  return lines.join("\n");
}

// Low-level: walk argv and split into { command, tokens, terminatorReached }.
// Tokens are passed to _consumeFlags below. This step only identifies the
// command-name (the first non-flag token, when commands are configured).
function _splitArgv(parser, argv) {
  if (!Array.isArray(argv)) {
    throw new ArgParserError("argParser/argv-not-array",
      "argv must be an array of strings");
  }
  for (var n = 0; n < argv.length; n++) {
    if (typeof argv[n] !== "string") {
      throw new ArgParserError("argParser/argv-element-not-string",
        "argv[" + n + "] must be a string");
    }
  }
  if (parser.commands.list.length === 0) {
    return { command: null, pre: argv.slice(), rest: [] };
  }
  // Walk argv looking for the first non-flag token. Anything before it
  // is a top-level flag (consumed against parser.flags). The token itself
  // becomes the command, and everything after is consumed against the
  // command's flags.
  for (var i = 0; i < argv.length; i++) {
    var t = argv[i];
    if (t === "--") return { command: null, pre: argv.slice(0, i), rest: argv.slice(i) };
    if (t.indexOf("-") !== 0) {
      var name = t;
      if (!parser.commands.byName[name]) {
        // Surface help / version as built-ins even when no command matches.
        if (name === "help") return { command: "__help__", pre: argv.slice(0, i), rest: argv.slice(i + 1) };
        throw new ArgParserError("argParser/unknown-command",
          "unknown command '" + name + "'");
      }
      return { command: name, pre: argv.slice(0, i), rest: argv.slice(i + 1) };
    }
  }
  return { command: null, pre: argv.slice(), rest: [] };
}

// Consume a token-list against a flag index, returning { flags, positionals,
// helpRequested }. Operates on the merged (top-level + command) flag index.
function _consumeFlags(index, tokens) {
  var flags = Object.create(null);
  var positionals = [];
  var helpRequested = false;
  var listAccum = Object.create(null);

  function _set(spec, raw) {
    if (spec.type === "list") {
      if (!listAccum[spec.name]) listAccum[spec.name] = [];
      var v = _coerceValue(spec, raw, "flag");
      // _coerceValue("list", x) returns an array; concat each element.
      for (var j = 0; j < v.length; j++) listAccum[spec.name].push(v[j]);
    } else {
      flags[spec.name] = _coerceValue(spec, raw, "flag");
    }
  }

  for (var i = 0; i < tokens.length; i++) {
    var tok = tokens[i];
    if (tok === "--") {
      for (var j = i + 1; j < tokens.length; j++) positionals.push(tokens[j]);
      break;
    }
    if (tok === "--help" || tok === "-h") { helpRequested = true; continue; }

    var spec = null;
    var rawValue = null;
    var hasInlineValue = false;

    if (tok.indexOf("--") === 0) {
      var rest = tok.slice(2);
      if (FORBIDDEN_NAMES.indexOf(rest.split("=")[0]) !== -1) {
        throw new ArgParserError("argParser/argv-forbidden-name",
          "flag '--" + rest.split("=")[0] + "' is reserved");
      }
      var eq = rest.indexOf("=");
      var nm;
      if (eq !== -1) {
        nm = rest.slice(0, eq);
        rawValue = rest.slice(eq + 1);
        hasInlineValue = true;
      } else {
        nm = rest;
      }
      spec = index.byName[nm];
      if (!spec) {
        throw new ArgParserError("argParser/unknown-flag",
          "unknown flag '--" + nm + "'");
      }
    } else if (tok.indexOf("-") === 0 && tok.length >= 2) {
      var alias = tok.slice(1);
      // Forms supported: -v, -v=value, -v value (next token).
      var aeq = alias.indexOf("=");
      var ach;
      if (aeq !== -1) {
        ach = alias.slice(0, aeq);
        rawValue = alias.slice(aeq + 1);
        hasInlineValue = true;
      } else {
        ach = alias;
      }
      if (ach.length !== 1) {
        throw new ArgParserError("argParser/short-flag-shape",
          "short flag '" + tok + "' must be a single letter (use --long-form for multi-char names)");
      }
      spec = index.byAlias[ach];
      if (!spec) {
        throw new ArgParserError("argParser/unknown-alias",
          "unknown short flag '-" + ach + "'");
      }
    } else {
      positionals.push(tok);
      continue;
    }

    if (spec.type === "boolean" && !hasInlineValue) {
      // Bare boolean flag — no inline value, do NOT consume the next
      // token (it might be a positional that happens to look word-y).
      _set(spec, true);
    } else {
      if (!hasInlineValue) {
        if (i + 1 >= tokens.length) {
          throw new ArgParserError("argParser/value-missing",
            "flag '--" + spec.name + "' requires a value");
        }
        rawValue = tokens[++i];
      }
      _set(spec, rawValue);
    }
  }

  // Roll list accumulators into the flags object.
  Object.keys(listAccum).forEach(function (k) { flags[k] = listAccum[k]; });

  return { flags: flags, positionals: positionals, helpRequested: helpRequested };
}

function _applyDefaultsAndRequired(specs, flags, ownerLabel) {
  // Defaults first — required check sees defaulted values.
  for (var i = 0; i < specs.length; i++) {
    var spec = specs[i];
    if (flags[spec.name] === undefined && spec.default !== undefined) {
      // Defaults are taken as-supplied. Operator-supplied defaults are
      // already in the target type's shape (this is config-time data).
      flags[spec.name] = spec.default;
    }
  }
  for (var k = 0; k < specs.length; k++) {
    var s = specs[k];
    if (s.required && flags[s.name] === undefined) {
      throw new ArgParserError("argParser/missing-required",
        ownerLabel + ": flag '--" + s.name + "' is required");
    }
  }
}

function _validateCommandSpec(cmd) {
  if (!cmd || typeof cmd !== "object") {
    throw new ArgParserError("argParser/command-spec-invalid",
      "command spec must be an object");
  }
  if (!_isPlainNonEmpty(cmd.name)) {
    throw new ArgParserError("argParser/command-name-invalid",
      "command name must be a non-empty string");
  }
  if (!/^[a-zA-Z][a-zA-Z0-9_-]*$/.test(cmd.name)) {
    throw new ArgParserError("argParser/command-name-shape",
      "command name '" + cmd.name + "' must match [a-zA-Z][a-zA-Z0-9_-]*");
  }
  if (cmd.handler !== undefined && typeof cmd.handler !== "function") {
    throw new ArgParserError("argParser/command-handler-not-function",
      "command '" + cmd.name + "' handler must be a function");
  }
  if (cmd.description !== undefined && typeof cmd.description !== "string") {
    throw new ArgParserError("argParser/command-description-invalid",
      "command '" + cmd.name + "' description must be a string");
  }
}

/**
 * @primitive b.argParser.create
 * @signature b.argParser.create(opts)
 * @since     0.8.48
 * @status    stable
 * @related   b.argParser.parseRaw
 *
 * Build a CLI parser from a declarative spec — top-level flags plus
 * named commands with their own per-command flag lists. Returns
 * `{ parse, help }`. Validates the spec at construction time so
 * misconfigured aliases / duplicate names / unsupported types throw
 * before any argv is seen.
 *
 * @opts
 *   programName: string,    // optional; rendered in usage text
 *   description: string,    // optional; one-line program summary
 *   flags:       Array,     // top-level flag specs
 *   commands:    Array,     // command specs (each carries its own flags)
 *
 *   // Each flag spec: { name, alias?, type?, required?, default?, description? }
 *   //   type ∈ { "string", "number", "boolean", "list" }; default "string"
 *   //   alias is a single ASCII letter
 *   //   forbidden names: __proto__, constructor, prototype
 *   //
 *   // Each command spec: { name, description?, flags?, handler? }
 *
 * @example
 *   var ap = b.argParser.create({
 *     programName: "blamejs",
 *     description: "Server-side framework CLI",
 *     flags: [
 *       { name: "verbose", alias: "v", type: "boolean",
 *         description: "Verbose output" },
 *     ],
 *     commands: [
 *       {
 *         name: "migrate",
 *         description: "Run database migrations",
 *         flags: [
 *           { name: "db",  type: "string", required: true,
 *             description: "Path to sqlite file" },
 *           { name: "dir", type: "string", default: "./migrations" },
 *         ],
 *       },
 *     ],
 *   });
 *
 *   var parsed = ap.parse(["migrate", "--db", "./app.db", "-v"]);
 *   parsed.command;          // → "migrate"
 *   parsed.flags.db;         // → "./app.db"
 *   parsed.flags.verbose;    // → true
 *   parsed.flags.dir;        // → "./migrations" (default)
 *   parsed.positionals;      // → []
 *
 *   ap.help();               // → top-level usage string
 *   ap.help("migrate");      // → "Usage: blamejs migrate [flags] ..."
 */
function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw new ArgParserError("argParser/opts-required",
      "argParser.create requires an opts object");
  }
  var programName = opts.programName;
  if (programName !== undefined && typeof programName !== "string") {
    throw new ArgParserError("argParser/program-name-invalid",
      "programName must be a string");
  }
  var description = opts.description;
  if (description !== undefined && typeof description !== "string") {
    throw new ArgParserError("argParser/description-invalid",
      "description must be a string");
  }
  var topFlagsSpec = opts.flags || [];
  if (!Array.isArray(topFlagsSpec)) {
    throw new ArgParserError("argParser/flags-not-array",
      "flags must be an array");
  }
  var topFlags = _buildFlagIndex(topFlagsSpec, "top-level");

  var commandsSpec = opts.commands || [];
  if (!Array.isArray(commandsSpec)) {
    throw new ArgParserError("argParser/commands-not-array",
      "commands must be an array");
  }
  var commandsByName = Object.create(null);
  var commandsList = [];
  for (var i = 0; i < commandsSpec.length; i++) {
    var c = commandsSpec[i];
    _validateCommandSpec(c);
    if (commandsByName[c.name]) {
      throw new ArgParserError("argParser/command-duplicate",
        "command '" + c.name + "' declared twice");
    }
    var cmdFlagsSpec = c.flags || [];
    if (!Array.isArray(cmdFlagsSpec)) {
      throw new ArgParserError("argParser/command-flags-not-array",
        "command '" + c.name + "' flags must be an array");
    }
    var cmdFlags = _buildFlagIndex(cmdFlagsSpec, "command '" + c.name + "'");
    var entry = {
      name:        c.name,
      description: c.description || "",
      handler:     c.handler || null,
      flags:       cmdFlags,
    };
    commandsByName[c.name] = entry;
    commandsList.push(entry);
  }

  var parser = {
    programName: programName || "",
    description: description || "",
    flags:       topFlags,
    commands:    { byName: commandsByName, list: commandsList },
  };

  function help(commandName) {
    if (commandName) {
      var cmd = commandsByName[commandName];
      if (!cmd) {
        throw new ArgParserError("argParser/help-unknown-command",
          "no command named '" + commandName + "'");
      }
      return _renderCommandHelp(parser, cmd);
    }
    return _renderHelp(parser);
  }

  function parse(argv, parseOpts) {
    parseOpts = parseOpts || {};
    var exitOnHelp = parseOpts.exit === true;
    var stdout = parseOpts.stdout || process.stdout;
    var split = _splitArgv(parser, argv);

    // Top-level flags consumed before the command name (split.pre) plus
    // any flags up to the command terminator.
    var pre = split.pre || [];
    var preParsed = _consumeFlags(parser.flags, pre);

    if (split.command === "__help__") {
      // `<prog> help [<cmd>]`
      var topic = (split.rest && split.rest.length > 0) ? split.rest[0] : null;
      var msg = topic && commandsByName[topic] ? help(topic) : help();
      if (exitOnHelp) { stdout.write(msg + "\n"); process.exit(0); } // allow:process-exit — explicit { exit: true } from a bin/ shim
      return { command: null, flags: {}, positionals: [], helpRequested: true, helpText: msg };
    }

    if (split.command) {
      var cmdEntry = commandsByName[split.command];
      // Build a merged index for this command (top-level + command flags;
      // command flags shadow same-named top-level flags).
      var mergedByName  = Object.create(null);
      var mergedByAlias = Object.create(null);
      var mergedList    = [];
      function _add(spec) {
        if (mergedByName[spec.name]) {
          // Overwrite top-level with the command-level definition.
          // Drop the prior alias mapping when it pointed at the top spec.
          var prior = mergedByName[spec.name];
          if (prior.alias && mergedByAlias[prior.alias] === prior) {
            delete mergedByAlias[prior.alias];
          }
          mergedList = mergedList.filter(function (s) { return s.name !== spec.name; });
        }
        mergedByName[spec.name] = spec;
        if (spec.alias) mergedByAlias[spec.alias] = spec;
        mergedList.push(spec);
      }
      parser.flags.list.forEach(_add);
      cmdEntry.flags.list.forEach(_add);
      var mergedIndex = { byName: mergedByName, byAlias: mergedByAlias, list: mergedList };
      var cmdParsed = _consumeFlags(mergedIndex, split.rest);

      if (cmdParsed.helpRequested || preParsed.helpRequested) {
        var cmsg = _renderCommandHelp(parser, cmdEntry);
        if (exitOnHelp) { stdout.write(cmsg + "\n"); process.exit(0); } // allow:process-exit — explicit { exit: true } from a bin/ shim
        return { command: cmdEntry.name, flags: {}, positionals: [], helpRequested: true, helpText: cmsg };
      }

      // Carry top-level flag values forward into the per-command flags
      // object so handlers see one unified bag (operator ergonomics).
      Object.keys(preParsed.flags).forEach(function (k) {
        if (cmdParsed.flags[k] === undefined) cmdParsed.flags[k] = preParsed.flags[k];
      });
      _applyDefaultsAndRequired(mergedList, cmdParsed.flags, "command '" + cmdEntry.name + "'");

      return {
        command:        cmdEntry.name,
        flags:          cmdParsed.flags,
        positionals:    cmdParsed.positionals,
        helpRequested:  false,
        handler:        cmdEntry.handler,
      };
    }

    // No commands configured (or argv contained no command-name) — treat
    // as a flag-only parser. Honor `--` and aggregate everything else.
    if (preParsed.helpRequested) {
      var hmsg = _renderHelp(parser);
      if (exitOnHelp) { stdout.write(hmsg + "\n"); process.exit(0); } // allow:process-exit — explicit { exit: true } from a bin/ shim
      return { command: null, flags: {}, positionals: [], helpRequested: true, helpText: hmsg };
    }
    _applyDefaultsAndRequired(parser.flags.list, preParsed.flags, "top-level");
    return {
      command:       null,
      flags:         preParsed.flags,
      positionals:   preParsed.positionals,
      helpRequested: false,
    };
  }

  return { parse: parse, help: help };
}

/**
 * @primitive b.argParser.parseRaw
 * @signature b.argParser.parseRaw(argv)
 * @since     0.8.48
 * @status    stable
 * @related   b.argParser.create
 *
 * Minimal positional + flag splitter used by `lib/cli.js` subcommand
 * handlers. Returns `{ pos, flags }` where `flags` is an
 * Object.create(null) bag — no schema validation, no command dispatch.
 * Refuses prototype-pollution flag names (`__proto__`, `constructor`,
 * `prototype`). Treats `-x` as a boolean shortcut; supports `--key
 * value`, `--key=value`, and bare `--bool`. `--` terminates flag
 * parsing.
 *
 * @example
 *   var r = b.argParser.parseRaw(
 *     ["build", "--target=node", "-v", "--out", "dist", "--", "extra"]);
 *   r.pos;             // → ["build", "extra"]
 *   r.flags.target;    // → "node"
 *   r.flags.v;         // → true
 *   r.flags.out;       // → "dist"
 */
function parseRaw(argv) {
  if (!Array.isArray(argv)) {
    throw new ArgParserError("argParser/argv-not-array",
      "argv must be an array of strings");
  }
  var pos = [];
  var flags = Object.create(null);
  for (var i = 0; i < argv.length; i++) {
    var tok = argv[i];
    if (typeof tok !== "string") {
      throw new ArgParserError("argParser/argv-element-not-string",
        "argv[" + i + "] must be a string");
    }
    if (tok === "--") {
      for (var j = i + 1; j < argv.length; j++) pos.push(argv[j]);
      break;
    }
    if (tok.indexOf("--") === 0) {
      var name = tok.slice(2);
      var eq = name.indexOf("=");
      var val;
      if (eq !== -1) {
        val = name.slice(eq + 1);
        name = name.slice(0, eq);
      } else if (i + 1 < argv.length && argv[i + 1].indexOf("--") !== 0) {
        val = argv[++i];
      } else {
        val = true;
      }
      if (FORBIDDEN_NAMES.indexOf(name) !== -1) {
        throw new ArgParserError("argParser/argv-forbidden-name",
          "flag '--" + name + "' is reserved");
      }
      flags[name] = val;
    } else if (tok.indexOf("-") === 0 && tok.length === 2) {
      var s = tok.slice(1);
      if (FORBIDDEN_NAMES.indexOf(s) !== -1) {
        throw new ArgParserError("argParser/argv-forbidden-name",
          "flag '-" + s + "' is reserved");
      }
      flags[s] = true;
    } else {
      pos.push(tok);
    }
  }
  return { pos: pos, flags: flags };
}

module.exports = {
  create:   create,
  parseRaw: parseRaw,
};
