const { describe, it } = require("node:test");
const assert = require("node:assert");
const b = require("../../lib/vendor/blamejs");

const { sanitizeFilename, sanitizeRename, stripNameControls, safeContentDisposition } = require("../../app/shared/sanitize-filename");

const ch = String.fromCharCode;
const BIDI = ch(0x202e);    // RIGHT-TO-LEFT OVERRIDE
const ZWSP = ch(0x200b);    // ZERO WIDTH SPACE
const BEL = ch(0x07);       // C0 control
const NUL = ch(0x00);
const DEL = ch(0x7f);
const NEL = ch(0x85);       // C1 NEXT LINE
const CSI = ch(0x9b);       // C1 CONTROL SEQUENCE INTRODUCER

describe("sanitize-filename — sanitizeFilename: parity for legitimate names", function () {
  it("passes ordinary filenames through unchanged", function () {
    assert.strictEqual(sanitizeFilename("report.pdf"), "report.pdf");
    assert.strictEqual(sanitizeFilename("my file.txt"), "my file.txt");
    assert.strictEqual(sanitizeFilename("photo (1).jpeg"), "photo (1).jpeg");
  });

  it("keeps unicode, multi-dot, executable, reserved, and long names (permissive)", function () {
    assert.strictEqual(sanitizeFilename("résumé.docx"), "résumé.docx");
    assert.strictEqual(sanitizeFilename("用户文件.txt"), "用户文件.txt");
    assert.strictEqual(sanitizeFilename("archive.tar.gz"), "archive.tar.gz");
    assert.strictEqual(sanitizeFilename("installer.exe"), "installer.exe");
    assert.strictEqual(sanitizeFilename("CON.txt"), "CON.txt");
    const long = "Annual Report Q4 2026 Final Reviewed Approved Version 3.xlsx";
    assert.strictEqual(sanitizeFilename(long), long);
  });

  it("strips < > \" ' ` so a stored name is safe to render in HTML", function () {
    assert.strictEqual(sanitizeFilename("a<script>.txt"), "ascript.txt");
    assert.strictEqual(sanitizeFilename("John's résumé.pdf"), "Johns résumé.pdf");
    assert.strictEqual(sanitizeFilename("back`tick`.txt"), "backtick.txt");
  });

  it("trims leading/trailing whitespace on the joined result", function () {
    assert.strictEqual(sanitizeFilename("  spaced.txt  "), "spaced.txt");
  });

  it("truncates to maxLength (default 255, override honoured)", function () {
    assert.strictEqual(sanitizeFilename("x".repeat(300) + ".bin").length, 255);
    assert.strictEqual(sanitizeFilename("y".repeat(600), 500).length, 500);
  });
});

describe("sanitize-filename — sanitizeFilename: relativePath structure + traversal", function () {
  it("preserves nested path structure, rejoining with /", function () {
    assert.strictEqual(sanitizeFilename("folder/sub/file.txt", 500), "folder/sub/file.txt");
  });

  it("normalises backslashes and drops empty / . segments", function () {
    assert.strictEqual(sanitizeFilename("a\\\\b\\file.txt", 500), "a/b/file.txt");
    assert.strictEqual(sanitizeFilename("./rel/./file.txt", 500), "rel/file.txt");
  });

  it("strips .. traversal segments while keeping structure", function () {
    assert.strictEqual(sanitizeFilename("a/../b/file.txt", 500), "a/b/file.txt");
    assert.strictEqual(sanitizeFilename("../../win/file.txt", 500), "win/file.txt");
  });

  it("returns empty string for fully-degenerate input (matches prior behaviour)", function () {
    assert.strictEqual(sanitizeFilename(""), "");
    assert.strictEqual(sanitizeFilename(".."), "");
    assert.strictEqual(sanitizeFilename("/"), "");
  });
});

describe("sanitize-filename — sanitizeFilename: hardening (neutralised, not lost)", function () {
  it("strips a bidi RTL-override (Trojan-Source filename spoof)", function () {
    assert.strictEqual(sanitizeFilename("evil" + BIDI + "cod.exe"), "evilcod.exe");
  });

  it("strips a zero-width space", function () {
    assert.strictEqual(sanitizeFilename("zero" + ZWSP + "width.txt"), "zerowidth.txt");
  });

  it("strips the invisible operators U+2061-2064 alongside U+2060", function () {
    // UAX #31 groups these five, and a name carrying one renders identically to
    // a name without it — the same display-spoofing shape as the zero-width
    // space above. WORD JOINER was covered; its four neighbours were not, so a
    // filename could differ from another only by an invisible operator.
    assert.strictEqual(sanitizeFilename("word" + ch(0x2060) + "joiner.txt"), "wordjoiner.txt");
    assert.strictEqual(sanitizeFilename("fn" + ch(0x2061) + "app.txt"), "fnapp.txt");
    assert.strictEqual(sanitizeFilename("inv" + ch(0x2062) + "times.txt"), "invtimes.txt");
    assert.strictEqual(sanitizeFilename("inv" + ch(0x2063) + "sep.txt"), "invsep.txt");
    assert.strictEqual(sanitizeFilename("inv" + ch(0x2064) + "plus.txt"), "invplus.txt");
  });

  it("collapses two names that differ only by an invisible operator", function () {
    // The property that matters for storage: an attacker cannot mint a second
    // name that displays identically to an existing one.
    assert.strictEqual(sanitizeFilename("report" + ch(0x2062) + ".pdf"),
      sanitizeFilename("report.pdf"));
  });

  it("strips C0 control characters", function () {
    assert.strictEqual(sanitizeFilename("ctrl" + BEL + "x.txt"), "ctrlx.txt");
  });

  // A NUL is REFUSED, not repaired, and this asserts that on purpose — it is
  // not a weaker version of the strip it replaced. The name a check reads and
  // the name the operating system acts on diverge at the byte, so a stripped
  // name is one nobody validated. b.guardFilename fixes nullBytePolicy at
  // reject and does not offer it as a policy, because there is no safe repair.
  // A name that is only the refused segment therefore sanitises to "", which is
  // already what "." and ".." do.
  it("refuses a NUL-bearing segment instead of repairing it", function () {
    assert.strictEqual(sanitizeFilename("a" + NUL + "b.txt"), "");
  });

  // The refusal invalidates the WHOLE path, and this is the assertion that
  // says why. Dropping just the refused component would rewrite the path to a
  // different VALID one — "docs/<refused>/report.pdf" becoming
  // "docs/report.pdf" — and a sync bundle resolves an existing file by that
  // path and replaces it, so a refused upload could land on a file it never
  // named. Traversal stays the exception below: dropping "." and ".." IS the
  // normalisation.
  it("refuses the whole path, not just the segment, so it cannot collapse onto another", function () {
    assert.strictEqual(sanitizeFilename("docs/a" + NUL + "b.txt/report.pdf"), "");
    assert.notStrictEqual(sanitizeFilename("docs/a" + NUL + "b.txt/report.pdf"),
      sanitizeFilename("docs/report.pdf"));
  });
});

describe("sanitize-filename — sanitizeFilename: regression guards (adversarial findings)", function () {
  it("strips TAB, CR, LF and DEL (full C0 + DEL parity with the prior helper)", function () {
    assert.strictEqual(sanitizeFilename("a" + ch(0x09) + "b" + ch(0x0a) + ch(0x0d) + ch(0x7f) + ".txt"), "ab.txt");
  });

  it("removes CR/LF so a filename cannot carry a response-splitting payload", function () {
    assert.strictEqual(sanitizeFilename("evil" + ch(0x0d) + ch(0x0a) + "Set-Cookie.txt"), "evilSet-Cookie.txt");
  });

  it("drops an obfuscated '..' that only reduces to '..' after stripping", function () {
    assert.strictEqual(sanitizeFilename("a/.." + ZWSP + "/b.txt", 500), "a/b.txt");   // zero-width
    assert.strictEqual(sanitizeFilename("a/" + BIDI + "../b.txt", 500), "a/b.txt");    // bidi override
  });

  // The NUL spelling of the same attack lands harder, and that is the point.
  // Zero-width and bidi are repairable, so the segment reduces to ".." and is
  // dropped as traversal. A NUL is not repairable, so the guard refuses it and
  // the whole path goes — which also stops "a/..<NUL>/b.txt" from arriving at
  // "a/b.txt", a path the uploader never named and which may already exist.
  it("refuses the whole path when the obfuscation is a NUL", function () {
    assert.strictEqual(sanitizeFilename("a/.." + NUL + "/b.txt", 500), "");
  });

  it("neutralizes hostile bytes in an interior path segment, not just the leaf", function () {
    assert.strictEqual(sanitizeFilename("folder/ev" + BIDI + "il/file.txt", 500), "folder/evil/file.txt");
  });

  it("preserves decomposed (NFD) unicode bytes exactly — no NFC folding", function () {
    const nfd = "Mu" + ch(0x0308) + "nchen.pdf";   // u + combining diaeresis
    assert.strictEqual(sanitizeFilename(nfd), nfd);
  });

  it("truncates an oversized single segment instead of dropping it", function () {
    assert.strictEqual(sanitizeFilename("a/" + "x".repeat(5000) + "/b.txt", 500).length, 500);
  });
});

describe("sanitize-filename — sanitizeRename bounds its subject", function () {
  // The replace chain runs before the length cap, and /\s*\.\s*/g is quadratic
  // on a whitespace run: 400,000 spaces measured at 57 seconds of blocked event
  // loop, reachable from the rename routes, which pass body.name unbounded.
  it("refuses an oversized raw value instead of sanitizing it", function () {
    const res = sanitizeRename(" ".repeat(400000), { maxLength: 255 });
    assert.strictEqual(res.valid, false, "an oversized value must be refused");
    assert.strictEqual(res.name, "");
    assert.match(res.error, /too long/i);
  });

  it("refuses the oversized value quickly", function () {
    const t0 = process.hrtime.bigint();
    sanitizeRename(" ".repeat(400000), { maxLength: 255 });
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    assert.ok(ms < 250, "must not run the quadratic chain on it (took " + ms.toFixed(1) + " ms)");
  });

  it("still accepts an ordinary rename", function () {
    assert.deepStrictEqual(sanitizeRename("my report.pdf"), { valid: true, name: "my report.pdf" });
  });

  it("still accepts a value at the long end of legitimate", function () {
    const res = sanitizeRename("a".repeat(300) + ".pdf", { maxLength: 255 });
    assert.strictEqual(res.valid, true);
    assert.strictEqual(res.name.length, 255);
  });
});

describe("sanitize-filename: control characters in renames and vault names", function () {
  it("sanitizeRename strips C0, DEL and C1 control characters", function () {
    assert.deepStrictEqual(sanitizeRename("a" + BEL + "b" + DEL + "c" + NEL + "d" + CSI + "e.txt"),
      { valid: true, name: "abcde.txt" });
  });

  it("sanitizeRename strips TAB, LF and CR", function () {
    assert.deepStrictEqual(sanitizeRename("a\tb\nc\rd.txt"), { valid: true, name: "abcd.txt" });
  });

  it("stripNameControls removes the same characters and keeps every other one", function () {
    assert.strictEqual(stripNameControls("re" + NUL + "port" + NEL + "\t.pdf"), "report.pdf");
    assert.strictEqual(stripNameControls("résumé (1).pdf"), "résumé (1).pdf");
  });
});

describe("sanitize-filename — colons survive (adsPolicy/reservedCharPolicy stay honored)", function () {
  // A colon is an ordinary filename character outside Windows, and FNAME_OPTS
  // sets adsPolicy and reservedCharPolicy to "allow" to keep it. A framework
  // build that stops honouring either empties these names rather than refusing
  // them, so nothing downstream reports an error: the upload just loses its
  // name. These assertions are what makes that visible.
  it("keeps a colon in an ordinary filename", function () {
    assert.strictEqual(sanitizeFilename("12:30 notes.txt"), "12:30 notes.txt");
    assert.strictEqual(sanitizeFilename("report:final.txt"), "report:final.txt");
    assert.strictEqual(sanitizeFilename("ratio 1:1.png"), "ratio 1:1.png");
  });

  it("keeps a colon inside a nested relativePath", function () {
    assert.strictEqual(sanitizeFilename("folder/note:1.txt", 500), "folder/note:1.txt");
  });

  it("keeps a Windows drive-style prefix, normalising the separators", function () {
    assert.strictEqual(sanitizeFilename("C:\\tmp\\a.txt", 500), "C:/tmp/a.txt");
  });

  it("keeps an alternate-data-stream shape rather than emptying the name", function () {
    assert.strictEqual(sanitizeFilename("notes.txt:Zone.Identifier"), "notes.txt:Zone.Identifier");
    assert.strictEqual(sanitizeFilename("x:$DATA"), "x:$DATA");
  });
});

describe("sanitize-filename — b.guardFilename contract (the primitive sanitizeFilename delegates to)", function () {
  it("strips a bidi override under bidiPolicy:strip while keeping the rest", function () {
    assert.strictEqual(b.guardFilename.sanitize("a" + BIDI + "b.txt", { bidiPolicy: "strip", reservedNamePolicy: "allow" }), "ab.txt");
  });

  it("refuses a policy value outside the vocabulary instead of ignoring it", function () {
    // The boot probe in app/shared/sanitize-filename.js depends on this: it is
    // what turns a policy the framework no longer accepts into a startup failure
    // naming the option, rather than every name silently coming back empty.
    assert.throws(function () {
      b.guardFilename.sanitize("probe.txt", { adsPolicy: "definitely-not-a-policy" });
    });
  });
});

describe("sanitize-filename relies on the b.codepointClass control table", function () {
  it("CTRL_RANGES holds C0 except TAB, LF and CR, plus DEL and C1, and no other code point up to U+00A0", function () {
    for (var cp = 0; cp <= 0xa0; cp++) {
      var expected = (cp <= 0x1f && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) || cp === 0x7f ||
        (cp >= 0x80 && cp <= 0x9f);
      assert.strictEqual(b.codepointClass.inRanges(cp, b.codepointClass.CTRL_RANGES), expected,
        "U+" + cp.toString(16).toUpperCase());
    }
  });

  it("stripRanges removes the listed code points and keeps every other character", function () {
    var emoji = String.fromCodePoint(0x1f600);
    assert.strictEqual(b.codepointClass.stripRanges("a" + NUL + "b" + DEL + "c" + NEL + "d" + ch(0x09) + "e",
      b.codepointClass.CTRL_RANGES), "abcd" + ch(0x09) + "e");
    assert.strictEqual(b.codepointClass.stripRanges("a" + emoji + "b", b.codepointClass.CTRL_RANGES), "a" + emoji + "b");
    var clean = "report (final).pdf";
    assert.strictEqual(b.codepointClass.stripRanges(clean, b.codepointClass.CTRL_RANGES), clean);
  });
});

describe("safeContentDisposition relies on the b.staticServe.attachmentDisposition contract", function () {
  function ad(name) { return b.staticServe.attachmentDisposition(name); }
  function expected(ascii, extValue) {
    return "attachment; filename=" + '"' + ascii + '"' + "; filename*=UTF-8''" + extValue;
  }
  var resume = "r" + ch(0xe9) + "sum" + ch(0xe9) + ".pdf";

  it("attachmentDisposition pairs an ASCII filename with an RFC 8187 filename* that escapes the apostrophe", function () {
    assert.strictEqual(ad("report (final).pdf"), expected("report (final).pdf", "report%20%28final%29.pdf"));
    assert.strictEqual(ad("it's.txt"), expected("it's.txt", "it%27s.txt"));
  });

  it("attachmentDisposition folds non-ASCII and a double quote out of filename and keeps them in filename*", function () {
    assert.strictEqual(ad(resume), expected("r_sum_.pdf", "r%C3%A9sum%C3%A9.pdf"));
    assert.strictEqual(ad("a" + '"' + "b.txt"), expected("a_b.txt", "a%22b.txt"));
  });

  it("attachmentDisposition serves an empty name, or one carrying CR, LF or NUL, as download", function () {
    var download = expected("download", "download");
    assert.strictEqual(ad(""), download);
    assert.strictEqual(ad(undefined), download);
    assert.strictEqual(ad("evil" + ch(0x0d) + ch(0x0a) + "Set-Cookie: x=1"), download);
    assert.strictEqual(ad("a" + NUL + "b.txt"), download);
  });

  it("attachmentDisposition keeps only the last segment of a stored relative path", function () {
    assert.strictEqual(ad("docs/report.pdf"), expected("report.pdf", "report.pdf"));
  });

  it("safeContentDisposition returns the primitive's value unchanged", function () {
    ["it's.txt", resume, "", "docs/report.pdf"].forEach(function (name) {
      assert.strictEqual(safeContentDisposition(name), ad(name));
    });
  });
});
