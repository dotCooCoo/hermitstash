const { describe, it } = require("node:test");
const assert = require("node:assert");
const b = require("../../lib/vendor/blamejs");

const { sanitizeFilename } = require("../../app/shared/sanitize-filename");

const ch = String.fromCharCode;
const BIDI = ch(0x202e);    // RIGHT-TO-LEFT OVERRIDE
const ZWSP = ch(0x200b);    // ZERO WIDTH SPACE
const BEL = ch(0x07);       // C0 control
const NUL = ch(0x00);

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

  it("strips C0 control characters and NUL bytes", function () {
    assert.strictEqual(sanitizeFilename("ctrl" + BEL + "x.txt"), "ctrlx.txt");
    assert.strictEqual(sanitizeFilename("a" + NUL + "b.txt"), "ab.txt");
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
    assert.strictEqual(sanitizeFilename("a/.." + NUL + "/b.txt", 500), "a/b.txt");     // NUL
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

describe("sanitize-filename — b.guardFilename contract (the primitive sanitizeFilename delegates to)", function () {
  it("strips a bidi override under bidiPolicy:strip while keeping the rest", function () {
    assert.strictEqual(b.guardFilename.sanitize("a" + BIDI + "b.txt", { bidiPolicy: "strip", reservedNamePolicy: "allow" }), "ab.txt");
  });
});
