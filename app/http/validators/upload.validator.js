/**
 * Upload request validators — shared validation for regular and chunked uploads.
 * Ensures consistent size/count/type enforcement across all upload paths.
 */
var nodePath = require("node:path");
var b = require("../../../lib/vendor/blamejs");

/**
 * Validate a file against allowed extensions, max size, and empty check.
 * Returns { valid: true } or { valid: false, reason: string }.
 */
function validateFile(filename, fileSize, allowedExtensions, maxFileSize) {
  if (!filename) return { valid: false, reason: "Missing filename." };
  if (fileSize === 0) return { valid: false, reason: "Empty file." };
  if (maxFileSize && fileSize > maxFileSize) return { valid: false, reason: "File too large." };

  var ext = nodePath.extname(filename).toLowerCase();
  if (!ext) return { valid: false, reason: "No file extension." };
  if (allowedExtensions && allowedExtensions.length > 0 && !allowedExtensions.includes(ext)) {
    return { valid: false, reason: "File type not allowed: " + ext };
  }

  return { valid: true };
}

/**
 * Validate chunk upload parameters.
 */
function validateChunk(chunkIndex, totalChunks, fileId) {
  if (chunkIndex === undefined || chunkIndex === null) return { valid: false, reason: "Missing chunk index." };
  if (!totalChunks || totalChunks <= 0) return { valid: false, reason: "Invalid total chunks." };
  if (totalChunks > 10000) return { valid: false, reason: "Too many chunks." };
  if (chunkIndex < 0 || chunkIndex >= totalChunks) return { valid: false, reason: "Chunk index out of range." };
  if (!fileId || !/^[a-zA-Z0-9]+$/.test(fileId)) return { valid: false, reason: "Invalid file ID." };
  return { valid: true };
}

/**
 * Validate bundle limits (file count, total size).
 */
function validateBundleLimits(fileCount, maxFiles, totalSize, maxBundleSize) {
  if (maxFiles && fileCount > maxFiles) return { valid: false, reason: "Too many files (max " + maxFiles + ")." };
  if (maxBundleSize && totalSize > maxBundleSize) return { valid: false, reason: "Bundle too large." };
  return { valid: true };
}

// ---- Magic byte content validation ----

// Extensions that map to the same detected type
var COMPAT = {
  ".jpeg": ".jpg",
  ".docx": ".zip", ".xlsx": ".zip", ".pptx": ".zip",  // OOXML = ZIP containers
  ".xls": ".ole2", ".ppt": ".ole2", ".doc": ".ole2",   // legacy Office = OLE2
  ".tar.gz": ".gz",
};

// Ceiling on how much a compressed archive may expand to while being inspected.
// The framework's own default is 1 GiB, which is a bound on the primitive, not
// on this request: inspecting a .gz means materialising the decompressed bytes,
// so that default would let a modest upload allocate 1 GiB per concurrent
// request on top of the plaintext the handler is already holding. The single
// upload path already caps its own memory (see MAX_CONCURRENT_REASSEMBLY); this
// keeps inspection inside the same discipline. An archive that expands past it
// is refused as un-inspectable rather than inspected at any cost.
var MAX_ARCHIVE_DECOMPRESSED_BYTES = b.constants.BYTES.mib(256);

// Ceiling on entries read from an archive's central directory before giving up.
// A legitimate upload is orders of magnitude below this; a directory claiming
// more is refused rather than walked.
var MAX_ARCHIVE_ENTRIES = 10000;

// The reader's bounds, set to match the balanced profile validateEntries runs
// under. They have to agree: the reader refuses from the sizes declared in the
// central directory BEFORE the profile is ever consulted, so leaving it on its
// own defaults meant an archive holding a 200 MiB file was turned away as
// `archive-read/entry-too-large` while the profile would have allowed it. Two
// limits on the same thing, and the tighter one wins silently — which is the
// worst way for a limit to be wrong, because the message names the reader and
// not the policy anyone would think to look at.
var ARCHIVE_BOMB_POLICY = {
  maxEntries:                 MAX_ARCHIVE_ENTRIES,
  maxEntryDecompressedBytes:  b.constants.BYTES.mib(500),
  maxTotalDecompressedBytes:  b.constants.BYTES.gib(1),
};

// Extensions that have known magic signatures and SHOULD be validated
var RISKY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tiff",
  ".pdf", ".zip", ".rar", ".7z", ".gz", ".tar.gz", ".bz2",
  ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".svg",
]);

// Raster image types fed to b.guardImage for polyglot / format-integrity
// tightening. SVG is deliberately absent — guardImage refuses SVG bytes via
// an svg-routing issue, and SVG has its own sanitize path (lib/sanitize-svg.js).
// Maps the detected extension to the MIME guardImage's magic table reports so
// the declared-vs-detected mismatch check stays neutral and only the polyglot /
// cap checks can fire (additive: guardImage can only TIGHTEN, never loosen).
var RASTER_IMAGE_MIME = {
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".bmp": "image/bmp",
  ".ico": "image/x-icon",
  ".tiff": "image/tiff",
};

/**
 * Detect actual content type from file buffer (first 512 bytes).
 * Returns extension string (".png", ".jpg", etc.) or null if unrecognized.
 */
function detectContentType(buf) {
  if (!buf || buf.length < 4) return null;
  var b = buf;
  // Images
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47) return ".png";
  if (b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return ".jpg";
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return ".gif";
  if (b[0] === 0x42 && b[1] === 0x4D) return ".bmp";
  if (b[0] === 0x00 && b[1] === 0x00 && b[2] === 0x01 && b[3] === 0x00) return ".ico";
  if ((b[0] === 0x49 && b[1] === 0x49 && b[2] === 0x2A && b[3] === 0x00) ||
      (b[0] === 0x4D && b[1] === 0x4D && b[2] === 0x00 && b[3] === 0x2A)) return ".tiff";
  if (b.length >= 12 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
      b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return ".webp";
  // Documents / archives
  // PDF: %PDF within first 1024 bytes (per Adobe spec — allows BOM, whitespace, or preamble)
  var pdfLimit = Math.min(1024, b.length - 3);
  for (var pi = 0; pi < pdfLimit; pi++) {
    if (b[pi] === 0x25 && b[pi+1] === 0x50 && b[pi+2] === 0x44 && b[pi+3] === 0x46) return ".pdf";
  }
  // ZIP: any PK signature (local header, central dir, end of central dir, spanned)
  if (b[0] === 0x50 && b[1] === 0x4B) return ".zip";
  if (b.length >= 6 && b[0] === 0x52 && b[1] === 0x61 && b[2] === 0x72 && b[3] === 0x21 && b[4] === 0x1A && b[5] === 0x07) return ".rar";
  if (b.length >= 6 && b[0] === 0x37 && b[1] === 0x7A && b[2] === 0xBC && b[3] === 0xAF && b[4] === 0x27 && b[5] === 0x1C) return ".7z";
  if (b[0] === 0x1F && b[1] === 0x8B) return ".gz";
  if (b[0] === 0x42 && b[1] === 0x5A && b[2] === 0x68) return ".bz2";
  if (b.length >= 8 && b[0] === 0xD0 && b[1] === 0xCF && b[2] === 0x11 && b[3] === 0xE0 &&
      b[4] === 0xA1 && b[5] === 0xB1 && b[6] === 0x1A && b[7] === 0xE1) return ".ole2";
  // SVG (text-based)
  if (b.length >= 8) {
    var head = b.subarray(0, Math.min(512, b.length)).toString("utf8").trim();
    if (head.startsWith("<?xml") || head.startsWith("<svg") || head.includes("<svg")) return ".svg";
  }
  return null;
}

/**
 * Validate that file content matches claimed extension.
 * Only checks extensions with known magic signatures — text formats skip validation.
 * Returns { valid: true } or { valid: false, reason: string }.
 */
function validateMagicBytes(filename, buffer) {
  if (!filename || !buffer) return { valid: true };
  var ext = nodePath.extname(filename).toLowerCase();
  if (!RISKY_EXTENSIONS.has(ext)) return { valid: true };
  if (buffer.length < 8) return { valid: false, reason: "File too small to verify content type." };

  var detected = detectContentType(buffer);
  if (!detected) return { valid: false, reason: "File content does not match " + ext + " format." };

  // Normalize both sides through the compatibility map
  var expectedType = COMPAT[ext] || ext;
  var detectedType = COMPAT[detected] || detected;
  // COMPAT already folds .jpeg to .jpg on both sides, and detectContentType
  // only ever reports .jpg — so the two spellings are one type by the time they
  // reach this comparison. A second .jpg/.jpeg special case used to sit here and
  // could not be reached: for it to be consulted the equality above had to fail,
  // which for that pair it cannot.
  var extensionMatches = (expectedType === detectedType);

  if (!extensionMatches) {
    return { valid: false, reason: "File content does not match " + ext + " format." };
  }

  // The buffer is a valid image whose extension agrees with its magic bytes.
  // For raster images only, run the polyglot / format-integrity guard — it can
  // only TIGHTEN this result. detectContentType() returns on the first magic
  // match, so a polyglot carrying two valid image signatures is mislabeled and
  // would otherwise pass; guardImage walks every signature and refuses a buffer
  // that matches more than one format. SVG is excluded (it routes through
  // lib/sanitize-svg.js; feeding it here trips a spurious svg-routing refusal).
  var rasterMime = RASTER_IMAGE_MIME[detectedType];
  if (rasterMime) {
    var imageCheck = b.guardImage.validate({ bytes: buffer, declaredMime: rasterMime });
    if (!imageCheck.ok) {
      return { valid: false, reason: "Image failed polyglot/format-integrity check." };
    }
  }

  return { valid: true };
}

// Archive formats whose entry list this can actually read. .7z, .rar and .bz2
// are accepted by RISKY_EXTENSIONS and verified against their magic bytes, but
// there is no reader for them here, so their contents go unexamined — better to
// say so than to imply the guard covers every archive an operator allows.
// gzip is here because .tar.gz and .gz are accepted extensions and a gzip
// stream reports its own magic, not the tar inside it. Reading only zip and tar
// left "compress the tar first" as the way past this check entirely — the guard
// would look present and do nothing for a whole accepted format.
/**
 * Does this buffer begin with a tar header?
 *
 * Decided by the header checksum rather than the "ustar" marker, because the
 * legacy V7 format carries no marker and is read perfectly well by ordinary
 * extractors — keying on the marker would let a V7 tar past. The checksum is
 * stored at offset 148 as octal and computed over the whole 512-byte header
 * with that field read as spaces, so it validates both formats identically.
 */
function _looksLikeTar(buf) {
  if (!buf || buf.length < 512) return false;
  var stored = buf.toString("ascii", 148, 156).replace(/\0.*$/, "").trim();
  if (!/^[0-7]+$/.test(stored)) return false;
  var expected = parseInt(stored, 8);
  var sum = 0;
  for (var i = 0; i < 512; i++) sum += (i >= 148 && i < 156) ? 0x20 : buf[i];
  return sum === expected;
}

// Each opener returns something with .entries(), or null when the format has no
// entry structure to inspect. gzip needs the extra hop: read.fromGzip yields a
// decompression handle, not a reader, and what is inside may be a tar or may be
// one plain compressed file.
var READABLE_ARCHIVE = {
  zip: function (adapter) {
    return b.archive.read.zip(adapter, { bombPolicy: ARCHIVE_BOMB_POLICY });
  },
  tar: function (adapter) {
    return b.archive.read.tar(adapter, { bombPolicy: ARCHIVE_BOMB_POLICY });
  },
  gzip: async function (adapter) {
    // Decompression itself is bounded by the framework's caps (1 GiB output,
    // 100x expansion), so a gzip bomb fails here before any tar is parsed.
    var gz = await b.archive.read.fromGzip(adapter, {
      maxDecompressedBytes: MAX_ARCHIVE_DECOMPRESSED_BYTES,
    });
    var bytes = await gz.toBuffer();

    // Decide whether this IS a tar before trying to read it as one, rather than
    // reading it and treating any failure as "not a tar". That shortcut is a
    // hole: a tar exceeding the entry cap, or one with deliberately malformed
    // metadata, throws exactly like a non-tar does, so every crafted .tar.gz
    // would be waved through as an ordinary compressed file. Deciding first
    // means a parse or policy failure on something that really is a tar
    // propagates and refuses, which is the fail-closed behaviour claimed.
    if (!_looksLikeTar(bytes)) return null;

    // Bomb policy passed explicitly: otherwise the compressed path would run on
    // the reader's 2^20 default while the direct .tar and .zip paths ran on this
    // cap, and the bound would hold everywhere except the format that arrives
    // already compressed.
    return b.archive.read.tar(b.archive.adapters.buffer(bytes), { bombPolicy: ARCHIVE_BOMB_POLICY });
  },
};

/**
 * Project a reader entry into the shape the guard reads.
 *
 * The readers describe an entry as `entryType` / `typeflag` / `linkname`; the
 * guard looks for `isSymlink` / `isHardlink` / `linkTarget`. Handing the reader's
 * output straight over therefore leaves every link check silently inert — the
 * guard runs, reports ok, and the symlink protection exists only in the claim.
 *
 * The framework has this projection, but only for zip (guardArchive.inspect
 * refuses any other format), and it hardcodes isHardlink to false because a zip
 * has no hardlink concept. A tar does: typeflag "1" is a hardlink and "2" a
 * symlink, with the destination in linkname. That is exactly the case a
 * zip-shaped projection would drop, so this reads both spellings.
 */
function toGuardEntry(e) {
  var type = e.entryType;
  return {
    name:           e.name,
    size:           e.size,
    compressedSize: e.compressedSize,
    isSymlink:      type === "symlink" || e.typeflag === "2",
    isHardlink:     type === "hardlink" || type === "link" || e.typeflag === "1",
    linkTarget:     e.linkname || e.linkTarget || null,
    isDirectory:    type === "directory" || e.typeflag === "5",
    isEncrypted:    !!e.isEncrypted,
    attrs:          { externalAttrs: e.externalAttrs },
  };
}

/**
 * Refuse an uploaded archive whose ENTRIES are hostile.
 *
 * validateMagicBytes already establishes that a file claiming to be a .zip is
 * one. Nothing looked inside it. This server never extracts an upload, so a
 * zip-slip path cannot hurt the server itself — but the archive is handed
 * straight back to whoever downloads it, and they will extract it. Passing on
 * an archive that writes outside its extraction directory is passing on the
 * attack, so it is refused here rather than stored and served.
 *
 * Runs the BALANCED profile, explicitly. The guard's bare defaults are the
 * strict profile, which caps an archive at 100 entries and 100 MiB — an
 * ordinary project zip or photo folder exceeds that, and calling validateEntries
 * with no options quietly refused a 150-file archive as `archive.entry-count`.
 * Balanced allows 10,000 entries (the same bound handed to the reader, so the
 * two agree), 1 GiB in total, and an archive nested two deep, which is what
 * someone zipping a folder that already contains a zip actually produces.
 *
 * What it still refuses is the structural set: an entry escaping its directory,
 * an absolute path, a symlink or hardlink pointing outside, a duplicate name,
 * and direction-changing, control, null or zero-width characters in a name.
 * Encryption is recorded rather than refused — sending a password-protected
 * archive is ordinary, and refusing it would refuse the product's purpose.
 *
 * Checked against real layouts before choosing that posture: an OOXML document
 * (every .docx/.xlsx/.pptx is a zip — `[Content_Types].xml`, `_rels/.rels`,
 * `word/document.xml`), an ordinary folder archive, and a source tree carrying
 * dotfiles all pass; a hand-built entry named `../../etc/passwd` is refused as
 * `archive.zip-slip`.
 *
 * async, unlike its sibling validators — reading a central directory is I/O
 * shaped even from a buffer. Both ingest paths await it.
 */
async function validateArchive(filename, buffer) {
  if (!buffer || buffer.length < 8) return { valid: true };

  // Magic first, then the declared extension. A tar in the legacy V7 format
  // carries no "ustar" marker at all, so sniffing identifies nothing — and
  // trusting the sniff alone would accept a V7 tar unexamined while ordinary
  // extractors read it quite happily. Falling back to the extension costs a
  // parse attempt on a file the sender already told us was a tar, and the
  // attempt failing is handled below as an unreadable archive.
  var magic = b.guardArchive.inspectMagic(buffer);
  var format = (magic && magic.format) || null;
  if (!format) {
    var ext = nodePath.extname(String(filename || "")).toLowerCase();
    if (ext === ".tar") format = "tar";
  }
  if (!format) return { valid: true };
  var open = READABLE_ARCHIVE[format];
  if (!open) return { valid: true };

  // The entry-count bound is handed to the reader rather than counted out here.
  // The reader parses the directory before yielding anything, so a count kept in
  // the loop below would only notice after the work it meant to prevent had
  // already happened; the reader's own bombPolicy refuses at the layer that does
  // the parsing. The default ceiling is 2^20, far above anything a real upload
  // carries — the point of naming a lower one is that this is somebody else's
  // archive, not ours.
  // inspect() rather than entries(): it is the one method every reader here
  // exposes and it returns the whole entry list. The zip reader also has
  // entries(), the tar reader does not — reaching for that would have refused
  // every .tar upload while appearing to work, because the throw would land in
  // the unreadable-archive branch below.
  var entries = [];
  try {
    var reader = await open(b.archive.adapters.buffer(buffer));
    if (!reader) return { valid: true };
    entries = await reader.inspect();
  } catch (e) {
    // Refuse rather than pass. The magic bytes already said this is an archive,
    // so a reader that cannot walk it means the structure is malformed or
    // beyond what this reader supports — and "accept what we could not read" is
    // how an attacker gets an archive past the check that a real extractor will
    // happily open. Over-refusing an exotic-but-valid archive is the cost, and
    // it is the right side to err on for somebody else's file.
    return { valid: false, reason: "Archive could not be read for inspection.", detail: e.code || "unreadable" };
  }

  var guardEntries = entries.map(toGuardEntry);

  // A link whose destination cannot be read is refused before the guard sees it.
  // A tar carries the destination in its header, so the guard can tell whether
  // it escapes; a ZIP stores it in the entry BODY, and the reader's entry list
  // has no field for it at all. That difference is invisible in the guard's
  // result — it is handed linkTarget: null, finds nothing to object to, and
  // returns ok. So a ZIP symlink pointing anywhere at all would have passed the
  // check that exists to stop exactly that, while the tar equivalent was caught.
  // Reading each link's body to recover the target is the alternative; refusing
  // is the smaller change and errs the right way for somebody else's archive,
  // where a symlink is uncommon to begin with.
  var blindLink = guardEntries.find(function (e) {
    return (e.isSymlink || e.isHardlink) && !e.linkTarget;
  });
  if (blindLink) {
    return {
      valid: false,
      reason: "Archive contents failed inspection.",
      detail: "archive.link-target-unreadable",
    };
  }

  var result = b.guardArchive.validateEntries(guardEntries, {
    profile: "balanced",
    // Keep the guard's entry cap and the reader's the same number. Two bounds
    // that disagree is a bug waiting to be found from whichever side is looser.
    maxEntries: MAX_ARCHIVE_ENTRIES,
  });
  if (result && result.ok) return { valid: true };

  // The finding names the offending entry, which is useful in the audit log and
  // is exactly what must NOT go back to the uploader: it is attacker-authored
  // text and would render their string in someone else's UI.
  var first = (result && result.issues && result.issues[0]) || null;
  return {
    valid: false,
    reason: "Archive contents failed inspection.",
    detail: first ? (first.ruleId || first.kind) : "unknown",
  };
}

// MIME types HS renders INLINE at serve time (mirrors app/domain/uploads/
// file.service.js SAFE_INLINE) and that b.fileType.detect can verify by magic
// bytes. The serve-time inline/download gate reads the STORED mimeType, which is
// the client-advertised multipart Content-Type — so a file declared as an
// inline-rendered type but whose bytes are something else could be steered to an
// inline render regardless of its extension (0.15.58 class). safeServeMime binds
// the stored type to the sniffed reality: a declared inline type whose bytes do
// not match is stored as application/octet-stream (forces download), never
// rejected. (image/svg+xml is absent — SVG is magic-byte-less and always routes
// to the sanitizer; every file response also carries X-Content-Type-Options:
// nosniff, so the browser never sniffs a served body into an active type.)
var INLINE_SNIFFABLE_MIME = new Set([
  "application/pdf", "image/gif", "image/jpeg", "image/png", "image/webp",
]);

function safeServeMime(declaredMime, buffer) {
  if (!declaredMime || typeof declaredMime !== "string") return "application/octet-stream";

  // Screen the declared type before anything else. Only the handful of inline
  // types below were ever sniff-bound; every other declared type was returned
  // verbatim, stored, and later written as a Content-Type header. The multipart
  // parser preserves a form field byte for byte, carriage returns and nulls
  // included, so a value like "text/plain\r\nX-Injected: 1" reached writeHead —
  // which refuses it with ERR_INVALID_CHAR. That is not header injection, node
  // stops that; it is worse in one specific way: the throw happens on every
  // subsequent download of that file, so an anonymous upload to a public stash
  // could make one file permanently unfetchable, with the download counter
  // incrementing on each failed attempt. A type the guard rejects is served as
  // a plain download instead of being trusted.
  var mimeCheck = b.guardMime.validate(declaredMime);
  if (!mimeCheck || !mimeCheck.ok) return "application/octet-stream";

  if (!INLINE_SNIFFABLE_MIME.has(declaredMime)) return declaredMime;
  if (!buffer || buffer.length < 4) return "application/octet-stream";
  var sniffed = b.fileType.detect(buffer);
  return (sniffed && sniffed.mime === declaredMime) ? declaredMime : "application/octet-stream";
}

module.exports = { validateFile, validateChunk, validateBundleLimits, detectContentType, validateMagicBytes, validateArchive, safeServeMime };
