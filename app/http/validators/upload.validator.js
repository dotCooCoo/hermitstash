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

// Inspecting a compressed archive means materialising its decompressed bytes,
// so the framework's 1 GiB default would let a modest upload allocate that much
// per concurrent request, on top of the plaintext the handler already holds.
// Anything expanding past this is refused as un-inspectable.
var MAX_ARCHIVE_DECOMPRESSED_BYTES = b.constants.BYTES.mib(256);

// Ceiling on entries read from an archive's central directory before giving up.
// A legitimate upload is orders of magnitude below this; a directory claiming
// more is refused rather than walked.
var MAX_ARCHIVE_ENTRIES = 10000;

// Must agree with the balanced profile validateEntries runs under. The reader
// refuses from the declared sizes before the profile is consulted, so on its own
// defaults it turned away archives the profile would have allowed — and the
// error named the reader, not the policy anyone would think to look at.
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

// Maps a detected extension to the MIME guardImage's own magic table reports,
// so its mismatch check stays neutral and only the polyglot and cap checks can
// fire. SVG is absent: it routes through lib/sanitize-svg.js instead.
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
  // COMPAT folds .jpeg to .jpg on both sides, so the two spellings are already
  // one type here and need no second case.
  var extensionMatches = (expectedType === detectedType);

  if (!extensionMatches) {
    return { valid: false, reason: "File content does not match " + ext + " format." };
  }

  // detectContentType returns on the first magic match, so a polyglot carrying
  // two valid image signatures is mislabelled and passes. guardImage walks every
  // signature and refuses a buffer matching more than one format.
  var rasterMime = RASTER_IMAGE_MIME[detectedType];
  if (rasterMime) {
    var imageCheck = b.guardImage.validate({ bytes: buffer, declaredMime: rasterMime });
    if (!imageCheck.ok) {
      return { valid: false, reason: "Image failed polyglot/format-integrity check." };
    }
  }

  return { valid: true };
}

// The archive formats whose entries this can actually read. .7z, .rar and .bz2
// are accepted and magic-verified but never examined inside, which is worth
// saying rather than implying the guard covers every archive an operator
// allows. gzip is here because a gzip stream reports its own magic, not the tar
// within — reading only zip and tar left "compress the tar first" as a way past
// this check entirely.
/**
 * Does this buffer begin with a tar header?
 *
 * Decided by the header checksum, not the "ustar" marker: the legacy V7 format
 * carries no marker and ordinary extractors read it perfectly well, so keying
 * on the marker would let a V7 tar through.
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

    // Decided before the read, not by treating a failed read as "not a tar":
    // a tar over the entry cap, or with deliberately malformed metadata, throws
    // exactly as a non-tar does, so every crafted .tar.gz would be waved
    // through as an ordinary compressed file.
    if (!_looksLikeTar(bytes)) return null;

    // Passed explicitly, or this path runs on the reader's default while the
    // direct .tar and .zip paths run on the cap above — leaving the bound in
    // force everywhere except the format that arrives already compressed.
    return b.archive.read.tar(b.archive.adapters.buffer(bytes), { bombPolicy: ARCHIVE_BOMB_POLICY });
  },
};

/**
 * Project a reader entry into the shape the guard reads.
 *
 * The readers describe an entry with `entryType` / `typeflag` / `linkname`; the
 * guard looks for `isSymlink` / `isHardlink` / `linkTarget`. Passing the
 * reader's output straight over leaves every link check silently inert — the
 * guard runs, reports ok, and the protection exists only in the claim.
 *
 * The framework's own projection is zip-shaped, and hardcodes isHardlink to
 * false because a zip has no such concept. A tar does, so this reads both.
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
 * validateMagicBytes establishes only that a file claiming to be a .zip is one.
 * This server never extracts an upload, so a zip-slip path cannot hurt the
 * server — but the archive is handed to whoever downloads it, and they will
 * extract it. Passing on an archive that writes outside its extraction
 * directory is passing on the attack.
 *
 * Runs the balanced profile explicitly. The bare defaults are strict, capping
 * an archive at 100 entries, which an ordinary project zip or photo folder
 * exceeds — so calling this with no options refused them as `archive.entry-
 * count`. Balanced allows 10,000 entries, matching the bound handed to the
 * reader, and an archive nested two deep, which is what zipping a folder that
 * already contains a zip produces.
 *
 * Still refused: an entry escaping its directory, an absolute path, a symlink
 * or hardlink pointing outside, a duplicate name, and direction-changing,
 * control, null or zero-width characters in a name. Encryption is recorded
 * rather than refused — refusing a password-protected archive would refuse the
 * product's own purpose.
 *
 * async because reading a central directory is I/O-shaped even from a buffer.
 */
async function validateArchive(filename, buffer) {
  if (!buffer || buffer.length < 8) return { valid: true };

  // Magic first, then the declared extension. A legacy V7 tar carries no
  // marker, so the sniff identifies nothing and trusting it alone would accept
  // one unexamined while ordinary extractors read it happily.
  var magic = b.guardArchive.inspectMagic(buffer);
  var format = (magic && magic.format) || null;
  if (!format) {
    var ext = nodePath.extname(String(filename || "")).toLowerCase();
    if (ext === ".tar") format = "tar";
  }
  if (!format) return { valid: true };
  var open = READABLE_ARCHIVE[format];
  if (!open) return { valid: true };

  // The entry-count bound belongs to the reader, not a count kept below: the
  // reader parses the whole directory before yielding anything, so a loop
  // counter only notices after the work it meant to prevent has happened.
  //
  // inspect() rather than entries(), because it is the one method every reader
  // here exposes. The tar reader has no entries(), so reaching for it would
  // have refused every .tar upload through the unreadable-archive branch below
  // while appearing to work.
  var entries = [];
  try {
    var reader = await open(b.archive.adapters.buffer(buffer));
    if (!reader) return { valid: true };
    entries = await reader.inspect();
  } catch (e) {
    // The magic bytes already said this is an archive, so a reader that cannot
    // walk it means malformed or unsupported structure. "Accept what we could
    // not read" is how an archive gets past a check a real extractor will
    // happily open; over-refusing an exotic but valid one is the cost.
    return { valid: false, reason: "Archive could not be read for inspection.", detail: e.code || "unreadable" };
  }

  var guardEntries = entries.map(toGuardEntry);

  // A link whose destination cannot be read is refused before the guard sees
  // it. A tar carries the destination in its header; a ZIP stores it in the
  // entry body, where the reader's entry list has no field for it — so the
  // guard is handed a null target, finds nothing to object to, and returns ok.
  // A ZIP symlink pointing anywhere at all would pass the check that exists to
  // stop exactly that, while its tar equivalent was caught.
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

// The types rendered inline at serve time that can also be magic-verified. The
// serve-time gate reads the STORED mimeType, which is whatever the client
// advertised — so a file declared as an inline type whose bytes are something
// else could be steered into an inline render. safeServeMime binds the stored
// type to the sniffed reality: a mismatch is stored as an octet-stream, which
// forces a download, and is never rejected outright. SVG is absent because it
// has no magic bytes and always routes to the sanitizer.
var INLINE_SNIFFABLE_MIME = new Set([
  "application/pdf", "image/gif", "image/jpeg", "image/png", "image/webp",
]);

function safeServeMime(declaredMime, buffer) {
  if (!declaredMime || typeof declaredMime !== "string") return "application/octet-stream";

  // Screen the declared type first. Only the inline types below are sniff-bound;
  // every other declared type is stored and later written as a Content-Type
  // header. The multipart parser preserves a field byte for byte, carriage
  // returns included, so "text/plain\r\nX-Injected: 1" reached writeHead — which
  // refuses it. Node stops the header injection; what it cannot stop is the
  // throw recurring on every later download, so an anonymous upload could make
  // one file permanently unfetchable while its counter kept incrementing.
  var mimeCheck = b.guardMime.validate(declaredMime);
  if (!mimeCheck || !mimeCheck.ok) return "application/octet-stream";

  if (!INLINE_SNIFFABLE_MIME.has(declaredMime)) return declaredMime;
  if (!buffer || buffer.length < 4) return "application/octet-stream";
  var sniffed = b.fileType.detect(buffer);
  return (sniffed && sniffed.mime === declaredMime) ? declaredMime : "application/octet-stream";
}

module.exports = { validateFile, validateChunk, validateBundleLimits, detectContentType, validateMagicBytes, validateArchive, safeServeMime };
