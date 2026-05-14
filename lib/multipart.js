/**
 * HermitStash multipart adapter over `b.parsers.multipart`.
 *
 * blamejs streams each part to a tmp file (`opts.tmpDir`) and returns
 * `{ field, filename, mimeType, path, size, hash }`. HS's existing
 * upload pipeline (`handleFileUpload`, `validateMagicBytes`,
 * `fileService.saveAndCreateFileRecord`, `storage.saveFile`) all
 * consume in-memory Buffers under the legacy field names
 * (`{ fieldname, filename, data, mimetype, size }`). We pre-buffer
 * here at the parse boundary and rename the keys, so downstream
 * handlers don't change.
 *
 * blamejs's standalone parser intentionally leaves tmp-file cleanup
 * to the caller (line 1481 of body-parser.js). We unlink immediately
 * after reading the buffer, so a route that throws between parse and
 * downstream handler never leaves an orphaned upload on disk.
 *
 * Free upgrade: blamejs computes a SHA3-512 hash of the bytes-as-
 * uploaded during the stream. We surface it as `file.hash` so any
 * downstream code that needs a checksum can read it directly instead
 * of running another sha3 pass over the buffer.
 *
 * Long-term direction: refactor the upload pipeline to accept paths
 * or streams end-to-end (`storage.saveFile` reading from `file.path`,
 * `validateMagicBytes` reading the first 256 bytes via fs.read) and
 * delete the pre-buffer step here. Until then this adapter is the
 * minimum-cost path that picks up blamejs's RFC 7578 / RFC 5987 /
 * RFC 6266 / POISONED_KEYS / HPE_* / per-file size cap protections.
 */
"use strict";

var nodeFs = require("node:fs");
var b = require("./vendor/blamejs");

async function parseMultipart(req, maxSize) {
  var raw = await b.parsers.multipart(req, {
    maxBytes:      maxSize,
    fileSize:      maxSize,
    mimeAllowlist: null,         // routes/uploadValidator do mime+magic checks downstream
  });

  var files = new Array(raw.files.length);
  for (var i = 0; i < raw.files.length; i++) {
    var f = raw.files[i];
    var data;
    try {
      data = nodeFs.readFileSync(f.path);
    } finally {
      try { nodeFs.unlinkSync(f.path); } catch (_e) { /* tmp may already be gone (parser cleanup race) — best-effort */ }
    }
    files[i] = {
      fieldname: f.field,
      filename:  f.filename,
      data:      data,
      mimetype:  f.mimeType,
      size:      f.size,
      hash:      f.hash,
    };
  }
  return { fields: raw.fields, files: files };
}

module.exports = { parseMultipart: parseMultipart };
