/**
 * HermitStash multipart adapter over `b.parsers.multipart`.
 *
 * blamejs parses each part in memory (`storage: "memory"`) and returns
 * `{ field, filename, mimeType, buffer, size, hash }`. HS's upload
 * pipeline (`handleFileUpload`, `validateMagicBytes`,
 * `fileService.saveAndCreateFileRecord`, `storage.saveFile`) consumes
 * in-memory Buffers under the legacy field names
 * (`{ fieldname, filename, data, mimetype, size }`), so we rename the
 * keys at the parse boundary — downstream handlers don't change.
 *
 * Memory mode keeps the uploaded plaintext in RAM for the life of the
 * request and never lands it on the local filesystem. The disk-mode
 * default streams each part to `os.tmpdir()` before HS encrypts it,
 * putting unencrypted user content at rest for the request duration —
 * memory mode removes that window. Peak memory is unchanged: the
 * downstream pipeline already buffers the whole file.
 *
 * Free upgrade: blamejs computes a SHA3-512 hash of the bytes as they
 * are uploaded during the parse. We surface it as `file.hash` so any
 * downstream code that needs a checksum can read it directly instead of
 * running another sha3 pass over the buffer.
 *
 * Large uploads that exceed the single-request path use the chunked
 * upload endpoints (`storage.saveChunk`), not this adapter.
 */
"use strict";

var b = require("./vendor/blamejs");

async function parseMultipart(req, maxSize) {
  var raw = await b.parsers.multipart(req, {
    maxBytes:      maxSize,
    fileSize:      maxSize,
    mimeAllowlist: null,        // routes/uploadValidator do mime+magic checks downstream
    storage:       "memory",    // uploaded plaintext stays in RAM — never streamed to os.tmpdir before HS encrypts it (0.17.15)
  });

  var files = new Array(raw.files.length);
  for (var i = 0; i < raw.files.length; i++) {
    var f = raw.files[i];
    files[i] = {
      fieldname: f.field,
      filename:  f.filename,
      data:      f.buffer,      // memory mode: the bytes are the in-RAM buffer (f.path is null)
      mimetype:  f.mimeType,
      size:      f.size,
      hash:      f.hash,
    };
  }
  return { fields: raw.fields, files: files };
}

module.exports = { parseMultipart: parseMultipart };
