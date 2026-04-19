/**
 * Parse multipart/form-data and JSON bodies from raw requests.
 */

// Shared body accumulator — used by both parsers
function accumulateBody(req, maxSize) {
  return new Promise((resolve, reject) => {
    var chunks = [], total = 0;
    req.on("data", (c) => {
      total += c.length;
      if (total > maxSize) { req.destroy(); return reject(new Error("Body too large — exceeds limit")); }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/**
 * Parse multipart/form-data from a raw request.
 * Returns { fields: { name: value }, files: [{ fieldname, filename, data, mimetype, size }] }
 */
function parseMultipart(req, maxSize) {
  return accumulateBody(req, maxSize).then((buf) => {
    const contentType = req.headers["content-type"] || "";
    if (!contentType.includes("multipart/form-data")) throw new Error("Not multipart/form-data");
    const boundaryMatch = contentType.match(/boundary=(.+?)(?:;|$)/);
    if (!boundaryMatch) throw new Error("No boundary found");
    const boundary = boundaryMatch[1].trim();

    const result = { fields: {}, files: [] };
    const sep = Buffer.from("--" + boundary);

    let pos = 0;
    while (pos < buf.length) {
      const start = buf.indexOf(sep, pos);
      if (start === -1) break;
      const nextStart = buf.indexOf(sep, start + sep.length + 2);
      if (nextStart === -1) break;

      let partStart = start + sep.length;
      if (buf[partStart] === 0x0d && buf[partStart + 1] === 0x0a) partStart += 2;

      const partBuf = buf.slice(partStart, nextStart);
      const headerEnd = partBuf.indexOf(Buffer.from("\r\n\r\n"), 0);
      if (headerEnd === -1) { pos = nextStart; continue; }

      const headerStr = partBuf.slice(0, headerEnd).toString("utf8");
      const body = partBuf.slice(headerEnd + 4);
      const bodyClean = body.length >= 2 && body[body.length - 2] === 0x0d && body[body.length - 1] === 0x0a
        ? body.slice(0, body.length - 2) : body;

      const nameMatch = headerStr.match(/name="([^"]+)"/);
      const filenameMatch = headerStr.match(/filename="([^"]+)"/);
      const ctMatch = headerStr.match(/Content-Type:\s*(.+)/i);

      if (filenameMatch && nameMatch) {
        result.files.push({
          fieldname: nameMatch[1],
          filename: filenameMatch[1],
          data: bodyClean,
          mimetype: ctMatch ? ctMatch[1].trim() : "application/octet-stream",
          size: bodyClean.length,
        });
      } else if (nameMatch) {
        result.fields[nameMatch[1]] = bodyClean.toString("utf8");
      }
      pos = nextStart;
    }
    return result;
  });
}

/**
 * Parse JSON body from request
 */
function parseJson(req, maxSize) {
  return accumulateBody(req, maxSize || 1048576).then((buf) => {
    try { return JSON.parse(buf.toString()); } catch { return {}; }
  });
}

module.exports = { parseMultipart, parseJson };
