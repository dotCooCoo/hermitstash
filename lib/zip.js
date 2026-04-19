var zlib = require("zlib");
var { promisify } = require("util");
var deflateRawAsync = promisify(zlib.deflateRaw);

/**
 * Minimal ZIP writer that streams to a writable.
 * Supports Deflate compression. No dependencies.
 */
class ZipWriter {
  constructor(output) {
    this.output = output;
    this.entries = [];
    this.offset = 0;
  }

  _write(buf) {
    this.output.write(buf);
    this.offset += buf.length;
  }

  _dosDate(date) {
    var d = date || new Date();
    var time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
    var day = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
    return { time, date: day };
  }

  async addFile(name, dataOrStream) {
    // Sanitize entry name to prevent Zip Slip path traversal
    name = String(name || "file")
      .split(/[/\\]+/).filter(function (s) { return s && s !== "." && s !== ".."; }).join("/")
      .replace(/^\/+/, "");
    if (!name) name = "file";
    var buf;
    if (Buffer.isBuffer(dataOrStream)) {
      buf = dataOrStream;
    } else {
      // Read stream to buffer
      var chunks = [];
      for await (const chunk of dataOrStream) chunks.push(chunk);
      buf = Buffer.concat(chunks);
    }

    var crc = crc32(buf);
    // async deflate so large compressible files don't stall the event loop.
    // The ZIP local header format requires knowing CRC + sizes before the
    // payload, so we still buffer the full file — cap is enforced by the
    // operator's maxFileSize upstream.
    var compressed = await deflateRawAsync(buf);
    var useDeflate = compressed.length < buf.length;
    var data = useDeflate ? compressed : buf;

    var nameBytes = Buffer.from(name, "utf8");
    var { time, date } = this._dosDate();
    var headerOffset = this.offset;

    // Local file header
    var local = Buffer.alloc(30 + nameBytes.length);
    local.writeUInt32LE(0x04034b50, 0);       // signature
    local.writeUInt16LE(20, 4);                // version needed
    local.writeUInt16LE(0, 6);                 // flags
    local.writeUInt16LE(useDeflate ? 8 : 0, 8); // method
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);      // compressed
    local.writeUInt32LE(buf.length, 22);       // uncompressed
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);                // extra length
    nameBytes.copy(local, 30);

    this._write(local);
    this._write(data);

    this.entries.push({
      nameBytes,
      crc,
      compressedSize: data.length,
      uncompressedSize: buf.length,
      method: useDeflate ? 8 : 0,
      time,
      date,
      offset: headerOffset,
    });
  }

  finalize() {
    var cdStart = this.offset;

    for (var e of this.entries) {
      var cd = Buffer.alloc(46 + e.nameBytes.length);
      cd.writeUInt32LE(0x02014b50, 0);          // central dir signature
      cd.writeUInt16LE(20, 4);                   // version made by
      cd.writeUInt16LE(20, 6);                   // version needed
      cd.writeUInt16LE(0, 8);                    // flags
      cd.writeUInt16LE(e.method, 10);
      cd.writeUInt16LE(e.time, 12);
      cd.writeUInt16LE(e.date, 14);
      cd.writeUInt32LE(e.crc, 16);
      cd.writeUInt32LE(e.compressedSize, 20);
      cd.writeUInt32LE(e.uncompressedSize, 24);
      cd.writeUInt16LE(e.nameBytes.length, 28);
      cd.writeUInt16LE(0, 30);                   // extra
      cd.writeUInt16LE(0, 32);                   // comment
      cd.writeUInt16LE(0, 34);                   // disk start
      cd.writeUInt16LE(0, 36);                   // internal attrs
      cd.writeUInt32LE(0, 38);                   // external attrs
      cd.writeUInt32LE(e.offset, 42);
      e.nameBytes.copy(cd, 46);
      this._write(cd);
    }

    var cdSize = this.offset - cdStart;

    // End of central directory
    var eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(0, 4);                    // disk
    eocd.writeUInt16LE(0, 6);                    // disk start
    eocd.writeUInt16LE(this.entries.length, 8);
    eocd.writeUInt16LE(this.entries.length, 10);
    eocd.writeUInt32LE(cdSize, 12);
    eocd.writeUInt32LE(cdStart, 16);
    eocd.writeUInt16LE(0, 20);                   // comment length
    this._write(eocd);

    this.output.end();
  }
}

// CRC-32 (IEEE)
var crcTable = new Uint32Array(256);
for (var i = 0; i < 256; i++) {
  var c = i;
  for (var j = 0; j < 8; j++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  crcTable[i] = c;
}

function crc32(buf) {
  var crc = 0xffffffff;
  for (var i = 0; i < buf.length; i++) crc = crcTable[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

module.exports = { ZipWriter };
