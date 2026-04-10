const zlib = require("zlib");

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
    const d = date || new Date();
    const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
    const day = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
    return { time, date: day };
  }

  async addFile(name, dataOrStream) {
    let buf;
    if (Buffer.isBuffer(dataOrStream)) {
      buf = dataOrStream;
    } else {
      // Read stream to buffer
      const chunks = [];
      for await (const chunk of dataOrStream) chunks.push(chunk);
      buf = Buffer.concat(chunks);
    }

    const crc = crc32(buf);
    const compressed = zlib.deflateRawSync(buf);
    const useDeflate = compressed.length < buf.length;
    const data = useDeflate ? compressed : buf;

    const nameBytes = Buffer.from(name, "utf8");
    const { time, date } = this._dosDate();
    const headerOffset = this.offset;

    // Local file header
    const local = Buffer.alloc(30 + nameBytes.length);
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
    const cdStart = this.offset;

    for (const e of this.entries) {
      const cd = Buffer.alloc(46 + e.nameBytes.length);
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

    const cdSize = this.offset - cdStart;

    // End of central directory
    const eocd = Buffer.alloc(22);
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
const crcTable = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  crcTable[i] = c;
}

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = crcTable[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

module.exports = { ZipWriter };
