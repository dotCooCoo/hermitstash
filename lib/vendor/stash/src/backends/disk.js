// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
/**
 * @module     stash.backends
 *
 * (Continuation block: page metadata lives with the memory backend; this
 * file's primitives render on the same page.)
 */

import { randomBytes } from "node:crypto";
import { constants as FS } from "node:fs";
import { link, lstat, lutimes, mkdir, open, readdir, realpath, rename, rm } from "node:fs/promises";
import { join, resolve } from "node:path";

import { C } from "../constants.js";
import { DEFAULT_DIGEST, algoOf, digestHash, finalize } from "../digest.js";
import { assertShape, assertTombstoneShape, spend } from "../entry.js";
import { IntegrityError, InvalidRef, RefClaimed, RefNotFound } from "../errors.js";
import { assertValid, constantTimeEqual, isValid } from "../ref.js";
import { options } from "../validate.js";

// The disk layout's required directories, in one place: #init creates every one and the
// CLI's layout pre-check validates a root against THIS set, so a partial root is refused.
export const SUBDIRS = ["blobs", "meta", "claims", "tombstones"];

// The sidecar naming rule and its ONE owner: meta/ and tombstones/ hold "<ref>.json" per
// entry. These names become paths, so the rule is containment-adjacent and lands once.
const SIDECAR_EXT = ".json";

function _sidecarName(id) {
  return id + SIDECAR_EXT;
}

// Null when `name` is not a sidecar. Does NOT validate the id: verify's audits must keep
// walking and record a finding instead of throwing.
function _sidecarId(name) {
  return name.endsWith(SIDECAR_EXT) ? name.slice(0, -SIDECAR_EXT.length) : null;
}

// For paths that cannot continue on a malformed name. The layout is this backend's OWN
// output, so a name that is not "<ref>.json" is a damaged store, not a caller error.
function _requireSidecarId(name) {
  const id = _sidecarId(name);
  if (id === null || !isValid(id)) throw new IntegrityError("store layout is damaged");
  return id;
}

// Far above any legitimate sidecar; a larger one is rejected unread, never parsed.
const MAX_SIDECAR_BYTES = 64 * C.BYTES.KIB;

// A grave is tens of bytes; a larger one is rejected unread (parser DoS, CWE-770/400).
const MAX_TOMBSTONE_BYTES = C.BYTES.KIB;

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;

// A blob write is issued in units of this size. Each write is synchronous (O_DSYNC below),
// so a source that yields small chunks would otherwise pay one device flush per chunk.
const WRITE_STAGE_BYTES = C.BYTES.MIB;

// Bound on remove()'s in-process exactly-once witness (#reaped). Far above any real
// concurrent-reap window, so an evicted id's re-remove reads ENOENT.
const REAP_MEMO = 4096;

// A stored file is read through its own descriptor: open once, verify it, read from that
// same handle, so no path is re-resolved between check and use (CWE-367). O_NOFOLLOW
// refuses a symlink at open on POSIX. O_NONBLOCK guards the open itself: a blob swapped
// for a writerless FIFO parks an O_RDONLY open FOREVER before fstat can reject it. Both
// are inert on regular files and 0 on Windows, which has no unprivileged FIFO.
const READ_FLAGS = FS.O_RDONLY | (FS.O_NOFOLLOW || 0) | (FS.O_NONBLOCK || 0);
// Every write reaches stable storage before it returns. O_DSYNC is set at open, a path
// operation the permission model checks against the write grant; FileHandle.sync() acts
// on a descriptor, which the permission model refuses outright (Node 24.22.0 and later).
// Windows maps O_DSYNC to write-through. A platform without it fails loudly at import
// rather than writing without durability.
const DSYNC = FS.O_DSYNC;
if (!Number.isInteger(DSYNC) || DSYNC === 0) {
  throw new Error("DiskBackend requires O_DSYNC, which this platform does not provide");
}
// A tmp file: create, refuse an existing name, write-only, synchronous writes.
const CREATE_FLAGS = FS.O_WRONLY | FS.O_CREAT | FS.O_EXCL | DSYNC;
// Plus O_RDWR for the in-place sidecar rewrite, and deliberately NO O_CREAT: consumeRead
// debits an EXISTING sidecar and must never recreate one a drop removed (SPEC 4.2).
const WRITE_FLAGS = FS.O_RDWR | (FS.O_NOFOLLOW || 0) | (FS.O_NONBLOCK || 0) | DSYNC;

// Windows lacks O_NOFOLLOW (0 above), so a post-open lstat cross-checks the name instead.
// The descriptor is already bound, so that lstat can only REJECT, never redirect a read.
const SYMLINK_GUARD_NEEDED = (FS.O_NOFOLLOW || 0) === 0;

// True for ENOENT, rethrows every other errno: the one place "file not found" becomes a
// fact instead of a failure. Any other errno is an fs fault and must stay loud.
function _absent(err) {
  if (err && err.code === "ENOENT") return true;
  throw err;
}

// Windows refuses a rename/link/unlink with EPERM/EACCES/EBUSY while a handle lingers, for
// a few event-loop turns, so a bounded backoff clears it (inert on POSIX). Only these
// transient codes retry: EEXIST and ENOENT are verdicts for the caller.
const FS_RETRY_LIMIT = 50;
const FS_RETRY_DELAY_MS = 4;
const TRANSIENT_FS_CODES = new Set(["EPERM", "EACCES", "EBUSY"]);
async function _retryTransient(fn) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await fn();
    } catch (err) {
      if (!err || !TRANSIENT_FS_CODES.has(err.code) || attempt >= FS_RETRY_LIMIT) throw err;
      await new Promise((resolve) => setTimeout(resolve, FS_RETRY_DELAY_MS));
    }
  }
}

// Loop over short writes: one write() can resolve after fewer than `length` bytes, and a
// truncated sidecar or blob reads back as corruption. Bytes go to `position + written`, so
// the loop is offset-correct for a fresh file and an in-place rewrite alike.
export async function _writeAll(fh, bytes, position) {
  let written = 0;
  while (written < bytes.length) {
    const { bytesWritten } = await fh.write(
      bytes,
      written,
      bytes.length - written,
      position + written,
    );
    if (bytesWritten === 0) throw new IntegrityError("store write made no progress");
    written += bytesWritten;
  }
}

// ELOOP (a symlink refused at open), EISDIR, or ENXIO (a device or FIFO with no peer) is
// store tampering, not absence: a blob or sidecar is a regular file.
function _openTamper(err) {
  return err && (err.code === "ELOOP" || err.code === "EISDIR" || err.code === "ENXIO");
}

// Does an open descriptor still speak for the name it was opened through? `opened` is the
// fstat the read draws from, `named` a no-follow lstat: a symlink traversed at open, or a
// name swapped after it, makes them different objects.
export function descriptorMatchesName(opened, named) {
  return !named.isSymbolicLink() && sameFile(opened, named);
}

// Do two fs.Stats describe the SAME on-disk object? Declared ONCE so no path re-inlines a
// dev+ino check that drifts. Windows synthesizes ino from the NTFS index and can report 0
// for distinct files under parallel I/O, colliding them at {dev, ino:0}, so size and
// birthtimeMs are ANDed on: they only make the predicate MORE selective.
// @enforced-by guard-shape-reinlined
// @guard-shape \.ino\s*===
export function sameFile(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.birthtimeMs === b.birthtimeMs;
}

// The fallback swap guard where the platform lacks O_NOFOLLOW. A symlink traversed at
// open, or a name SWAPPED after it, is refused as corruption; a name that VANISHED is a
// concurrent REMOVAL, not a swap, so it reports absence. Either way #openStored closes the
// handle unread, so no traversed descriptor is ever served.
export async function verifyDescriptorAgainstName(openedStat, path, damaged) {
  let named;
  try {
    named = await lstat(path);
  } catch (err) {
    if (_absent(err)) return false; // vanished after open: a concurrent removal, never a served handle
    throw err;
  }
  if (!descriptorMatchesName(openedStat, named)) {
    throw new IntegrityError(damaged);
  }
  return true;
}

/**
 * @primitive  stash.backends.DiskBackend
 * @signature  new DiskBackend(opts) -> DiskBackend
 * @since      0.1.1
 * @status     stable
 * @spec       SPEC.md 9, SPEC.md 2.1, RFC 8259
 * @defends    CWE-22, CWE-59, CWE-367, CWE-377, CWE-770, path traversal (CWE-23)
 * @related    stash.backends.MemoryBackend, stash.Stash
 *
 * Construct the sidecar-file disk backend over `opts.root`. The layout is
 * `blobs/<id>` + `meta/<id>.json`, plus the claims and tombstones directories
 * the pop cycle and replication use; directories are mode 0700, files 0600, and
 * there is no central index to corrupt (a listing is a readdir plus sidecar
 * reads). Writes stream to a `.tmp` opened with `O_DSYNC`, then rename, so a reader never sees
 * a partial blob and a crash leaves an invisible orphan, never a half-entry.
 * The constructor does no I/O; the layout appears on first use.
 *
 * Containment is the backend's own job, not the sandbox's: the root is
 * realpath-pinned at init, every operation re-asserts that its directory still
 * resolves inside it, and a symlink where a blob belongs is refused rather than
 * followed. Reads verify the descriptor they draw from, so no path is
 * re-resolved between the check and the read.
 *
 * @example
 *   import { Stash } from "@blamejs/stash";
 *   import { DiskBackend } from "@blamejs/stash/backends/disk";
 *
 *   const stash = new Stash({ backend: new DiskBackend({ root: "./.stash" }) });
 */
export class DiskBackend {
  #root;
  #realRoot = null;
  #initPromise = null;
  #reaped = new Set(); // ids removed by this instance: the exactly-once witness Windows cannot give

  constructor(opts) {
    options(opts, "new DiskBackend", { allowed: ["root"] });
    if (typeof opts.root !== "string" || opts.root.length === 0) {
      throw new TypeError("new DiskBackend: root must be a non-empty path string");
    }
    this.#root = resolve(opts.root);
  }

  // The store's CANONICAL root path, so the single-writer-per-root guard (SPEC.md 6) sees
  // two Stash over one store as one writer even through different path spellings (a
  // symlink, a case variant) and neither recovery age-reclaims the other's live read.
  // A coordination KEY only: containment uses #containedDir, never this.
  get identity() {
    return "disk:" + (this.#realRoot ?? this.#root);
  }

  // Lazy, memoized layout creation. A failed init clears the memo so the next operation
  // retries instead of poisoning the instance forever.
  #init() {
    if (this.#initPromise === null) {
      this.#initPromise = (async () => {
        await mkdir(this.#root, { recursive: true, mode: DIR_MODE });
        for (const sub of SUBDIRS) {
          await mkdir(join(this.#root, sub), { recursive: true, mode: DIR_MODE });
        }
        this.#realRoot = await realpath(this.#root);
      })().catch((err) => {
        this.#initPromise = null;
        throw err;
      });
    }
    return this.#initPromise;
  }

  // The containment choke point: a subdirectory that no longer realpaths to its pinned
  // place under the root is an escape (InvalidRef), a vanished one is tampering. The
  // permission-model sandbox follows symlinks out of granted paths, so this is the actual
  // wall (SPEC.md 2.1, 9). It catches only links that persist across the check, so callers
  // resolve immediately before the write, never at the top of a long operation.
  // @enforced-by guard-shape-reinlined
  // @guard-shape \brealpath(?:Sync)?\s*\(
  async #containedDir(subdir) {
    await this.#init();
    const expected = join(this.#realRoot, subdir);
    let real;
    try {
      real = await realpath(expected);
    } catch (err) {
      if (err && err.code === "ENOENT") throw new IntegrityError("store layout is damaged");
      throw err;
    }
    if (real !== expected) throw new InvalidRef();
    return expected;
  }

  // The read discipline in one place: open, fstat the descriptor to confirm a regular
  // file, and where O_NOFOLLOW is missing cross-check its identity against the name. The
  // descriptor is already bound, so that check can only REJECT, never redirect the read.
  // It compares stats rather than re-checking the path because the OPENED OBJECT's
  // identity is the one thing a swap cannot change. ENOENT is the caller's chosen absence;
  // a non-regular, symlinked, or swapped name is `damaged`. The caller closes the handle.
  async #openStored(path, onAbsent, damaged, flags = READ_FLAGS) {
    let fh;
    try {
      fh = await open(path, flags);
    } catch (err) {
      if (err && err.code === "ENOENT") throw onAbsent();
      if (_openTamper(err)) throw new IntegrityError(damaged);
      throw err;
    }
    try {
      const opened = await fh.stat();
      if (!opened.isFile()) throw new IntegrityError(damaged);
      if (SYMLINK_GUARD_NEEDED && !(await verifyDescriptorAgainstName(opened, path, damaged))) {
        throw onAbsent(); // the name vanished after open: absence, never a served descriptor
      }
    } catch (err) {
      await fh.close();
      throw err;
    }
    return fh;
  }

  // Write bytes to <name>.tmp synchronously, rename into place. ANY failure after the handle
  // opens removes the tmp before rethrowing: a rejected write leaves no partial behind.
  async #writeAtomic(dir, name, bytes) {
    const tmpPath = join(dir, name + ".tmp");
    const finalPath = join(dir, name);
    const fh = await open(tmpPath, CREATE_FLAGS, FILE_MODE);
    try {
      try {
        await _writeAll(fh, bytes, 0);
      } finally {
        await fh.close();
      }
      await _retryTransient(() => rename(tmpPath, finalPath));
    } catch (err) {
      await rm(tmpPath, { force: true });
      throw err;
    }
    return finalPath;
  }

  // Streams to blobs/<id>.tmp computing size and digest as chunks pass, copying them into a
  // fixed staging buffer that is written synchronously each time it fills, renames into
  // place, THEN writes the sidecar, so a crash leaves either nothing or an invisible
  // blob orphan, never a served half-entry; any rejection removes the tmp. Containment is
  // re-asserted immediately before the sidecar write, because the blob stream runs as long
  // as its source chooses and a check taken before it would vouch for meta/ across that
  // whole window, letting a mid-stream swap land the sidecar outside the root (CWE-367).
  async write(id, source, entry) {
    assertValid(id);
    // The algorithm rides IN the entry's self-describing digest, so the policy layer's
    // selection arrives through the documented argument; a markerless entry takes
    // the store's default.
    const algo = algoOf(entry.digest) ?? DEFAULT_DIGEST;
    const blobDir = await this.#containedDir("blobs");
    const tmpPath = join(blobDir, id + ".tmp");
    const blobPath = join(blobDir, id);
    const hash = digestHash(algo);
    let size = 0;
    const fh = await open(tmpPath, CREATE_FLAGS, FILE_MODE);
    try {
      try {
        // The chunk is copied, not held: a source may reuse its buffer once it yields.
        const stage = Buffer.alloc(WRITE_STAGE_BYTES);
        let staged = 0;
        for await (const chunk of source) {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          hash.update(buf);
          let off = 0;
          while (off < buf.length) {
            const n = Math.min(buf.length - off, stage.length - staged);
            buf.copy(stage, staged, off, off + n);
            staged += n;
            off += n;
            if (staged === stage.length) {
              await _writeAll(fh, stage, size);
              size += staged;
              staged = 0;
            }
          }
        }
        if (staged > 0) {
          await _writeAll(fh, stage.subarray(0, staged), size);
          size += staged;
        }
      } finally {
        await fh.close();
      }
      // The just-closed tmp's handle can linger on Windows and fail this rename with a
      // transient EPERM/EACCES/EBUSY; _retryTransient absorbs it, inert on POSIX.
      await _retryTransient(() => rename(tmpPath, blobPath));
    } catch (err) {
      await rm(tmpPath, { force: true });
      throw err;
    }

    const stored = structuredClone(entry);
    stored.size = size;
    stored.digest = finalize(hash, algo);
    const sidecar = Buffer.from(JSON.stringify(stored), "utf8");
    if (sidecar.length > MAX_SIDECAR_BYTES) {
      await rm(blobPath, { force: true });
      // IntegrityError, not TypeError: write() also serves store()'s replication insert,
      // and a replicated entry is untrusted stored input, not a caller argument, so an
      // oversized sidecar is a content verdict, matching the READ side of the same bound.
      // The message names no verb: this line cannot tell which one called it.
      throw new IntegrityError("stored entry rejected: meta size");
    }
    try {
      const metaDir = await this.#containedDir("meta");
      await this.#writeAtomic(metaDir, _sidecarName(id), sidecar);
    } catch (err) {
      await rm(blobPath, { force: true });
      throw err;
    }
    return structuredClone(stored);
  }

  // The entry must exist (sidecar present and valid); a sidecar without its blob is
  // corruption. The blob is streamed from the descriptor the check ran on.
  async read(id) {
    const entry = await this.stat(id);
    const blobDir = await this.#containedDir("blobs");
    const blobPath = join(blobDir, entry.id);
    const damaged = "blob storage shape is damaged";
    // A blob missing from blobs/ under a present sidecar is NOT absence: it is a live claim
    // or corruption, so the RefNotFound sentinel is resolved by the catch, never surfaced.
    let fh;
    try {
      fh = await this.#openStored(blobPath, () => new RefNotFound(), damaged);
    } catch (err) {
      if (err instanceof RefNotFound) throw await this.#claimAwareAbsent(entry.id, damaged);
      throw err;
    }
    return fh.createReadStream();
  }

  // A no-follow lstat of claims/<id>: present means the blob moved there for a pop
  // (RefClaimed, being served, not gone); absent means no blob anywhere (IntegrityError).
  // RefClaimed keeps a concurrent reader from being told a popped entry is corrupt, the
  // cried-wolf failure that trains operators to ignore EINTEGRITY.
  async #claimAwareAbsent(id, damaged) {
    const claimsDir = await this.#containedDir("claims");
    try {
      await lstat(join(claimsDir, id));
      return new RefClaimed();
    } catch (err) {
      _absent(err);
      return new IntegrityError(damaged);
    }
  }

  // Sidecar first (the entry stops existing), then the blob; absent is a fact, not a
  // failure. The boolean is the WITNESS the exactly-once 'expired' and 'dropped' emits
  // depend on: true for EXACTLY ONE of two removes racing an entry. The FILESYSTEM cannot
  // supply it on Windows, where unlinking a sidecar a reader holds open only marks it for
  // deletion and the NAME LINGERS, so a second remove sees the name and also reports
  // success. `#reaped` keeps the witness in-process instead, claimed before the first
  // await, per instance (SPEC.md 4.3's exactly-once is per Stash, never cross-process).
  async remove(id) {
    assertValid(id);
    if (this.#reaped.has(id)) return false; // this instance already removed it (the fs name may still linger)
    this.#reaped.add(id); // claim BEFORE any await: atomic vs a concurrent remove of the same id
    if (this.#reaped.size > REAP_MEMO) this.#reaped.delete(this.#reaped.values().next().value); // evict oldest
    // ANY failure after the claim un-claims the marker, so a retry re-attempts rather than
    // being told "already removed" and skipping a still-present entry.
    try {
      // Contained immediately before its own op: a resolve-early/use-late gap is the same
      // directory TOCTOU write() closes (CWE-367).
      const metaDir = await this.#containedDir("meta");
      let had = true;
      try {
        // recursive so a tampered directory-shaped sidecar is reaped too, NO force so an
        // ENOENT is the "already gone" witness. rm never follows a final symlink (CWE-59).
        await _retryTransient(() => rm(join(metaDir, _sidecarName(id)), { recursive: true }));
      } catch (err) {
        if (_absent(err))
          had = false; // already gone: a cross-process removal, not ours
        else throw err;
      }
      const blobDir = await this.#containedDir("blobs");
      // force AND recursive: verify repair must also reap a directory-shaped blob.
      await rm(join(blobDir, id), { force: true, recursive: true });
      return had;
    } catch (err) {
      this.#reaped.delete(id); // a real fault above: roll the claim back for a retry
      throw err;
    }
  }

  // Strictly validated, and every check runs on the one descriptor the read draws from, so
  // a symlink swapped in cannot redirect the read to attacker-chosen metadata.
  async stat(id) {
    assertValid(id);
    const metaDir = await this.#containedDir("meta");
    const sidecarPath = join(metaDir, _sidecarName(id));
    const fh = await this.#openStored(
      sidecarPath,
      () => new RefNotFound(),
      "sidecar storage shape is damaged",
    );
    try {
      return await this.#readSidecar(fh, id);
    } finally {
      await fh.close();
    }
  }

  // Bounded read, parse under a corruption verdict, exact shape, constant-time id match.
  // Shared by stat and consumeRead, so reader validation and the debit cannot diverge.
  async #readSidecar(fh, id) {
    if ((await fh.stat()).size > MAX_SIDECAR_BYTES) {
      throw new IntegrityError("sidecar exceeds its size bound");
    }
    const raw = await fh.readFile("utf8");
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new IntegrityError("sidecar is not valid JSON");
    }
    assertShape(parsed, IntegrityError);
    if (!constantTimeEqual(parsed.id, id)) throw new IntegrityError("sidecar identity mismatch");
    return parsed;
  }

  // The single meta/ walk behind list() and listReconcilable(). Being readdir-then-stat,
  // an entry can be removed between the two steps, so a RefNotFound has left the listing
  // and is skipped in BOTH faces. The ONE difference is a CORRUPT sidecar: collectCorrupt
  // false rethrows, because silently dropping a damaged sidecar would hide corruption;
  // true collects the id and keeps walking, so one rotten sidecar cannot halt replication
  // of the healthy entries. Structural damage and fs FAULTS stay loud in both faces.
  async #scanEntries(collectCorrupt) {
    const metaDir = await this.#containedDir("meta");
    const entries = [];
    const corrupt = [];
    for (const name of await readdir(metaDir)) {
      if (name.endsWith(".tmp")) continue;
      const id = _requireSidecarId(name);
      let entry;
      try {
        entry = await this.stat(id);
      } catch (err) {
        if (err instanceof RefNotFound) continue; // removed between readdir and stat
        if (collectCorrupt && err instanceof IntegrityError) {
          // A STRUCTURAL layout fault (meta/ swapped mid-scan) must stay loud even here,
          // so re-resolve: damaged now means this was not a per-entry corruption.
          await this.#containedDir("meta"); // throws (loud) if the layout is damaged
          corrupt.push(id);
          continue;
        }
        throw err; // loud-not-lossy, and every fs fault, in both faces
      }
      entries.push(entry);
    }
    return { entries, corrupt };
  }

  // Loud, not lossy: a sidecar that fails validation fails the listing, because silently
  // skipping corruption would hide it.
  async list() {
    return (await this.#scanEntries(false)).entries;
  }

  // The reconciliation-grade listing (SPEC.md 4.4): healthy entries an anti-entropy pass
  // can replicate, plus the ref ids whose sidecars are too damaged to read. Where list()
  // aborts on a corrupt sidecar and stalls replication of every healthy entry, this face
  // keeps enumerating; the caller routes `corrupt` to verify({ repair: true }).
  async listReconcilable() {
    return this.#scanEntries(true);
  }

  // The stash-wide limit pre-check reads this aggregate rather than parsing every sidecar.
  // `bytes` counts each blob PLUS its sidecar file PLUS any sidecar-less claim or orphan
  // blob still occupying the shelf, so no caller slips past `maxTotal` with tiny blobs and
  // huge `meta`, nor by hoarding crashed removes' orphans. A `.tmp` in meta/, blobs/ or
  // claims/ (a write that died with its process) counts too, fresh or aged, until verify
  // reaps it; tombstones/ tmps stay out, as graves do. A foreign name in ANY layout
  // dir is loud. The sidecar is stat'd BEFORE the entry is counted, so one that vanished
  // mid-scan is skipped rather than counted as an entry with zero bytes.
  async stats() {
    const metaDir = await this.#containedDir("meta");
    const blobDir = await this.#containedDir("blobs");
    const claimsDir = await this.#containedDir("claims");
    let entries = 0;
    let bytes = 0;
    const counted = new Set();
    for (const name of await readdir(metaDir)) {
      if (name.endsWith(".tmp")) {
        bytes += await this.#tmpBytes(metaDir, name);
        continue;
      }
      const id = _requireSidecarId(name);
      let sidecarSize;
      try {
        sidecarSize = (await lstat(join(metaDir, name))).size; // the sidecar file
      } catch (err) {
        _absent(err); // the sidecar vanished mid-scan -> not a live entry; skip it
        continue; // whole, the same tolerance list() holds: never count it
      }
      entries += 1;
      bytes += sidecarSize;
      counted.add(id); // this id's blob (in blobs/ or claims/) is accounted here
      try {
        bytes += (await lstat(join(blobDir, id))).size; // the blob
      } catch (err) {
        _absent(err); // absent from blobs/: either vanished, or claimed into claims/,
        try {
          bytes += (await lstat(join(claimsDir, id))).size; // where the blob still
        } catch (e2) {
          _absent(e2); // occupies the store, so its bytes are counted there
        }
      }
    }
    let claimed = 0;
    for (const name of await readdir(claimsDir)) {
      if (name.endsWith(".tmp")) {
        bytes += await this.#tmpBytes(claimsDir, name);
        continue;
      }
      if (!isValid(name)) throw new IntegrityError("store layout is damaged");
      claimed += 1;
      // A claim whose sidecar is gone has no meta/ entry to count it, but its blob still
      // occupies the store: repeated pop+drop+abandon would hoard invisible claim blobs.
      if (counted.has(name)) continue;
      counted.add(name); // account this claim's blob so the blobs/ walk cannot double-count a duplicate-link
      try {
        bytes += (await lstat(join(claimsDir, name))).size;
      } catch (err) {
        _absent(err); // vanished mid-scan (a concurrent restore or commit)
      }
    }
    // blobs/: an ORPHAN blob (a valid ref name with no sidecar and no claim, left by a
    // crashed remove) still occupies the store, so count it, or repeated crashed removes
    // hoard orphans every bounded push sees as free space.
    for (const name of await readdir(blobDir)) {
      if (name.endsWith(".tmp")) {
        bytes += await this.#tmpBytes(blobDir, name);
        continue;
      }
      if (!isValid(name)) throw new IntegrityError("store layout is damaged");
      if (counted.has(name)) continue; // already counted via its sidecar or its claim
      try {
        bytes += (await lstat(join(blobDir, name))).size;
      } catch (err) {
        _absent(err); // vanished mid-scan (a concurrent verify or drop)
      }
    }
    // tombstones/: their bytes are not part of the footprint, but the walk still refuses a
    // foreign name as every layout dir does.
    for (const name of await readdir(await this.#containedDir("tombstones"))) {
      if (name.endsWith(".tmp")) continue;
      // Called for its THROW, not its value: nothing here needs the id.
      _requireSidecarId(name);
    }
    return { entries, bytes, claimed };
  }

  // The size of one `.tmp` for stats(). A tmp whose rename landed mid-walk counts 0 here;
  // its bytes are then counted under the final name, or not at all if the walk passed it.
  // A tmp stat'd before its rename and then reached again under the final name is counted
  // twice; the total then reads high for that one call, which can refuse a bounded push.
  async #tmpBytes(dir, name) {
    try {
      return (await lstat(join(dir, name))).size;
    } catch (err) {
      _absent(err);
      return 0;
    }
  }

  // Stream-hash a blob with the ENTRY's own algorithm, so bit rot on a sha3-512 entry is
  // caught by re-hashing with sha3-512, in bounded chunks rather than a full-blob read.
  async #hashBlob(path, algo) {
    const fh = await this.#openStored(
      path,
      () => new RefNotFound(),
      "blob storage shape is damaged",
    );
    try {
      const hash = digestHash(algo);
      let size = 0;
      const buf = Buffer.allocUnsafe(64 * C.BYTES.KIB);
      for (;;) {
        const { bytesRead } = await fh.read(buf, 0, buf.length, null);
        if (bytesRead === 0) break;
        hash.update(buf.subarray(0, bytesRead));
        size += bytesRead;
      }
      return { size, digest: finalize(hash, algo) };
    } finally {
      await fh.close();
    }
  }

  // Destroy a damaged entry. remove() deletes the sidecar BEFORE the blob, so a crash
  // between them leaves an invisible blob orphan, never a served half-entry.
  async #condemn(id, kind, repaired) {
    await this.remove(id);
    repaired.push({ kind, id });
  }

  // Destroy a damaged entry ONLY if it is not claimed RIGHT NOW. The digest is verified by
  // an UNBOUNDED hash and a pop can claim the blob DURING it, so a claim flag read earlier
  // in the walk is already stale: a blob claimed meanwhile is a live mid-pop entry whose
  // damage is reported but which is NEVER condemned (CWE-362/367).
  async #condemnIfUnclaimed(id, kind, repaired) {
    if (await this.#isPresent(join(await this.#containedDir("claims"), id))) return; // claimed now: recovery owns it
    await this.#condemn(id, kind, repaired);
  }

  // Remove a NON-entry file (a foreign name, a stale .tmp), re-resolving its parent
  // immediately before the removal so a directory swap during the unbounded walk cannot
  // redirect the delete outside the root (CWE-367). force AND recursive: the shape may be
  // a tampered DIRECTORY repair must reap; rm never follows a final symlink (CWE-59).
  async #discard(subdir, name, kind, repaired) {
    await rm(join(await this.#containedDir(subdir), name), { force: true, recursive: true });
    repaired.push({ kind, id: null });
  }

  // lstat probe: present is true, ENOENT is false, any OTHER errno is an fs FAULT that
  // propagates. Re-checks a claim or sidecar LIVE at a condemnation decision (CWE-362).
  async #isPresent(path) {
    try {
      await lstat(path);
      return true;
    } catch (err) {
      _absent(err); // ENOENT -> genuinely absent; any other errno throws
      return false;
    }
  }

  // The ONE `.tmp` verdict for every layout dir. A FRESH `.tmp` is a live atomic write and
  // is spared, because deleting it would corrupt a running push (CWE-367); one AGED past
  // the grace is a crashed write's orphan, reported and, under repair, discarded.
  async #auditOrphanTmp(subdir, dir, name, now, opts, findings, repaired) {
    if (!name.endsWith(".tmp")) return false;
    let tmpStat = null;
    try {
      tmpStat = await lstat(join(dir, name));
    } catch (err) {
      _absent(err); // the rename landed mid-walk: a fault re-raises, ENOENT leaves tmpStat null
    }
    // A null tmpStat raced out from under us: still a .tmp, nothing left to age.
    if (tmpStat !== null && now - tmpStat.mtimeMs >= C.AUDIT.TMP_GRACE_MS) {
      findings.push({ kind: "orphan-tmp", id: null });
      if (opts.repair) await this.#discard(subdir, name, "orphan-tmp", repaired);
    }
    return true; // it WAS a .tmp: the caller skips it either way (never an entry)
  }

  // Audit the physical layout. Damage is a FINDING (returned); an fs FAULT THROWS, because
  // a walk error absorbed into a clean report is the fail-open-verify shape (CWE-392). Dry
  // by default; repair removes ONLY what it condemns (blob AND sidecar together), never a
  // stale claim (SPEC.md 6 recovery's job), and never bytes a live operation still owns
  // (CWE-367): a claim is re-checked LIVE, and an orphan blob is condemned only once AGED,
  // since a fresh one may be a push's pre-sidecar window. A foreign or tmp name reports
  // id: null, because verify never echoes a filename (SPEC.md 10).
  async verify(opts) {
    const now = Date.now();
    const findings = [];
    const repaired = [];
    const scanned = new Set(); // ref ids with a ref-shaped sidecar (an entry)

    // Every directory is re-resolved before each readdir, blob read, and unlink, never once
    // at the top: the hash walk is unbounded, so a directory vouched for once and reused
    // would carry a mid-walk swap through it (CWE-367).
    const metaDir = await this.#containedDir("meta");

    for (const name of await readdir(metaDir)) {
      if (await this.#auditOrphanTmp("meta", metaDir, name, now, opts, findings, repaired))
        continue; // an in-flight or orphaned sidecar write
      const id = _sidecarId(name);
      if (id === null || !isValid(id)) {
        findings.push({ kind: "foreign-file", id: null });
        if (opts.repair) await this.#discard("meta", name, "foreign-file", repaired);
        continue;
      }
      scanned.add(id);
      const blobDir = await this.#containedDir("blobs"); // re-resolved per entry, right before this entry's blob reads
      let entry;
      try {
        entry = await this.stat(id); // bounded read + assertShape + id match, free
      } catch (err) {
        if (err instanceof RefNotFound) continue; // vanished mid-walk (a concurrent drop)
        if (err instanceof IntegrityError) {
          // A vanished meta/ and a bad sidecar are both IntegrityError, so re-resolve to
          // disambiguate: the layout fault RE-THROWS rather than masking a fallen-over
          // walk as N spurious corrupt-sidecar findings (CWE-392).
          await this.#containedDir("meta");
          findings.push({ kind: "corrupt-sidecar", id });
          // A corrupt sidecar may belong to a CLAIMED entry (a crash mid consumeRead
          // rewrite): report the damage, but condemn only if it is not claimed now.
          if (opts.repair) await this.#condemnIfUnclaimed(id, "corrupt-sidecar", repaired);
          continue;
        }
        throw err; // an fs FAULT, never a finding
      }
      // Find the blob: normally blobs/<id>, but a pop may have claimed it into claims/<id>
      // after this walk began, so claims/ is re-checked LIVE. A claimed blob is still
      // digest-checked, but every condemn routes through #condemnIfUnclaimed, so one
      // claimed during the unbounded hash is never destroyed under the reader (CWE-362).
      let blobPath = join(blobDir, id);
      let blobStat;
      try {
        blobStat = await lstat(blobPath);
      } catch (err) {
        _absent(err); // absent from blobs/ (ENOENT); any other errno propagates
        blobPath = join(await this.#containedDir("claims"), id);
        try {
          blobStat = await lstat(blobPath);
        } catch (err2) {
          _absent(err2); // absent from claims/ too -> genuinely missing
          findings.push({ kind: "missing-blob", id });
          if (opts.repair) await this.#condemnIfUnclaimed(id, "missing-blob", repaired);
          continue;
        }
      }
      if (blobStat.size !== entry.size) {
        findings.push({ kind: "size-mismatch", id });
        if (opts.repair) await this.#condemnIfUnclaimed(id, "size-mismatch", repaired);
        continue;
      }
      let got;
      try {
        got = await this.#hashBlob(blobPath, algoOf(entry.digest));
      } catch (err) {
        if (err instanceof RefNotFound) continue; // vanished mid-walk (a claim committed / a drop)
        if (err instanceof IntegrityError) {
          // a symlink / non-regular blob, refused
          findings.push({ kind: "digest-mismatch", id });
          if (opts.repair) await this.#condemnIfUnclaimed(id, "digest-mismatch", repaired);
          continue;
        }
        throw err;
      }
      if (!constantTimeEqual(got.digest, entry.digest)) {
        findings.push({ kind: "digest-mismatch", id });
        if (opts.repair) await this.#condemnIfUnclaimed(id, "digest-mismatch", repaired);
      }
    }

    const blobScan = await this.#containedDir("blobs");
    for (const name of await readdir(blobScan)) {
      if (await this.#auditOrphanTmp("blobs", blobScan, name, now, opts, findings, repaired))
        continue; // an in-flight push or orphaned .tmp
      if (!isValid(name)) {
        findings.push({ kind: "foreign-file", id: null });
        if (opts.repair) await this.#discard("blobs", name, "foreign-file", repaired);
        continue;
      }
      if (scanned.has(name)) continue; // a sidecar in the meta snapshot vouches for it
      // write() renames the blob to its FINAL name BEFORE the sidecar lands, so an
      // in-flight push looks like an orphan by name alone. Condemn ONLY an AGED blob whose
      // sidecar and claim are BOTH absent LIVE, or a live push loses its bytes (CWE-367).
      let orphanStat;
      try {
        orphanStat = await lstat(join(blobScan, name));
      } catch (err) {
        _absent(err);
        continue;
      }
      if (now - orphanStat.mtimeMs < C.AUDIT.TMP_GRACE_MS) continue; // fresh: a possibly-in-flight push
      if (await this.#isPresent(join(await this.#containedDir("meta"), _sidecarName(name))))
        continue; // sidecar landed after the snapshot
      if (await this.#isPresent(join(await this.#containedDir("claims"), name))) continue; // claimed after the snapshot
      findings.push({ kind: "orphan-blob", id: name });
      if (opts.repair) await this.#condemn(name, "orphan-blob", repaired);
    }

    // claims/: stale claims are REPORTED, never repaired (deleting a restorable
    // claim would be data loss; SPEC.md 6 recovery owns resolution).
    const claimsDir = await this.#containedDir("claims");
    for (const name of await readdir(claimsDir)) {
      if (await this.#auditOrphanTmp("claims", claimsDir, name, now, opts, findings, repaired))
        continue; // an orphaned .tmp (claims/ writes none in normal flow)
      if (!isValid(name)) {
        findings.push({ kind: "foreign-file", id: null });
        if (opts.repair) await this.#discard("claims", name, "foreign-file", repaired);
        continue;
      }
      let claimStat;
      try {
        claimStat = await lstat(join(claimsDir, name));
      } catch (err) {
        _absent(err);
        continue;
      }
      if (now - claimStat.mtimeMs >= opts.claimTimeoutMs)
        findings.push({ kind: "stale-claim", id: name });
    }

    // tombstones/: the dir is audited for layout damage (a foreign name is loud, an aged
    // .tmp an orphan) AND each grave's CONTENTS through the parser prune() uses.
    const tombstonesDir = await this.#containedDir("tombstones");
    for (const name of await readdir(tombstonesDir)) {
      if (
        await this.#auditOrphanTmp("tombstones", tombstonesDir, name, now, opts, findings, repaired)
      )
        continue;
      const id = _sidecarId(name);
      if (id === null || !isValid(id)) {
        findings.push({ kind: "foreign-file", id: null });
        if (opts.repair) await this.#discard("tombstones", name, "foreign-file", repaired);
        continue;
      }
      // A grave whose CONTENTS fail the parser makes tombstones() and prune() loud with no
      // other repair path, and holds no restorable bytes, so verify condemns it.
      try {
        await this.#readTombstone(join(tombstonesDir, name), id);
      } catch (err) {
        if (err instanceof RefNotFound) continue; // vanished mid-scan (a concurrent prune)
        if (!(err instanceof IntegrityError)) throw err;
        findings.push({ kind: "corrupt-tombstone", id });
        if (opts.repair) {
          await this.removeTombstone(id);
          repaired.push({ kind: "corrupt-tombstone", id });
        }
      }
    }

    return { scanned: scanned.size, findings, repaired };
  }

  // FIRST-WRITE-WINS, race-safe. Two destroyers of ONE id can run concurrently with no
  // mutex, because drop takes no claim, so the commit cannot be #writeAtomic's shared tmp
  // plus rename: two writers collide on that tmp under O_EXCL, and rename silently
  // REPLACES on Windows, clobbering the first grave's destroyedAt (SPEC.md 4.2, 4.4).
  // Instead a UNIQUE tmp is `link`ed to the grave name: link NEVER overwrites, so a
  // racer's EEXIST IS the first write winning, and its tmp is a harmless orphan.
  async writeTombstone(id, tombstone) {
    assertValid(id);
    const dir = await this.#containedDir("tombstones");
    const finalPath = join(dir, _sidecarName(id));
    if (await this.#isPresent(finalPath)) return; // a grave already stands: first-write-wins
    // The policy layer hands an exact { id, destroyedAt, cause }, so serialize it whole.
    const bytes = Buffer.from(JSON.stringify(tombstone), "utf8");
    const tmpPath = join(dir, _sidecarName(id) + "." + randomBytes(8).toString("hex") + ".tmp");
    const fh = await open(tmpPath, CREATE_FLAGS, FILE_MODE);
    try {
      try {
        await _writeAll(fh, bytes, 0);
      } finally {
        await fh.close();
      }
      await _retryTransient(() => link(tmpPath, finalPath));
    } catch (err) {
      if (!(err && err.code === "EEXIST")) throw err; // a real fs fault: the tmp is reaped below
    } finally {
      await rm(tmpPath, { force: true }); // our unique tmp is transient whether we won or lost
    }
  }

  // Presence ONLY (lstat, no-follow): a grave, even a corrupt or symlinked one, refuses
  // resurrection, so store() need not parse it and a corrupt grave still blocks.
  async hasTombstone(id) {
    assertValid(id);
    return this.#isPresent(join(await this.#containedDir("tombstones"), _sidecarName(id)));
  }

  // Loud, not lossy (the list() discipline): a foreign name or a corrupt grave FAILS the
  // listing. One that vanished between the readdir and its read is no longer listed.
  async listTombstones() {
    const dir = await this.#containedDir("tombstones");
    const out = [];
    for (const name of await readdir(dir)) {
      if (name.endsWith(".tmp")) continue; // an in-flight grave write
      const id = _requireSidecarId(name);
      try {
        out.push(await this.#readTombstone(join(dir, name), id));
      } catch (err) {
        if (err instanceof RefNotFound) continue; // vanished mid-scan: no longer a grave
        throw err;
      }
    }
    return out;
  }

  // ttl pruning. force AND recursive so a tampered directory-shaped grave is reaped too.
  // Presence is read BEFORE the removal, because force swallows the ENOENT it needs.
  async removeTombstone(id) {
    assertValid(id);
    const path = join(await this.#containedDir("tombstones"), _sidecarName(id));
    const had = await this.#isPresent(path);
    await _retryTransient(() => rm(path, { force: true, recursive: true }));
    return had;
  }

  // The sidecar discipline on a grave: no-follow open, bounded read BEFORE parse, exact
  // shape plus id match. onAbsent is RefNotFound so a grave pruned mid-scan is tolerated.
  async #readTombstone(path, id) {
    const fh = await this.#openStored(
      path,
      () => new RefNotFound(),
      "tombstone storage shape is damaged",
    );
    try {
      if ((await fh.stat()).size > MAX_TOMBSTONE_BYTES)
        throw new IntegrityError("tombstone exceeds its size bound");
      let parsed;
      try {
        parsed = JSON.parse(await fh.readFile("utf8"));
      } catch {
        throw new IntegrityError("tombstone is not valid JSON");
      }
      assertTombstoneShape(parsed, IntegrityError);
      if (!constantTimeEqual(parsed.id, id))
        throw new IntegrityError("tombstone identity mismatch");
      return parsed;
    } finally {
      await fh.close();
    }
  }

  // Atomically claim the blob into claims/<id> and stream from there. The mutex is `link`,
  // NOT `rename`: link FAILS with EEXIST when a claim exists, so exactly one of two racing
  // pops wins, where rename would silently replace the destination and let both win on
  // Windows. The sidecar stays in meta/, so a claimed entry is a sidecar plus a claim.
  async claim(id) {
    assertValid(id);
    const blobDir = await this.#containedDir("blobs");
    const claimsDir = await this.#containedDir("claims");
    const claimPath = join(claimsDir, id);
    // The claim mutex (link) runs BEFORE reading the sidecar: a loser rejects RefClaimed at
    // the link without opening the sidecar the winner's consumeRead is rewriting.
    try {
      await _retryTransient(() => link(join(blobDir, id), claimPath));
    } catch (err) {
      // EEXIST: another pop claimed it. ENOENT: the blob left blobs/ (a committed pop, or
      // a drop), so disambiguate; never report not-found without checking the claim first.
      if (err && err.code === "EEXIST") throw new RefClaimed();
      if (err && err.code === "ENOENT") {
        try {
          await lstat(claimPath);
        } catch (probe) {
          _absent(probe);
          throw new RefNotFound();
        }
        throw new RefClaimed();
      }
      throw err;
    }
    await _retryTransient(() => rm(join(blobDir, id), { force: true }));
    // link does not touch mtime, so stamp claimedAt explicitly, or every claim on an older
    // entry looks instantly stale to recovery. lutimes, NOT utimes: a hostile blobs/<id>
    // symlink is hard-linked into claims/ as a link to the symlink, and a path utimes
    // would FOLLOW it and touch timestamps OUTSIDE the store. From here the blob lives
    // ONLY at claims/<id>, so a failure before a source is handed back would orphan a
    // claim that blocks later reads: undo it best-effort, then surface the failure.
    try {
      const claimedAt = Date.now();
      await lutimes(claimPath, new Date(claimedAt), new Date(claimedAt));
      const entry = await this.stat(id); // the winner reads the sidecar (present)
      const damaged = "claimed blob storage shape is damaged";
      const fh = await this.#openStored(claimPath, () => new IntegrityError(damaged), damaged);
      return { entry, source: fh.createReadStream() };
    } catch (err) {
      await this.restore(id).catch(() => {});
      throw err;
    }
  }

  // Return a claimed blob from claims/<id> to blobs/<id>. POSIX rename overwrites silently,
  // so an occupied blobs/<id> would resurrect destroyed data (SPEC.md 4.2 monotone) and is
  // refused unless the occupant is the SAME inode, which is an interrupted claim.
  async restore(id) {
    assertValid(id);
    const claimsDir = await this.#containedDir("claims");
    // A drop during the claim unlinks the sidecar, orphaning the claimed blob. Restoring
    // it would resurrect bytes for an entry that no longer exists (SPEC 4.2 monotone), so
    // finish the drop's destruction instead. A restore runs only after the read settled.
    const metaDir = await this.#containedDir("meta");
    try {
      await lstat(join(metaDir, _sidecarName(id)));
    } catch (err) {
      _absent(err);
      await rm(join(claimsDir, id), { force: true });
      throw new RefNotFound();
    }
    const blobDir = await this.#containedDir("blobs");
    const blobPath = join(blobDir, id);
    let occupant = null;
    try {
      occupant = await lstat(blobPath);
    } catch (err) {
      _absent(err); // blobs/<id> is free: proceed to the rename below
    }
    if (occupant) {
      // The SAME file as the claim means the process died after link() but before removing
      // the original name, so the entry is already live and the redundant claim name is
      // dropped. A DIFFERENT file is two blobs for one unique id: corruption, refused.
      let claimed;
      try {
        claimed = await lstat(join(claimsDir, id));
      } catch (err) {
        _absent(err);
        throw new RefNotFound();
      }
      if (sameFile(occupant, claimed)) {
        await rm(join(claimsDir, id), { force: true });
        return;
      }
      throw new IntegrityError("restore target is occupied");
    }
    try {
      await _retryTransient(() => rename(join(claimsDir, id), blobPath));
    } catch (err) {
      if (_absent(err)) throw new RefNotFound();
      throw err;
    }
    // Re-check the sidecar AFTER the move: the check above and this rename are not atomic,
    // so a drop in that window would leave the restored blob unreferenced and never
    // reclaimed by the claim-driven recovery scan, a permanent leak.
    try {
      await lstat(join(metaDir, _sidecarName(id)));
    } catch (err) {
      _absent(err);
      await rm(blobPath, { force: true });
      throw new RefNotFound();
    }
  }

  // Sidecar first, then the claimed blob, the same delete order as remove(), so a crash
  // between them leaves a claim without a sidecar, which recovery reads as an interrupted
  // commit and COMPLETES rather than restoring a sidecar-less blob. Idempotent by force.
  async commit(id) {
    assertValid(id);
    const metaDir = await this.#containedDir("meta");
    // recursive: a corrupt sidecar can be DIRECTORY-shaped, and recovery must still reap
    // it, or commit throws EISDIR, the claim stands, and every later verb re-fails.
    await rm(join(metaDir, _sidecarName(id)), { force: true, recursive: true });
    const claimsDir = await this.#containedDir("claims");
    // The claimed blob's read stream may have only just closed and its Windows handle can
    // linger, so absorb the transient EPERM rather than fail the commit.
    await _retryTransient(() => rm(join(claimsDir, id), { force: true, recursive: true }));
  }

  // The recovery scan's input. Same name discipline as list(): a foreign name is
  // corruption, a claim that vanished mid-scan is skipped. claimedAt is the stamped mtime.
  async listClaims() {
    const claimsDir = await this.#containedDir("claims");
    const out = [];
    for (const name of await readdir(claimsDir)) {
      if (name.endsWith(".tmp")) continue;
      if (!isValid(name)) throw new IntegrityError("store layout is damaged");
      let claimedAt;
      try {
        // Floor to integer milliseconds: mtimeMs is a float on sub-millisecond-precision
        // filesystems, but claimedAt is the integer-ms contract recovery compares.
        claimedAt = Math.floor((await lstat(join(claimsDir, name))).mtimeMs);
      } catch (err) {
        _absent(err);
        continue;
      }
      out.push({ id: name, claimedAt });
    }
    return out;
  }

  // Advisory: is a live claim held right now? A single lstat with no sidecar open, so a
  // contended reader rejects RefClaimed without opening the sidecar the claim-holder is
  // rewriting (an open reader blocks that rewrite on Windows and livelocks the holder).
  async isClaimed(id) {
    assertValid(id);
    return this.#isPresent(join(await this.#containedDir("claims"), id));
  }

  // Debit one read credit and return what is left. Only ever called while holding the
  // claim, the cross-process mutex, so no two readers race the decrement.
  async consumeRead(id) {
    assertValid(id);
    const metaDir = await this.#containedDir("meta");
    const sidecarPath = join(metaDir, _sidecarName(id));
    const damaged = "sidecar storage shape is damaged";
    // ONE descriptor for the read AND the rewrite: the open is the atomicity anchor. A
    // concurrent drop BEFORE it ENOENTs (the debit never recreates a dropped entry); one
    // AFTER unlinks the name while this descriptor keeps the nameless inode, so the debit
    // lands on a ghost (SPEC 4.2 monotone), where a tmp+rename would recreate the name the
    // drop just removed. Debiting before the caller restores the blob means a crash here
    // still leaves a decremented entry, so a completed drain is always paid for.
    const fh = await this.#openStored(sidecarPath, () => new RefNotFound(), damaged, WRITE_FLAGS);
    try {
      const next = spend(await this.#readSidecar(fh, id));
      const bytes = Buffer.from(JSON.stringify(next), "utf8");
      // A crash mid-write leaves a short sidecar the next read rejects as IntegrityError:
      // fail-closed and loud, never silently bad. spend() owns the readsLeft arithmetic.
      await fh.truncate(0);
      await _writeAll(fh, bytes, 0);
      return next.readsLeft;
    } finally {
      await fh.close();
    }
  }
}
