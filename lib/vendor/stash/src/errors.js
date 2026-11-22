// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
/**
 * @module     stash.errors
 * @nav        Core
 * @title      Errors
 * @order      30
 * @slug       errors
 *
 * @intro
 *   Every failure StashJS reports is a typed error with a stable `.code`.
 *   Consumers branch on the code, never on the message text: messages are
 *   free to improve between patches, codes are frozen. All classes extend
 *   `StashError`, so `err instanceof StashError` separates a stash verdict
 *   from an unrelated bug.
 *
 *   No message ever contains a ref, a `meta` value, or a filesystem path
 *   (the CWE-209 / CWE-532 exposure classes). A ref is a capability, and an
 *   error that echoes one into a log file has leaked it.
 *
 * @card
 *   Typed error classes with stable codes: the fail-closed verdict surface
 *   of the store.
 */

/** Base class for every StashJS error. Subclasses fix a stable string `code` and a capability-free default message. */
export class StashError extends Error {
  constructor(message) {
    super(message);
    this.name = new.target.name;
  }
}

/** Unknown or expired ref. Code: ENOREF. */
export class RefNotFound extends StashError {
  code = "ENOREF";
  constructor(message = "no entry for that ref") {
    super(message);
  }
}

/** A concurrent pop already claimed the entry. Code: ECLAIMED. */
export class RefClaimed extends StashError {
  code = "ECLAIMED";
  constructor(message = "entry already claimed by a concurrent pop") {
    super(message);
  }
}

/** Blob bytes no longer match the recorded digest. Code: EINTEGRITY. */
export class IntegrityError extends StashError {
  code = "EINTEGRITY";
  constructor(message = "blob bytes do not match the recorded digest") {
    super(message);
  }
}

/** maxSize crossed mid-stream. Code: E2BIG. */
export class SizeExceeded extends StashError {
  code = "E2BIG";
  constructor(message = "entry exceeds the configured maxSize") {
    super(message);
  }
}

/** maxEntries / maxTotal reached; the push was refused. Code: EFULL. */
export class StashFull extends StashError {
  code = "EFULL";
  constructor(message = "stash is full; push refused") {
    super(message);
  }
}

/** Malformed ref string; refused before any storage access. Code: EBADREF. */
export class InvalidRef extends StashError {
  code = "EBADREF";
  constructor(message = "malformed ref") {
    super(message);
  }
}
