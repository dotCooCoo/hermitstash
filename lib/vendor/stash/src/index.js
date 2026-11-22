// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
//
// The public surface: the Stash policy class and the typed error set. Backends
// load from their own subpath so a bundle carries only the storage it uses.

import pkg from "../package.json" with { type: "json" };

export { Stash } from "./stash.js";
export {
  StashError,
  RefNotFound,
  RefClaimed,
  IntegrityError,
  SizeExceeded,
  StashFull,
  InvalidRef,
} from "./errors.js";

export const version = pkg.version;
