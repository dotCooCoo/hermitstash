// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * _codebase-shingle-worker — worker_threads entry point invoked by
 * testNoDuplicateCodeBlocks in codebase-patterns.test.js.
 *
 * Receives a shard via workerData: {files, repoRoot, shingleSizes,
 * minDistinctTokens}. Runs scanShard() and posts the resulting
 * per-pass-per-size fingerprint map back to the main thread, which
 * merges with other shards before cluster aggregation.
 */
var workerThreads = require("worker_threads");
var shingle       = require("./_codebase-shingle");

if (!workerThreads.parentPort) {
  throw new Error("_codebase-shingle-worker.js must be launched via Worker, not required directly");
}

var data = workerThreads.workerData || {};
var result = shingle.scanShard(data.files || [], {
  repoRoot:          data.repoRoot,
  shingleSizes:      data.shingleSizes,
  minDistinctTokens: data.minDistinctTokens,
});
workerThreads.parentPort.postMessage(result);
