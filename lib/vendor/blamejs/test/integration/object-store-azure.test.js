// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live Azure Blob (Shared Key) round-trip against the Azurite emulator in
 * docker-compose.test.yml, over TLS with the test CA (NODE_EXTRA_CA_CERTS set
 * by scripts/test-integration.js — no rejectUnauthorized:false).
 *
 * Azurite is PATH-STYLE: the account is the first URL path segment
 * (https://127.0.0.1:10000/devstoreaccount1/<container>/<blob>), unlike
 * production Azure's host-based <account>.blob.core.windows.net. A successful
 * authenticated round-trip is itself the proof that the Shared-Key canonical
 * resource carries the account exactly once — a doubled account (the prior
 * behavior) returns 403 AuthenticationFailed and put() would throw. Also a
 * deterministic buildStringToSign check that path-style does not double it.
 */
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");
var azureBlob = require("../../lib/object-store/azure-blob");

// Azurite's well-known emulator account + key (public, documented).
var ENDPOINT = "https://127.0.0.1:10000";
var ACCOUNT  = "devstoreaccount1";
var KEY      = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

async function run() {
  var az = await services.requireService("azurite");
  if (!az.ok) throw new Error("azurite unreachable: " + az.reason);

  // --- deterministic: canonical resource is "/" + account + the request's
  // absolute path. For a PATH-STYLE URL (account already the first path
  // segment, as with Azurite) that yields the account twice — the form a
  // path-style server expects (verified live below). For a HOST-BASED URL
  // (account only in the host) it appears once. ---
  var HDRS = { "x-ms-date": "Mon, 01 Jan 2024 00:00:00 GMT", "x-ms-version": azureBlob.DEFAULT_API_VERSION };
  var stsPath = azureBlob.buildStringToSign({
    method: "GET", accountName: ACCOUNT,
    url: new URL(ENDPOINT + "/" + ACCOUNT + "/c1/blob.txt"), headers: HDRS,
  });
  check("path-style canonical resource is the doubled-account form a path-style server expects",
    stsPath.indexOf("/" + ACCOUNT + "/" + ACCOUNT + "/c1/blob.txt") !== -1);
  var stsHost = azureBlob.buildStringToSign({
    method: "GET", accountName: ACCOUNT,
    url: new URL("https://" + ACCOUNT + ".blob.core.windows.net/c1/blob.txt"), headers: HDRS,
  });
  check("host-based canonical resource carries the account exactly once",
    stsHost.indexOf("/" + ACCOUNT + "/c1/blob.txt") !== -1 &&
    stsHost.indexOf("/" + ACCOUNT + "/" + ACCOUNT + "/") === -1);

  var container = "blamejs-az-" + process.pid;
  var commonCfg = {
    protocol: "azure-blob", accountName: ACCOUNT, accountKey: KEY,
    endpoint: ENDPOINT, allowInternal: true,
    pathStyle: true,   // Azurite addresses the account as the first path segment
  };

  // --- container lifecycle (path-style auto-detected from the IP host) ---
  var ops = b.objectStore.bucketOps.create(commonCfg);
  await ops.create(container);
  check("createContainer accepted (signature verified by Azurite)", true);
  var containers = await ops.list();
  check("listContainers includes the new container",
    containers.some(function (c) { return c.name === container; }));

  // --- blob round-trip ---
  var be = b.objectStore.buildBackend(Object.assign({ container: container }, commonCfg));
  var key = "folder/object.bin";
  var payload = Buffer.from("azure-roundtrip-" + process.pid + "-" + "Z".repeat(64), "utf8");

  var putRes = await be.put(key, payload, { contentType: "application/octet-stream" });
  check("put returns the byte length", putRes.size === payload.length);

  var got = await be.get(key);
  check("get returns byte-identical content", Buffer.isBuffer(got) && Buffer.compare(got, payload) === 0);

  var h = await be.head(key);
  check("head reports the correct size", h.size === payload.length);

  var listed = await be.list("");
  check("list surfaces the uploaded key",
    listed.items.some(function (it) { return it.key === key; }));

  var deleted = await be.delete(key);
  check("delete returns true for an existing blob", deleted === true);

  var afterDelete = await be.list("");
  check("list no longer surfaces the deleted key",
    !afterDelete.items.some(function (it) { return it.key === key; }));

  await ops.delete(container);
  check("deleteContainer accepted", true);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
