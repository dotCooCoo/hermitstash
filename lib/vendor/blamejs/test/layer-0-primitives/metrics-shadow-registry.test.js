// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

function testFactoryShape() {
  var shadow = b.metrics.snapshot.shadowRegistry({
    namespace: "tenant_a",
    counters:  ["requests_total"],
    gauges:    ["queue_depth"],
    info:      ["build_info"],
  });
  check("has inc",      typeof shadow.inc === "function");
  check("has set",      typeof shadow.set === "function");
  check("has setInfo",  typeof shadow.setInfo === "function");
  check("has snapshot", typeof shadow.snapshot === "function");
  check("has render",   typeof shadow.render === "function");
  check("has reset",    typeof shadow.reset === "function");
}

function testInc() {
  var shadow = b.metrics.snapshot.shadowRegistry({
    namespace: "ns_b",
    counters:  ["hits"],
  });
  shadow.inc("hits");
  shadow.inc("hits");
  shadow.inc("hits", { route: "/api" });
  var snap = shadow.snapshot();
  check("counter incremented",      snap.counters.hits[""] === 2);
  check("labeled counter tracked",  snap.counters.hits['{"route":"/api"}'] === 1);
  // Non-mirrored counter silently ignored.
  shadow.inc("not_mirrored");
  check("non-mirrored ignored",     snap.counters.not_mirrored === undefined);
}

function testSet() {
  var shadow = b.metrics.snapshot.shadowRegistry({
    namespace: "ns_c",
    gauges:    ["queue_depth"],
  });
  shadow.set("queue_depth", 42);
  shadow.set("queue_depth", 7, { tenant: "a" });
  var snap = shadow.snapshot();
  check("gauge set",                snap.gauges.queue_depth[""] === 42);
  check("labeled gauge",            snap.gauges.queue_depth['{"tenant":"a"}'] === 7);
}

function testCardinalityCap() {
  var shadow = b.metrics.snapshot.shadowRegistry({
    namespace: "ns_d",
    counters:  ["spam"],
    cardinalityCap: 3,
    onCardinalityExceeded: "refuse",
  });
  shadow.inc("spam", { x: "1" });
  shadow.inc("spam", { x: "2" });
  shadow.inc("spam", { x: "3" });
  var threw = false;
  try { shadow.inc("spam", { x: "4" }); } catch (_e) { threw = true; }
  check("cap refuses overflow", threw);
}

function testPrometheusPreservesLabels() {
  var shadow = b.metrics.snapshot.shadowRegistry({
    namespace: "tenant_b",
    counters:  ["hits_total"],
    gauges:    ["queue_depth"],
  });
  shadow.inc("hits_total", { route: "/api" });
  shadow.inc("hits_total", { route: "/api" });
  shadow.inc("hits_total", { route: "/health" });
  shadow.set("queue_depth", 7, { tenant: "a" });

  var out = shadow.render({ format: "prometheus" });
  check("emits hits_total{route=\"/api\"} 2",
    out.indexOf('tenant_b_hits_total{route="/api"} 2') !== -1);
  check("emits hits_total{route=\"/health\"} 1",
    out.indexOf('tenant_b_hits_total{route="/health"} 1') !== -1);
  check("emits queue_depth{tenant=\"a\"} 7",
    out.indexOf('tenant_b_queue_depth{tenant="a"} 7') !== -1);
  check("emits TYPE counter for hits_total",
    out.indexOf("# TYPE tenant_b_hits_total counter") !== -1);
}

function testPrometheusLabelValueInjection() {
  // A `,` or `=` in a label VALUE must stay inside the value — it must NOT
  // forge extra label pairs in the exposition output (label injection that
  // downstream tenant-scoping / authz selectors / recording rules would trust
  // as a boundary). The shadow registry previously serialized the label set to
  // a `name=value,...` key and re-split it on `,` for rendering, so a comma in
  // a value split into multiple forged pairs.
  var shadow = b.metrics.snapshot.shadowRegistry({
    namespace: "tenant_x",
    counters:  ["hits_total"],
  });
  shadow.inc("hits_total", { route: 'a,evil="bad' });
  var out = shadow.render({ format: "prometheus" });
  // The full value (comma + escaped quote) stays inside route's quotes.
  check("label value with a comma stays inside the value (no forged pair)",
    out.indexOf('route="a,evil=\\"bad"') !== -1);
  // The series line carries exactly ONE label pair (no injected second label).
  var line = out.split("\n").filter(function (l) { return l.indexOf("tenant_x_hits_total{") === 0; })[0] || "";
  var braces = line.slice(line.indexOf("{") + 1, line.lastIndexOf("}"));
  var labelNames = (braces.match(/(^|,)[a-zA-Z_][a-zA-Z0-9_]*="/g) || []).length;                     // allow:regex-no-length-cap — counts top-level label-name= boundaries in a bounded exposition line
  check("exactly one label pair (no injected label)", labelNames === 1);
}

function testPrometheusReservedLabelNames() {
  // A label whose NAME is `constructor`, `prototype`, or `__proto__` is a valid
  // Prometheus label name ([a-zA-Z_][a-zA-Z0-9_]*) and must survive render. The
  // shadow registry must NOT route the label key through a prototype-pollution-
  // hardened JSON parse (which strips those names), nor lose the dimension.
  var shadow = b.metrics.snapshot.shadowRegistry({
    namespace: "tenant_y",
    counters:  ["hits_total"],
  });
  shadow.inc("hits_total", { constructor: "a" });
  shadow.inc("hits_total", { prototype: "b" });
  // `{ __proto__: "c" }` as a literal sets the prototype (a no-op for a string);
  // the real vector is a labels object that came from parsed external data, so
  // its `__proto__` is an own enumerable property.
  shadow.inc("hits_total", JSON.parse('{"__proto__":"c"}'));
  var out = shadow.render({ format: "prometheus" });
  check("label named constructor survives render",
    out.indexOf('tenant_y_hits_total{constructor="a"} 1') !== -1);
  check("label named prototype survives render",
    out.indexOf('tenant_y_hits_total{prototype="b"} 1') !== -1);
  check("label named __proto__ survives render",
    out.indexOf('tenant_y_hits_total{__proto__="c"} 1') !== -1);
  // No dimension collapsed into a bare unlabeled series: every value line for
  // this metric carries a label brace.
  var valueLines = out.split("\n").filter(function (l) {
    return l.indexOf("tenant_y_hits_total") === 0 && l.indexOf("# TYPE") !== 0;
  });
  var bare = valueLines.filter(function (l) { return l.indexOf("{") === -1; });
  check("no unlabeled bare series leaked", bare.length === 0);
}

function testRefusalsAtConfigTime() {
  var threw;
  threw = false; try { b.metrics.snapshot.shadowRegistry({}); } catch (_e) { threw = true; }
  check("missing namespace throws", threw);

  threw = false; try { b.metrics.snapshot.shadowRegistry({ namespace: "bad space" }); } catch (_e) { threw = true; }
  check("invalid namespace shape throws", threw);

  threw = false; try {
    b.metrics.snapshot.shadowRegistry({
      namespace: "ok", counters: "not-an-array",
    });
  } catch (_e) { threw = true; }
  check("non-array counters throws", threw);
}

function run() {
  testFactoryShape();
  testInc();
  testSet();
  testCardinalityCap();
  testPrometheusPreservesLabels();
  testPrometheusLabelValueInjection();
  testPrometheusReservedLabelNames();
  testRefusalsAtConfigTime();
}

if (require.main === module) run();
module.exports = { run: run };
