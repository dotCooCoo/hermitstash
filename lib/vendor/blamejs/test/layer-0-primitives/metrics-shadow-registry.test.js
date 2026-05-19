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
  check("labeled counter tracked",  snap.counters.hits["route=/api"] === 1);
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
  check("labeled gauge",            snap.gauges.queue_depth["tenant=a"] === 7);
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
  testRefusalsAtConfigTime();
}

if (require.main === module) run();
module.exports = { run: run };
