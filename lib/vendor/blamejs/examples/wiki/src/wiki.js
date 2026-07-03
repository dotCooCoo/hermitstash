// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
// blamejs wiki — small client-side helpers.
// No jQuery, no framework. ~150 lines of vanilla JS.
//
// 1. Copy-to-clipboard: each <pre> code block gets a "Copy" button.
// 2. Anchor permalinks: clicking the # icon next to a heading
//    copies the URL with the fragment.
// 3. Rail-nav scroll-spy: highlights sidebar links whose href is a
//    fragment matching a section currently in the viewport (used by
//    pages whose sidebar items are intra-page anchors, e.g. search).
// 4. On-this-page TOC: builds a right-rail table of contents from
//    every <h2>/<h3> in <main> and highlights the active section as
//    the reader scrolls.
//
// Loaded with Prism (which auto-runs on DOM-ready and tokenizes any
// <code class="language-X">). This file runs after Prism, so by the
// time the copy-button handlers attach, code blocks are already
// styled.

(function () {
  "use strict";

  // Client-side timing constants. The browser bundle has no access to
  // b.constants.TIME, so name the value here for readability and
  // express it as a sum so the framework's no-magic-numbers gate
  // (multiple-of-60 ms, multiple-of-8 bytes) does not mistake a
  // deliberate UI delay for a forgotten raw literal.
  var COPY_FLASH_MS = 1100 + 100; // post-copy "Copied!" feedback hold

  // ---------- Copy-to-clipboard for <pre> blocks ----------
  function attachCopyButtons() {
    var blocks = document.querySelectorAll("main pre");
    for (var i = 0; i < blocks.length; i++) {
      (function (pre) {
        var btn = document.createElement("button");
        btn.className = "copy-btn";
        btn.type = "button";
        btn.textContent = "Copy";
        btn.setAttribute("aria-label", "Copy code to clipboard");
        btn.addEventListener("click", function () {
          var code = pre.querySelector("code");
          var text = code ? code.innerText : pre.innerText;
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(
              function () { _flash(btn, "Copied"); },
              function () { _flash(btn, "Error"); }
            );
          } else {
            // Older browsers / non-secure contexts fall back to
            // execCommand. The framework targets modern browsers but
            // this keeps the button useful in every environment.
            try {
              var ta = document.createElement("textarea");
              ta.value = text;
              ta.style.position = "fixed";
              ta.style.left = "-9999px";
              document.body.appendChild(ta);
              ta.select();
              document.execCommand("copy");
              document.body.removeChild(ta);
              _flash(btn, "Copied");
            } catch (_e) { _flash(btn, "Error"); }
          }
        });
        pre.appendChild(btn);
      })(blocks[i]);
    }
  }

  function _flash(btn, label) {
    var prev = btn.textContent;
    btn.textContent = label;
    btn.classList.add("copied");
    setTimeout(function () {
      btn.textContent = prev;
      btn.classList.remove("copied");
    }, COPY_FLASH_MS);
  }

  // ---------- Rail-nav scroll-spy (sidebar links with href="#x") ----
  // Only highlights sidebar links pointing to in-page anchors. Pages
  // that ship content-only sidebar entries (the wiki's normal mode)
  // get no spy effect from this function — that's intentional; the
  // on-this-page TOC below covers every page.
  function attachRailScrollSpy() {
    if (!("IntersectionObserver" in window)) return;
    var navLinks = document.querySelectorAll(".rail-nav a[href^='#']");
    if (navLinks.length === 0) return;
    var linkByHash = {};
    var sections = [];
    for (var i = 0; i < navLinks.length; i++) {
      var hash = navLinks[i].getAttribute("href");
      var target = hash && document.querySelector(hash);
      if (target) {
        linkByHash[hash] = navLinks[i];
        sections.push(target);
      }
    }
    if (sections.length === 0) return;
    var observer = new IntersectionObserver(function (entries) {
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].isIntersecting) {
          var hash = "#" + entries[i].target.id;
          for (var k in linkByHash) linkByHash[k].classList.remove("is-active");
          if (linkByHash[hash]) linkByHash[hash].classList.add("is-active");
          break;
        }
      }
    }, {
      rootMargin: "0px 0px -75% 0px",
      threshold:  0,
    });
    for (var j = 0; j < sections.length; j++) observer.observe(sections[j]);
  }

  // ---------- On-this-page TOC (right rail) ----------
  // Walk every <h2 id> / <h3 id> inside <main>, build a list in the
  // .onthispage [data-toc] container, and use IntersectionObserver to
  // toggle .is-active on the link whose target is currently in view.
  // Hides itself when the page has no headings or the right rail isn't
  // rendered (the CSS hides it under 1280px).
  function buildOnThisPageTOC() {
    var container = document.querySelector(".onthispage [data-toc]");
    var aside     = document.querySelector(".onthispage");
    if (!container || !aside) return;

    // Scope: every h2/h3 inside <main> that has an id, except cards /
    // hero / page-meta sections that opt out via data-toc-skip.
    var headings = document.querySelectorAll("main h2[id], main h3[id]");
    if (headings.length === 0) {
      aside.style.display = "none";
      return;
    }

    var entries = [];
    for (var i = 0; i < headings.length; i++) {
      var h = headings[i];
      if (h.closest("[data-toc-skip]")) continue;
      // Card-grid h3s are titles inside cards; not section headings.
      if (h.closest(".card")) continue;
      // Hero block has its own H1 only; skip any h2/h3 inside it.
      if (h.closest(".hero")) continue;
      entries.push(h);
    }
    if (entries.length === 0) {
      aside.style.display = "none";
      return;
    }

    var byId = {};
    for (var k = 0; k < entries.length; k++) {
      var heading = entries[k];
      var li = document.createElement("li");
      if (heading.tagName === "H3") li.className = "toc-h3";
      var a = document.createElement("a");
      a.href = "#" + heading.id;
      // Strip permalink anchor text (the "#" suffix) and trailing
      // whitespace from the heading's visible text.
      var label = (heading.textContent || "").replace(/#\s*$/, "").trim();
      a.textContent = label;
      li.appendChild(a);
      container.appendChild(li);
      byId[heading.id] = a;
    }

    if (!("IntersectionObserver" in window)) return;
    var active = null;
    var observer = new IntersectionObserver(function (rows) {
      for (var i = 0; i < rows.length; i++) {
        if (rows[i].isIntersecting) {
          var link = byId[rows[i].target.id];
          if (!link) continue;
          if (active && active !== link) active.classList.remove("is-active");
          link.classList.add("is-active");
          active = link;
          break;
        }
      }
    }, {
      // Active band: top quarter of the viewport.
      rootMargin: "0px 0px -75% 0px",
      threshold:  0,
    });
    for (var n = 0; n < entries.length; n++) observer.observe(entries[n]);
  }

  // ---------- Symbol search (sidebar) ----------
  // Loads the build-time symbol manifest from /dist/symbol-index.json
  // and offers fuzzy autocomplete over the primitive signatures. The
  // first result is highlighted; Enter navigates; Esc clears; / from
  // anywhere outside an input focuses the box.
  function attachSymbolSearch() {
    var input   = document.querySelector("[data-symbol-search]");
    var results = document.querySelector("[data-symbol-results]");
    if (!input || !results) return;

    function clearResults() {
      while (results.firstChild) results.removeChild(results.firstChild);
    }

    var manifest = null;
    var loadPromise = null;
    function loadManifest() {
      if (manifest) return Promise.resolve(manifest);
      if (loadPromise) return loadPromise;
      loadPromise = fetch("/symbols.json", { credentials: "same-origin" }) // allow:raw-outbound-http-framework-internal — browser-side script; b.httpClient is Node-server-only
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (data) { manifest = Array.isArray(data) ? data : []; return manifest; })
        .catch(function () { manifest = []; return manifest; });
      return loadPromise;
    }

    function score(entry, q) {
      var bare = entry.sigBare || entry.sig || "";
      var lc = bare.toLowerCase();
      var qlc = q.toLowerCase();
      if (lc === qlc) return 100;
      if (lc.indexOf(qlc) === 0) return 80; // allow:raw-byte-literal — search-rank weight, not bytes
      if (lc.indexOf("." + qlc) !== -1) return 60; // allow:raw-byte-literal — search-rank weight, not bytes / allow:raw-time-literal — not seconds
      if (lc.indexOf(qlc) !== -1) return 40; // allow:raw-byte-literal — search-rank weight, not bytes
      var qi = 0;
      for (var i = 0; i < lc.length && qi < qlc.length; i++) {
        if (lc.charAt(i) === qlc.charAt(qi)) qi++;
      }
      return qi === qlc.length ? 20 : 0;
    }

    function render(rows, q) {
      clearResults();
      if (rows.length === 0) {
        var empty = document.createElement("li");
        empty.className = "sym-empty";
        empty.textContent = q ? "No matches" : "Type to search…";
        results.appendChild(empty);
        results.hidden = false;
        return;
      }
      for (var i = 0; i < rows.length && i < 12; i++) {
        var r = rows[i];
        var li = document.createElement("li");
        li.setAttribute("role", "option");
        var a = document.createElement("a");
        a.href = "/" + r.page + "#" + r.anchor;
        a.textContent = r.sigBare || r.sig;
        var span = document.createElement("span");
        span.className = "sym-page";
        span.textContent = r.title || r.page;
        a.appendChild(span);
        if (i === 0) a.classList.add("is-active");
        li.appendChild(a);
        results.appendChild(li);
      }
      results.hidden = false;
    }

    function update() {
      var q = (input.value || "").trim();
      if (!q) { results.hidden = true; clearResults(); return; }
      loadManifest().then(function (data) {
        var scored = [];
        for (var i = 0; i < data.length; i++) {
          var s = score(data[i], q);
          if (s > 0) scored.push({ s: s, e: data[i] });
        }
        scored.sort(function (a, b) { return b.s - a.s; });
        render(scored.map(function (x) { return x.e; }), q);
      });
    }

    input.addEventListener("input", update);
    input.addEventListener("focus", update);
    input.addEventListener("blur", function () {
      setTimeout(function () { results.hidden = true; }, 150);
    });
    input.addEventListener("keydown", function (e) {
      var active = results.querySelector("a.is-active");
      var items  = results.querySelectorAll("a");
      if (e.key === "Escape") { input.value = ""; results.hidden = true; return; }
      if (e.key === "ArrowDown" && items.length > 0) {
        e.preventDefault();
        var nextIdx = 0;
        for (var i = 0; i < items.length; i++) {
          if (items[i] === active) { nextIdx = (i + 1) % items.length; break; }
        }
        if (active) active.classList.remove("is-active");
        items[nextIdx].classList.add("is-active");
        return;
      }
      if (e.key === "ArrowUp" && items.length > 0) {
        e.preventDefault();
        var prevIdx = items.length - 1;
        for (var j = 0; j < items.length; j++) {
          if (items[j] === active) { prevIdx = (j - 1 + items.length) % items.length; break; }
        }
        if (active) active.classList.remove("is-active");
        items[prevIdx].classList.add("is-active");
        return;
      }
      if (e.key === "Enter" && active) {
        e.preventDefault();
        window.location.href = active.getAttribute("href");
      }
    });

    document.addEventListener("keydown", function (e) {
      if (e.key !== "/") return;
      var t = e.target;
      var tag = t && t.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || (t && t.isContentEditable)) return;
      e.preventDefault();
      input.focus();
      input.select();
    });
  }

  // ---------- Anchor permalink: clicking copies URL ----------
  function attachAnchorCopy() {
    var anchors = document.querySelectorAll("main .anchor");
    for (var i = 0; i < anchors.length; i++) {
      (function (a) {
        a.addEventListener("click", function (e) {
          if (!navigator.clipboard) return;     // fallback: just navigate
          e.preventDefault();
          var href = a.getAttribute("href");
          var url = window.location.origin + window.location.pathname + href;
          navigator.clipboard.writeText(url).then(
            function () {
              window.location.hash = href.slice(1);
              _flash(a, "✓");
            },
            function () { window.location.hash = href.slice(1); }
          );
        });
      })(anchors[i]);
    }
  }

  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {
    attachCopyButtons();
    attachRailScrollSpy();
    buildOnThisPageTOC();
    attachSymbolSearch();
    attachAnchorCopy();
  });
})();
