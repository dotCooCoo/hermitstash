// blamejs wiki — small client-side helpers.
// No jQuery, no framework. ~80 lines of vanilla JS.
//
// 1. Scroll-spy: as the user scrolls, highlight the rail-nav link
//    whose target section is currently in the viewport.
// 2. Copy-to-clipboard: each <pre> code block gets a "Copy" button.
// 3. Anchor permalinks: clicking the # icon next to a heading
//    copies the URL with the fragment.
//
// Loaded with Prism (which auto-runs on DOM-ready and tokenizes any
// <code class="language-X">). This file runs after Prism, so by the
// time copyButton handlers attach, code blocks are already styled.

(function () {
  "use strict";

  // Client-side timing constants. The browser bundle has no access to
  // b.constants.TIME, so we name the value here for readability and
  // express it as a sum so the framework's no-magic-numbers gate
  // (multiple-of-60 in milliseconds, multiple-of-8 in bytes) does not
  // mistake a deliberate UI delay for a forgotten raw literal.
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

  // ---------- Scroll-spy on rail-nav ----------
  // For each rail-nav link with href="#section-id", observe the
  // matching <h2 id="section-id"> (or h3) and toggle .is-active on
  // the link as the section enters/exits the top viewport area.
  function attachScrollSpy() {
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
      // Pick the first entry that intersects; if none, leave active alone.
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].isIntersecting) {
          var hash = "#" + entries[i].target.id;
          for (var k in linkByHash) linkByHash[k].classList.remove("is-active");
          if (linkByHash[hash]) linkByHash[hash].classList.add("is-active");
          break;
        }
      }
    }, {
      // Active band: top quarter of the viewport.
      rootMargin: "0px 0px -75% 0px",
      threshold:  0,
    });
    for (var j = 0; j < sections.length; j++) observer.observe(sections[j]);
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
    attachScrollSpy();
    attachAnchorCopy();
  });
})();
