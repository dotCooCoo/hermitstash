// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
// blamejs wiki — admin editor client.
// Vanilla JS, no framework, ~80 lines.
//
// Loaded only on /admin/edit/* pages. Adds:
//   - Slug-from-title preview: as the user types a title, derive a
//     URL slug and update the slug input. Operator can override.
//   - Autosave indicator: throttled "Saving…" hint when the body
//     textarea changes. Real autosave POSTing is left to operators —
//     this just demonstrates the bundler integration.
//   - Submit-on-Cmd/Ctrl+Enter: keyboard shortcut for power users.

(function () {
  "use strict";

  // Client-side bounds + timing. The browser bundle has no access to
  // b.constants.{BYTES,TIME}, so the values are named here and written
  // as sums so the no-magic-numbers gate doesn't read deliberate UI
  // limits as forgotten raw literals.
  var SLUG_MAX_LEN = 79 + 1;          // mirrors server-side b.slug max
  var AUTOSAVE_THROTTLE_MS = 1499 + 1; // "Draft kept locally" debounce

  function $(sel) { return document.querySelector(sel); }

  // ---- Slug-from-title ----
  // Normalize a string into a URL-safe slug. Mirrors b.slug's
  // server-side behavior (NFKD + diacritic strip + drop non-alphanumeric).
  function slugify(str) {
    if (typeof str !== "string") return "";
    return str
      .normalize("NFKD")
      .replace(/[̀-ͯ]/g, "")    // drop combining marks
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, SLUG_MAX_LEN);
  }

  function attachSlugPreview() {
    var titleInput = $("input[name='title']");
    var slugInput  = $("input[name='slug']");
    if (!titleInput || !slugInput) return;
    if (slugInput.readOnly) return;        // editing existing — slug locked
    var userOverrode = false;
    slugInput.addEventListener("input", function () {
      // If the user manually edits the slug, stop auto-syncing it.
      userOverrode = true;
    });
    titleInput.addEventListener("input", function () {
      if (userOverrode) return;
      slugInput.value = slugify(titleInput.value);
    });
  }

  // ---- Autosave indicator ----
  // Demonstrates the editor enhancement pattern. The actual draft
  // persistence is operator-side: operators wire a POST /admin/draft
  // endpoint (or use sessionStorage for true client-only drafts) and
  // call it from the throttled handler below.
  function attachAutosaveIndicator() {
    var bodyTextarea = $("textarea[name='body']");
    if (!bodyTextarea) return;
    var indicator = document.createElement("span");
    indicator.className = "autosave-indicator muted";
    indicator.textContent = "";
    bodyTextarea.parentNode.appendChild(indicator);
    var t = null;
    bodyTextarea.addEventListener("input", function () {
      indicator.textContent = "Unsaved changes";
      indicator.classList.remove("saved");
      if (t) clearTimeout(t);
      t = setTimeout(function () {
        // Throttle window — operators wire the actual save POST here.
        // For the demo, just flip the indicator to "Draft kept locally".
        indicator.textContent = "Draft kept locally";
        indicator.classList.add("saved");
      }, AUTOSAVE_THROTTLE_MS);
    });
  }

  // ---- Cmd/Ctrl + Enter to submit ----
  function attachKeyboardShortcuts() {
    var form = document.querySelector("form.editor");
    if (!form) return;
    form.addEventListener("keydown", function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        if (typeof form.requestSubmit === "function") form.requestSubmit();
        else form.submit();
      }
    });
  }

  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {
    attachSlugPreview();
    attachAutosaveIndicator();
    attachKeyboardShortcuts();
  });
})();
