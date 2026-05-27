/**
 * Shared client-side helpers for formatting and escaping.
 */
(function() {
  function formatSize(b) {
    if (!b) return '0 B';
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(0) + ' KB';
    if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
    return (b / 1073741824).toFixed(2) + ' GB';
  }
  function esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/'/g,'&#39;').replace(/"/g,'&quot;');
  }
  function showRenameError(input, msg) {
    var err = input.parentNode.querySelector('.rename-error');
    if (!err) { err = document.createElement('div'); err.className = 'rename-error'; err.style.cssText = 'font-size:.72rem;color:var(--danger);margin-top:2px'; input.parentNode.appendChild(err); }
    err.textContent = msg; input.style.borderColor = 'var(--danger)';
    setTimeout(function() { if (err.parentNode) err.remove(); input.style.borderColor = ''; }, 3000);
  }
  // Copy text to the clipboard. The async Clipboard API (navigator.clipboard)
  // exists only in a secure context (HTTPS / localhost); over plain HTTP at a
  // non-localhost origin — a LAN host or reverse-proxy deployment without TLS —
  // it is undefined, so a direct navigator.clipboard.writeText() throws. Fall
  // back to the legacy execCommand('copy') path, which works in any context.
  // Always returns a Promise so callers can chain .then() uniformly.
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand('copy');
        document.body.removeChild(ta);
        if (ok) resolve(); else reject(new Error('copy failed'));
      } catch (e) { reject(e); }
    });
  }

  // RFC 4122 v4 UUID. crypto.randomUUID() is secure-context-only, so fall back
  // to crypto.getRandomValues() (available in any context) on plain HTTP.
  function uuid() {
    if (window.crypto && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    var b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    var h = [];
    for (var i = 0; i < 16; i++) h.push((b[i] + 0x100).toString(16).slice(1));
    return h[0]+h[1]+h[2]+h[3]+'-'+h[4]+h[5]+'-'+h[6]+h[7]+'-'+h[8]+h[9]+'-'+h[10]+h[11]+h[12]+h[13]+h[14]+h[15];
  }

  window.Helpers = { formatSize: formatSize, esc: esc, showRenameError: showRenameError, copyText: copyText, uuid: uuid };
})();
