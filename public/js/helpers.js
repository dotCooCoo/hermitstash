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
  window.Helpers = { formatSize: formatSize, esc: esc, showRenameError: showRenameError };
})();
