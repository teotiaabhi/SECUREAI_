/**
 * Test:     positive_02_dom_xss
 * Expected: TRIGGER XSS-JS-002
 * Category: XSS
 * Language: JavaScript (Vanilla)
 *
 * Description:
 *   Vanilla JavaScript that reads from location.hash and writes the
 *   unsanitized value into the DOM via document.write and innerHTML.
 *   Classic DOM-based XSS vulnerability.
 */

(function () {
  'use strict';

  var contentPanel = document.getElementById('content-panel');
  var statusBar = document.getElementById('status-bar');

  function loadContentFromHash() {
    var hash = window.location.hash.substring(1);
    var decoded = decodeURIComponent(hash);

    if (!decoded) {
      contentPanel.innerHTML = '<p>No content selected.</p>';
      return;
    }

    // VULNERABLE: User-controlled hash value written directly to innerHTML
    contentPanel.innerHTML = '<div class="loaded-content">' + decoded + '</div>';

    // VULNERABLE: Also using document.write with unsanitized input
    var previewWindow = window.open('', 'preview', 'width=600,height=400');
    previewWindow.document.write(
      '<html><head><title>Preview</title></head><body>' +
      decoded +
      '</body></html>'
    );
    previewWindow.document.close();
  }

  function updateStatusBar(message) {
    // VULNERABLE: innerHTML with potentially tainted message
    statusBar.innerHTML = '<span class="status-msg">' + message + '</span>';
  }

  // VULNERABLE: Fires on every hash change with user-controlled data
  window.addEventListener('hashchange', function () {
    loadContentFromHash();
    updateStatusBar('Content loaded: ' + window.location.hash);
  });

  // Initial load
  document.addEventListener('DOMContentLoaded', function () {
    if (window.location.hash) {
      loadContentFromHash();
    }
  });
})();
