// bridge.js — ISOLATED world relay on suno.com.
// Metadata only. Never carries audio bytes, tokens, cookies, or keys.
// Forwards track-list updates from the MAIN-world capture script to the
// extension (popup/background) via chrome.runtime messaging, and forwards
// control messages (toggle/clear/remove/save) back into the page.
(function () {
  'use strict';
  // Guard against double injection (onInstalled + onStartup can both fire).
  if (window.__mimiBridgeLoaded) return;
  window.__mimiBridgeLoaded = true;
  var lastTracks = [];

  window.addEventListener('message', function (event) {
    if (!event.data || event.data.source !== 'mimi-capture-main') return;
    if (event.data.type === 'tracks-update') {
      lastTracks = event.data.tracks || [];
      try {
        chrome.runtime.sendMessage({ type: 'tracks-update', tracks: lastTracks });
      } catch (e) { /* popup/background may be closed */ }
    } else if (event.data.type === 'save-done' || event.data.type === 'save-failed') {
      try {
        chrome.runtime.sendMessage({ type: event.data.type, id: event.data.id, reason: event.data.reason || '' });
      } catch (e) { /* ignore */ }
    }
  });

  chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (!msg || !msg.type) return;
    if (msg.type === 'ping') { sendResponse({ ok: true }); return; }
    if (msg.type === 'set-capture-on') {
      window.postMessage({ source: 'mimi-bridge', type: 'set-capture-on', value: !!msg.value }, '*');
    } else if (msg.type === 'clear-all') {
      window.postMessage({ source: 'mimi-bridge', type: 'clear-all' }, '*');
    } else if (msg.type === 'remove-track') {
      window.postMessage({ source: 'mimi-bridge', type: 'remove-track', id: msg.id }, '*');
    } else if (msg.type === 'request-tracks') {
      window.postMessage({ source: 'mimi-bridge', type: 'request-tracks' }, '*');
    } else if (msg.type === 'save-track') {
      // Forward to the MAIN-world capture script; it downloads in page
      // origin and reports save-done / save-failed back through tracks-update.
      window.postMessage({ source: 'mimi-bridge', type: 'save-track', id: msg.id, filename: msg.filename || '' }, '*');
    } else if (msg.type === 'save-all') {
      window.postMessage({ source: 'mimi-bridge', type: 'save-all' }, '*');
    }
  });
})();
