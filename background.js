// background.js — service worker.
// Open-source, fully free: no daily limit, no license key, no subscription.
// Keeps the capture on/off preference and re-injects content scripts into
// Suno tabs that were open before an extension (re)load.
'use strict';

// Static content_scripts only inject on page load. After an extension reload,
// Suno tabs that are already open keep the OLD (now removed) scripts and get no
// new ones — so clicking a song does nothing. Re-inject into those tabs here.
var SUNO_MATCHES = ['*://suno.com/*', '*://www.suno.com/*'];
function injectIntoSuno(tab) {
  // bridge.js runs in ISOLATED world; capture-main.js must run in MAIN world.
  // Inject bridge first so its message listener exists before capture posts.
  chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['bridge.js'] }, function () {
    chrome.scripting.executeScript({
      target: { tabId: tab.id }, files: ['capture-main.js'], world: 'MAIN'
    }, function () {
      // Ask the freshly injected script to send its current state to the popup.
      try { chrome.tabs.sendMessage(tab.id, { type: 'request-tracks' }).catch(function () {}); } catch (e) {}
    });
  });
}
function reinjectOpenSunoTabs() {
  chrome.tabs.query({ url: SUNO_MATCHES }, function (tabs) {
    (tabs || []).forEach(injectIntoSuno);
  });
}

chrome.runtime.onInstalled.addListener(function (details) {
  chrome.storage.local.get(['captureOn'], function (r) {
    if (typeof r.captureOn === 'undefined') chrome.storage.local.set({ captureOn: true });
  });
  // On install or update/reload, existing tabs have stale or no content script.
  if (details && (details.reason === 'install' || details.reason === 'update')) {
    // Drop track lists captured by a previous version/session — otherwise the
    // popup opens showing stale placeholder tracks (e.g. 5 "Suno track").
    latestTracks = [];
    chrome.storage.local.remove(['latestTracks']);
    reinjectOpenSunoTabs();
  }
});

// Also re-inject when the service worker starts fresh (e.g. after reload) if a
// Suno tab is open but has no bridge listening. Probe first; inject only on
// failure so already-injected tabs are not double-loaded.
chrome.runtime.onStartup && chrome.runtime.onStartup.addListener(function () {
  chrome.tabs.query({ url: SUNO_MATCHES }, function (tabs) {
    (tabs || []).forEach(function (tab) {
      try {
        chrome.tabs.sendMessage(tab.id, { type: 'ping' }, function (reply) {
          if (chrome.runtime.lastError || !reply) injectIntoSuno(tab);
        });
      } catch (e) { injectIntoSuno(tab); }
    });
  });
});

// Keep the latest track list from the active Suno tab so the popup can show
// it even if the tab message arrived while the popup was closed.
var latestTracks = [];
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (!msg || !msg.type) return;
  if (msg.type === 'tracks-update') {
    latestTracks = msg.tracks || [];
    chrome.storage.local.set({ latestTracks: latestTracks });
  } else if (msg.type === 'get-state') {
    // Read tracks back from storage: the MV3 service worker can be torn down
    // between capture (song playing) and popup open, resetting latestTracks
    // to []. storage.local survives that; the in-memory copy does not.
    chrome.storage.local.get(['captureOn', 'latestTracks'], function (r) {
      var tracks = (r.latestTracks && r.latestTracks.length) ? r.latestTracks : latestTracks;
      latestTracks = tracks;
      sendResponse({ captureOn: r.captureOn !== false, tracks: tracks });
    });
    return true; // async sendResponse
  } else if (msg.type === 'set-capture-on') {
    chrome.storage.local.set({ captureOn: !!msg.value });
    chrome.tabs.query({ url: SUNO_MATCHES }, function (tabs) {
      (tabs || []).forEach(function (t) {
        chrome.tabs.sendMessage(t.id, { type: 'set-capture-on', value: !!msg.value }).catch(function () {});
      });
    });
  }
});
