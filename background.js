// background.js — service worker.
// Freemium: free 5 saves/day, subscription for unlimited, owner unlimited.
// Daily reset in Asia/Shanghai. No license server is wired: validateLicense
// accepts only owner keys matching /^MIMI-OWNER-/; every other key is invalid
// until a real provider (Stripe / LemonSqueezy / ExtensionPay) is connected.
// TODO: wire a real subscription provider here; do not invent an endpoint.
'use strict';

var FREE_DAILY_LIMIT = 5;
var OWNER_KEY_RE = /^MIMI-OWNER-/;

function shanghaiDateKey(d) {
  var parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit'
  }).formatToParts(d || new Date());
  var y = '', m = '', day = '';
  parts.forEach(function (p) {
    if (p.type === 'year') y = p.value;
    if (p.type === 'month') m = p.value;
    if (p.type === 'day') day = p.value;
  });
  return y + '-' + m + '-' + day;
}

function validateLicense(key) {
  if (typeof key === 'string' && OWNER_KEY_RE.test(key.trim())) {
    return { ok: true, kind: 'owner' };
  }
  return { ok: false, kind: 'none' };
}

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
    chrome.storage.local.get(['captureOn', 'licenseKey', 'dailyCount', 'dailyDate', 'latestTracks'], function (r) {
      var today = shanghaiDateKey(new Date());
      var count = (r.dailyDate === today) ? (r.dailyCount || 0) : 0;
      var lic = validateLicense(r.licenseKey || '');
      var tracks = (r.latestTracks && r.latestTracks.length) ? r.latestTracks : latestTracks;
      latestTracks = tracks;
      sendResponse({
        captureOn: r.captureOn !== false,
        tracks: tracks,
        todayUsed: count,
        dailyLimit: FREE_DAILY_LIMIT,
        licensed: lic.ok,
        licenseKind: lic.kind
      });
    });
    return true; // async sendResponse
  } else if (msg.type === 'set-capture-on') {
    chrome.storage.local.set({ captureOn: !!msg.value });
    chrome.tabs.query({ url: ['*://suno.com/*', '*://www.suno.com/*'] }, function (tabs) {
      (tabs || []).forEach(function (t) {
        chrome.tabs.sendMessage(t.id, { type: 'set-capture-on', value: !!msg.value }).catch(function () {});
      });
    });
  } else if (msg.type === 'set-license-key') {
    chrome.storage.local.set({ licenseKey: (msg.key || '').trim() });
  } else if (msg.type === 'consume-save') {
    // Called by the popup AFTER a save completes. Owner/licensed: no count.
    chrome.storage.local.get(['licenseKey', 'dailyCount', 'dailyDate'], function (r) {
      var lic = validateLicense(r.licenseKey || '');
      if (lic.ok) { sendResponse({ allowed: true, counted: false }); return; }
      var today = shanghaiDateKey(new Date());
      var count = (r.dailyDate === today) ? (r.dailyCount || 0) : 0;
      if (count >= FREE_DAILY_LIMIT) { sendResponse({ allowed: false, counted: false, todayUsed: count }); return; }
      chrome.storage.local.set({ dailyCount: count + 1, dailyDate: today }, function () {
        sendResponse({ allowed: true, counted: true, todayUsed: count + 1 });
      });
    });
    return true;
  }
});
