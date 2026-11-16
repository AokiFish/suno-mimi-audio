// popup.js — reads state from background, sends controls to the Suno tab.
'use strict';

var tracks = [];
var SUNO_URLS = ['*://suno.com/*', '*://www.suno.com/*'];

function fmtMB(bytes) {
  return (bytes / 1048576).toFixed(2) + ' MB';
}

// Three UI states:
//  1. no Suno tab open   -> "Open a Suno tab" prompt
//  2. Suno open, 0 tracks -> "Give it a little music." empty state
//  3. tracks captured    -> track cards
function render(state) {
  tracks = state.tracks || [];
  document.getElementById('capture-label').textContent = state.captureOn ? 'Capture is on' : 'Capture is off';
  var tgl = document.getElementById('capture-toggle');
  tgl.classList.toggle('on', !!state.captureOn);
  document.getElementById('count-badge').textContent = tracks.length;

  // "Download all" only makes sense when at least one track is ready to save.
  var readyCount = tracks.filter(function (tr) { return tr.status === 'Ready to save'; }).length;
  var dlAll = document.getElementById('download-all');
  dlAll.disabled = readyCount === 0;
  dlAll.textContent = readyCount ? 'Download all (' + readyCount + ')' : 'Download all';

  chrome.tabs.query({ url: SUNO_URLS }, function (tabs) {
    var sunoOpen = !!(tabs && tabs.length);
    document.getElementById('open-prompt').style.display = sunoOpen ? 'none' : 'block';
    document.getElementById('suno-panel').style.display = sunoOpen ? 'block' : 'none';
    document.getElementById('empty-state').style.display = (sunoOpen && !tracks.length) ? 'block' : 'none';
  });

  var list = document.getElementById('track-list');
  list.innerHTML = '';
  tracks.forEach(function (tr) {
    var div = document.createElement('div');
    div.className = 'track card';

    var head = document.createElement('div');
    head.className = 'track-head';
    var title = document.createElement('div');
    title.className = 'title';
    title.textContent = tr.title || 'Suno track';
    var rm = document.createElement('button');
    rm.className = 'rm';
    rm.textContent = '×';
    rm.setAttribute('aria-label', 'Remove track');
    rm.addEventListener('click', function () {
      sendToSunoTab({ type: 'remove-track', id: tr.id });
    });
    head.appendChild(title);
    head.appendChild(rm);

    var meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = tr.status + ' · ' + fmtMB(tr.bytes || 0) + ' · ' + tr.id;

    var actions = document.createElement('div');
    actions.className = 'actions';
    var input = document.createElement('input');
    input.type = 'text';
    input.value = tr.title || 'Suno track';
    var save = document.createElement('button');
    save.className = 'primary';
    save.textContent = 'Save audio ↓';
    save.disabled = tr.status !== 'Ready to save';
    save.addEventListener('click', function () {
      sendToSunoTab({ type: 'save-track', id: tr.id, filename: input.value.trim() || tr.title });
    });
    actions.appendChild(input);
    actions.appendChild(save);

    div.appendChild(head);
    div.appendChild(meta);
    div.appendChild(actions);
    list.appendChild(div);
  });
}

function refresh() {
  chrome.runtime.sendMessage({ type: 'get-state' }, function (state) {
    if (state) render(state);
  });
}

function sendToSunoTab(msg) {
  chrome.tabs.query({ url: SUNO_URLS }, function (tabs) {
    (tabs || []).forEach(function (t) {
      chrome.tabs.sendMessage(t.id, msg).catch(function () {});
    });
  });
}

document.getElementById('open-suno').addEventListener('click', function () {
  chrome.tabs.query({ url: SUNO_URLS }, function (tabs) {
    if (tabs && tabs.length) {
      // Already open: focus that tab instead of spawning a duplicate.
      var tab = tabs[0];
      chrome.windows.update(tab.windowId, { focused: true });
      chrome.tabs.update(tab.id, { active: true });
    } else {
      chrome.tabs.create({ url: 'https://suno.com/' }, function () {
        setTimeout(refresh, 300); // re-evaluate state now that a Suno tab exists
      });
    }
  });
});

document.getElementById('capture-toggle').addEventListener('click', function () {
  chrome.runtime.sendMessage({ type: 'get-state' }, function (state) {
    if (!state) return;
    var next = !state.captureOn;
    chrome.runtime.sendMessage({ type: 'set-capture-on', value: next }, function () { refresh(); });
    sendToSunoTab({ type: 'set-capture-on', value: next });
  });
});

document.getElementById('clear-all').addEventListener('click', function () {
  sendToSunoTab({ type: 'clear-all' });
  setTimeout(refresh, 200);
});

document.getElementById('download-all').addEventListener('click', function () {
  sendToSunoTab({ type: 'save-all' });
});

chrome.runtime.onMessage.addListener(function (msg) {
  if (!msg) return;
  if (msg.type === 'tracks-update') refresh();
  if (msg.type === 'save-done' && msg.id) {
    chrome.runtime.sendMessage({ type: 'consume-save' }, function () { refresh(); });
  }
  if (msg.type === 'save-failed') refresh();
});

refresh();
