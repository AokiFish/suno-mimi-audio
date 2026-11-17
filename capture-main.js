// capture-main.js — MAIN world, document_start on suno.com.
// Original code.
//
// CORRECTED capture layer (2026-11-16, after Luca's forensic check + static
// analysis of Suno's own player JS):
// - The first build hooked fetch/XHR. That grabs the ENCRYPTED stream bytes:
//   the saved file had no ftyp/moov/moof/mdat, entropy 7.99996 bit/byte
//   (pure random = ciphertext), no repeated blocks, length not a multiple
//   of 16 (streamed/chunked encryption). Reassembling those bytes as .m4a
//   is garbage. The save step and the file assembly were NOT the problem.
// - Suno's player (chunk c_1e15t1v9xc__t.js, "SW HLS") fetches an HLS-style
//   manifest {initUrl, segments, codec, duration}, fetches the init segment
//   + media segments, DECRYPTS them in page JS (bytesDecrypted counter,
//   decryptDurationMs), runs them through MP4Box.js, and appends the result
//   to a MediaSource SourceBuffer in order: init segment first, then media
//   segments. There is NO EME/Widevine anywhere in the 120 chunks
//   (no requestMediaKeySystemAccess, no setMediaKeys, no mediaKeys), so the
//   bytes reaching SourceBuffer.appendBuffer are always plaintext.
// - Therefore the hook sits on SourceBuffer.prototype.appendBuffer: the
//   first appended buffer is the init segment (ftyp+moov), the rest are
//   media segments (moof+mdat). Concatenated in append order they form a
//   valid fragmented MP4, playable as .m4a. A second hook on
//   URL.createObjectURL catches the player's progressive path, which builds
//   one whole decrypted audio Blob and hands it to an <audio> element.
// - No fetch/XHR audio capture anymore. No download menu call, no
//   token/cookie/key read, no upload, no MediaRecorder re-encode.
(function () {
  'use strict';
  // Guard against double injection (onInstalled + onStartup can both fire).
  if (window.__mimiCaptureLoaded) return;
  window.__mimiCaptureLoaded = true;
  var MAX_TRACKS = 8; // hold up to 8 songs at once (user: "at least 6")
  var MAX_BYTES = 67108864; // 64 MiB per track
  var QUIET_MS = 2500; // no append to a song for 2.5 s => player done with it => Ready

  var captureOn = true;
  var tracks = {}; // id -> {id, title, chunks, bytes, status, source, startedAt, timer}
  var order = [];
  var sbToSession = new WeakMap(); // SourceBuffer -> session id
  var DUP_SINK = '__dup__'; // SourceBuffer replaying an already-held song: ignore its media
  var msToSbs = new WeakMap(); // MediaSource -> [SourceBuffer]
  var tombstoneInits = []; // init signatures of tracks superseded by the network layer

  function shortId() {
    var s = '';
    var c = '0123456789abcdef';
    for (var i = 0; i < 8; i++) s += c[Math.floor(Math.random() * 16)];
    return s;
  }

  // --- Minimal box reader for fragmented MP4 (no external libs) ---
  // init segment: ftyp + moov; media segment: moof + mdat.
  // moov/mvhd gives timescale + full duration; moof/traf/tfdt gives the
  // decode-time already appended. Together they tell if a song is complete.
  function boxes(buf, start, end, type) {
    var out = [], d = new Uint8Array(buf), o = start;
    while (o + 8 <= end) {
      var size = (d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3];
      if (size < 8 || o + size > end) break;
      if (d[o + 4] === type.charCodeAt(0) && d[o + 5] === type.charCodeAt(1) &&
          d[o + 6] === type.charCodeAt(2) && d[o + 7] === type.charCodeAt(3)) out.push(o);
      o += size;
    }
    return out;
  }
  function readU32(d, o) {
    return ((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) >>> 0;
  }
  function readU64(d, o) {
    return readU32(d, o) * 4294967296 + readU32(d, o + 4);
  }
  // init segment -> {duration, timescale}; duration in timescale units.
  function parseInitTiming(buf) {
    try {
      var d = new Uint8Array(buf);
      var moov = boxes(buf, 0, d.length, 'moov')[0];
      if (moov === undefined) return null;
      var moovEnd = moov + (((d[moov] << 24) | (d[moov + 1] << 16) | (d[moov + 2] << 8) | d[moov + 3]) >>> 0);
      var mvhd = boxes(buf, moov + 8, moovEnd, 'mvhd')[0];
      if (mvhd === undefined) return null;
      var p = mvhd + 8, ver = d[p];
      var ts, dur;
      if (ver === 1) { ts = readU32(d, p + 20); dur = readU64(d, p + 24); }
      else { ts = readU32(d, p + 12); dur = readU32(d, p + 16); }
      if (!ts || !dur || dur >= 4294967295) return null; // 0 or 0xFFFFFFFF = unknown duration
      return { duration: dur, timescale: ts };
    } catch (e) { return null; }
  }
  // media segment -> highest baseMediaDecodeTime across its traf/tfdt boxes.
  function parseMediaTime(buf) {
    try {
      var d = new Uint8Array(buf);
      var moofs = boxes(buf, 0, d.length, 'moof');
      var max = -1;
      for (var m = 0; m < moofs.length; m++) {
        var moof = moofs[m];
        var moofEnd = moof + (((d[moof] << 24) | (d[moof + 1] << 16) | (d[moof + 2] << 8) | d[moof + 3]) >>> 0);
        var trafs = boxes(buf, moof + 8, moofEnd, 'traf');
        for (var t = 0; t < trafs.length; t++) {
          var traf = trafs[t];
          var trafEnd = traf + (((d[traf] << 24) | (d[traf + 1] << 16) | (d[traf + 2] << 8) | d[traf + 3]) >>> 0);
          var tfdts = boxes(buf, traf + 8, trafEnd, 'tfdt');
          for (var f = 0; f < tfdts.length; f++) {
            var tfdt = tfdts[f], q = tfdt + 8;
            var v = d[q];
            var base = v === 1 ? readU64(d, q + 4) : readU32(d, q + 4);
            if (base > max) max = base;
          }
        }
      }
      return max;
    } catch (e) { return -1; }
  }

  // Suno is an SPA: document.title stays "Home"/"Library" and never changes
  // to the playing song. The clip title lives in the React tree of the card
  // you click, and in the player DOM. Prefer those; document.title is last.
  var PAGE_WORDS = /^(home|library|create|explore|suno|inbox|notifications|search|profile|settings|upgrade|more|show more|variety default|your music, ready to keep\.?|ai music generator)$/i;
  var UI_WORDS = /^(play|pause|share|download|more|copy|like|save|close|remove|remix|extend|upload|create|sign in|subscribe)$/i;
  var lastPlayTitle = '';
  var lastPlayAt = 0;
  var TITLE_MAX_AGE = 60000; // a clicked name is only valid for the song that starts within 60 s
  var TITLE_ATTACH_MS = 5000; // a name arriving this soon after a track may fill it

  // The player plays ONE song at a time. All appended data belongs to the
  // current track until the user clicks a different song. Re-inits from auto-
  // seek, new SourceBuffers, etc. are all the same song — never new tracks.
  var activeTrackId = null;
  var ACTIVE_GRACE_MS = 15000; // a finished track stays "current" this long

  function goodTitle(s) {
    if (typeof s !== 'string') return false;
    s = s.trim();
    return s.length >= 2 && s.length <= 120 && !PAGE_WORDS.test(s) && !UI_WORDS.test(s) && !/^[\d:.\s/-]+$/.test(s);
  }

  // A Suno clip object has title plus at least one data field (id/audio_url/...).
  // Plain props like {title: "Play"} must not be mistaken for a song.
  function titleFromObject(v, depth) {
    if (!v || typeof v !== 'object' || depth < 0) return '';
    if (goodTitle(v.title) && (v.id || v.clip_id || v.audio_url || v.video_url || v.duration || v.created_at || v.name)) return v.title.trim();
    if (goodTitle(v.name) && (v.audio_url || v.video_url || v.clip_id)) return v.name.trim();
    if (depth === 0) return '';
    for (var k in v) {
      var child = v[k];
      if (!child || typeof child !== 'object') continue;
      var t = titleFromObject(child, depth - 1);
      if (t) return t;
    }
    return '';
  }

  function titleFromHooks(state) {
    var n = 0;
    while (state && typeof state === 'object' && n++ < 60) {
      var t = titleFromObject(state.memoizedState, 2);
      if (t) return t;
      state = state.next;
    }
    return '';
  }

  // Walk up from a clicked node through React fibers to the song card.
  function titleFromFiber(node) {
    var fiberKey = null, propsKey = null;
    try {
      for (var k in node) {
        if (k.indexOf('__reactFiber$') === 0) fiberKey = k;
        else if (k.indexOf('__reactProps$') === 0) propsKey = k;
      }
    } catch (e) { return ''; }
    if (propsKey) {
      var pt = titleFromObject(node[propsKey], 2);
      if (pt) return pt;
    }
    var f = fiberKey ? node[fiberKey] : null;
    var i = 0;
    while (f && i++ < 50) {
      var t = titleFromObject(f.memoizedProps, 2) || titleFromHooks(f.memoizedState);
      if (t) return t;
      f = f.return;
    }
    return '';
  }

  function titleFromDom(node) {
    var el = node;
    for (var i = 0; el && el !== document.body && i < 8; i++, el = el.parentElement) {
      var attrs = el.querySelectorAll ? el.querySelectorAll('[title],[aria-label]') : [];
      for (var j = 0; j < Math.min(attrs.length, 40); j++) {
        var a = attrs[j].getAttribute('title') || attrs[j].getAttribute('aria-label') || '';
        if (goodTitle(a)) return a.trim();
      }
      var text = (el.innerText || el.textContent || '').trim();
      if (!text) continue;
      var lines = text.split('\n').map(function (s) { return s.trim(); }).filter(goodTitle);
      if (lines.length) return lines[0];
    }
    return '';
  }

  // A click captures the name. It belongs to exactly ONE track:
  //  - if a track was just created without a name, fill that one;
  //  - otherwise hold it for the next track to snapshot.
  // Either way the name is consumed (cleared) so it can never be reused by a
  // later song — that reuse was the "all songs share the first name" bug.
  // The user clicked a different song: end the current track so the next init
  // can create a new one. Driven by a recognized song click (title found) —
  // clicking play/pause of the SAME song yields no title and won't split it.
  function openSession() {
    if (activeTrackId && tracks[activeTrackId]) {
      finalizeTrack(tracks[activeTrackId], true);
    }
    activeTrackId = null;
  }

  function setSongTitle(t) {
    if (!t || !goodTitle(t)) return;
    lastPlayTitle = t;
    lastPlayAt = Date.now();
    for (var i = order.length - 1; i >= 0; i--) {
      var tr = tracks[order[i]];
      if (tr && tr.source === 'mse' && !tr.named &&
          (Date.now() - tr.startedAt < TITLE_ATTACH_MS)) {
        tr.title = t;
        tr.named = true;
        lastPlayTitle = ''; lastPlayAt = 0; // consumed
        adoptMoonlitByTitle(tr);
        postUpdate();
        return;
      }
    }
  }

  // Click capture: prefer React fiber (the clip object), fall back to the
  // clicked card's own text (song cards show the name). Keep a short log for
  // diagnosis. Never scan the player bar or network JSON — both give UI junk.
  var clickLog = [];
  document.addEventListener('click', function (e) {
    if (!captureOn || !e.target || !e.target.nodeType) return;
    var el = e.target.nodeType === 1 ? e.target : e.target.parentElement;
    var found = '';
    for (var i = 0; el && el !== document.body && i < 10; i++, el = el.parentElement) {
      found = titleFromFiber(el);
      if (found) break;
      // Card text fallback: only the element clicked and its immediate parent,
      // and only the first short line — avoids pulling in UI labels.
      if (i < 2 && el.innerText) {
        var line = el.innerText.trim().split('\n')[0].trim();
        if (goodTitle(line) && line.length <= 80) { found = line; break; }
      }
    }
    var txt = ((e.target.innerText || e.target.textContent || '') + '').trim().slice(0, 60);
    clickLog.push({
      tag: (e.target.tagName || '').toLowerCase(),
      text: txt, title: found || null, at: Date.now()
    });
    if (clickLog.length > 20) clickLog.shift();
    // A click on something with text inside the song list is a song selection.
    // Open a new session even if we failed to read the exact name — switching
    // songs must never depend on title extraction succeeding.
    // Song identity comes from the audio data (see recordAppend), not from
    // clicks. A click only supplies the NAME for a new song. Clicks that show
    // no recognizable song, or a song we already hold, are ignored: they must
    // neither split the current capture nor leave a stale name behind for the
    // next song.
    if (!found) return;
    openSession();
    setSongTitle(found);
  }, true);

  // NOTE: the earlier fetch/XHR title scrape was removed. It grabbed the first
  // clip-like object out of ANY json response — including recommendation feeds
  // with unrelated songs — which is why titles became wrong/random. Without
  // seeing Suno's real DOM/JSON we cannot reliably map a network clip to the
  // song actually playing. The click on a song card is the only signal tied to
  // the specific song the user chose, so it is the only title source now.
  // A diagnostic (window.__mimiCapture.probeTitle) is provided below to capture
  // real data if clicking still fails.

  // The player usually publishes the playing song to the Media Session API
  // (lock-screen / media-key metadata). It names the song that is actually
  // playing, unlike a click, which can resolve to the wrong card.
  function mediaTitle() {
    try {
      var md = navigator.mediaSession && navigator.mediaSession.metadata;
      var t = md && typeof md.title === 'string' ? md.title.trim() : '';
      return goodTitle(t) ? t : '';
    } catch (e) { return ''; }
  }
  // The metadata can lag a moment behind the first segment: sample a few
  // times, and only while this track is still the current one (so a quick
  // switch can never rename it with the next song's title).
  function scheduleMediaTitle(tr) {
    [1200, 3500, 7000].forEach(function (ms) {
      setTimeout(function () {
        if (tracks[tr.id] !== tr || activeTrackId !== tr.id) return;
        var t = mediaTitle();
        if (t && tr.title !== t) {
          tr.title = t;
          tr.named = true;
          if (tr.source === 'mse') adoptMoonlitByTitle(tr);
          postUpdate();
        }
      }, ms);
    });
  }

  function titleFromPage() {
    if (lastPlayTitle && Date.now() - lastPlayAt < TITLE_MAX_AGE) return lastPlayTitle;
    return 'Suno track';
  }

  function postUpdate() {
    var list = order.map(function (id) {
      var tr = tracks[id];
      return { id: tr.id, title: tr.title, bytes: tr.bytes, status: tr.status };
    });
    window.postMessage({ source: 'mimi-capture-main', type: 'tracks-update', tracks: list }, '*');
  }

  function newSession() {
    // Full: evict the oldest already-finished track to make room, so a new
    // song is never silently dropped ("previous ones stopped loading").
    if (order.length >= MAX_TRACKS) {
      var victim = null;
      for (var i = 0; i < order.length; i++) {
        var t = tracks[order[i]];
        if (t && t.status !== 'Capturing') { victim = t; break; }
      }
      if (!victim) return null; // all still capturing: wait for a quiet timer
      clearTimer(victim);
      delete tracks[victim.id];
      order = order.filter(function (x) { return x !== victim.id; });
    }
    var id = shortId();
    // Snapshot the pending name and consume it immediately — a name is used
    // once only, so later songs never inherit the first song's name.
    var named = !!(lastPlayTitle && Date.now() - lastPlayAt < TITLE_MAX_AGE);
    var tr = { id: id, title: named ? lastPlayTitle : 'Suno track', named: named,
      chunks: [], bytes: 0, status: 'Capturing', source: 'mse',
      startedAt: Date.now(), timer: null,
      duration: 0, timescale: 0, maxMediaTime: -1, sawMedia: false };
    if (named) { lastPlayTitle = ''; lastPlayAt = 0; }
    tracks[id] = tr;
    order.push(id);
    return tr;
  }

  // Coverage = how much of the song's timeline has been appended.
  // Returns -1 when timing is unknown (no usable moov/mvhd or tfdt).
  function coverage(tr) {
    // mvhd duration and tfdt baseMediaDecodeTime share the same timescale,
    // so the ratio is a direct division. timescale is kept for diagnostics.
    if (!tr.duration || !tr.timescale || tr.maxMediaTime < 0) return -1;
    return tr.maxMediaTime / tr.duration;
  }

  // Whatever the player appended is savable. Ready means "the player stopped
  // feeding this song" (switch / seek / EOS / quiet), NOT "the song played to
  // the end". No coverage gate: short/early switches still give a full file
  // because Suno buffers the whole track into MSE within seconds of play.
  // Provable completeness, used when fast capture is OFF (the player then only
  // buffers a little ahead of the playhead, so "no new data for a while" does
  // NOT mean the song is complete). Complete = the player signalled end of
  // stream, or every segment of the timeline has been appended.
  function noteSegTime(tr, mt) {
    var a = tr._mts || (tr._mts = []);
    a.push(mt);
    a.sort(function (x, y) { return x - y; });
    var m = 0;
    for (var i = 1; i < a.length; i++) {
      var g = a[i] - a[i - 1];
      if (g > 0 && (m === 0 || g < m)) m = g;
    }
    tr.segLen = m;
  }
  function timingKnown(tr) {
    return !!(tr.duration && tr.timescale && tr.maxMediaTime >= 0 && tr.source !== 'blob');
  }
  function isComplete(tr) {
    if (tr.eos) return true;
    if (tr.source === 'blob') return true;
    if (!timingKnown(tr) || !tr.segLen || !tr._mts) return false;
    var expected = Math.ceil((tr.duration * 0.98) / tr.segLen);
    return tr._mts.length >= expected && (tr.maxMediaTime + tr.segLen) >= tr.duration * 0.98;
  }

  // forced = the player moved on (song switched): decide now. Otherwise (quiet
  // timer) a not-yet-complete track keeps waiting when fast capture is off.
  function finalizeTrack(tr, forced) {
    if (!tr || tr.status !== 'Capturing' || tr.bytes <= 0) return;
    if (tr._warming) return; // don't finish while waiting for the preload seek
    if (!autoSeek && timingKnown(tr) && !isComplete(tr)) {
      if (!forced) return; // still buffering normally: keep waiting
      tr.status = 'Incomplete'; // switched away before the song was fully buffered
      tr.endedAt = Date.now();
      clearTimer(tr);
      postUpdate();
      return;
    }
    tr.status = 'Ready to save';
    tr.complete = isComplete(tr);
    tr.endedAt = Date.now();
    clearTimer(tr);
    postUpdate();
  }

  function armQuietTimer(tr) {
    if (tr.timer) clearTimeout(tr.timer);
    if (tr._warming) return; // quiet timer starts after warmup/seek completes
    tr.timer = setTimeout(function () {
      if (tr.status === 'Capturing' && tr.bytes > 0) finalizeTrack(tr);
    }, QUIET_MS);
  }

  function clearTimer(tr) {
    if (tr.timer) { clearTimeout(tr.timer); tr.timer = null; }
    if (tr._gateTimer) { clearTimeout(tr._gateTimer); tr._gateTimer = null; }
  }

  function copyBytes(data) {
    try {
      if (data instanceof ArrayBuffer) return data.slice(0);
      if (data && data.buffer instanceof ArrayBuffer) {
        var off = data.byteOffset || 0;
        return data.buffer.slice(off, off + data.byteLength);
      }
    } catch (e) { /* ignore */ }
    return null;
  }

  function isInitSegment(buf) {
    try {
      var d = new Uint8Array(buf);
      return d.length > 8 && d[4] === 0x66 && d[5] === 0x74 && d[6] === 0x79 && d[7] === 0x70; // 'ftyp'
    } catch (e) { return false; }
  }

  // Content signature of an init segment (ftyp+moov). The player re-appends the
  // SAME init bytes when it re-initializes MSE on seek. Comparing signatures
  // lets us tell a same-song re-init from a real song switch — without this,
  // every auto-seek spawns a new track and fills up all 8 slots with one song.
  function initSig(buf) {
    try {
      var d = new Uint8Array(buf);
      var h = 2166136261;
      // Hash EVERY byte: sampling skipped the few bytes (duration) that differ
      // between songs, making different songs look identical.
      var step = 1;
      for (var i = 0; i < d.length; i += step) {
        h ^= d[i];
        h = (h * 16777619) >>> 0;
      }
      return d.length + ':' + h.toString(36);
    } catch (e) { return ''; }
  }

  // Find an existing track for the same song, across ALL SourceBuffers.
  // Match by init bytes, or by duration/timescale in a short window (covers
  // mvhd duration changing from unknown to real between appends).
  function findTrackForInit(sig, timing) {
    for (var i = 0; i < order.length; i++) {
      var t = tracks[order[i]];
      if (!t) continue;
      if (sig && t.initSig && sig === t.initSig) return t;
      if (timing && t.duration && t.timescale &&
          timing.duration === t.duration && timing.timescale === t.timescale &&
          (Date.now() - t.startedAt < 8000)) return t;
    }
    return null;
  }

  function recordAppend(sb, data) {
    if (!captureOn) return;
    var buf = copyBytes(data);
    if (!buf || buf.byteLength === 0) return;
    var isInit = isInitSegment(buf);
    var sig = isInit ? initSig(buf) : '';
    var timing = isInit ? parseInitTiming(buf) : null;

    // The network layer superseded this song: a re-init (e.g. from the
    // fallback seek) must not respawn a duplicate track.
    if (isInit && sig && tombstoneInits.indexOf(sig) >= 0) {
      sbToSession.set(sb, DUP_SINK);
      return;
    }

    var id = sbToSession.get(sb);
    var tr = id ? tracks[id] : null;

    // This SourceBuffer is replaying a song we already hold: drop its media
    // segments so no duplicate track (same name) is created. A new init
    // segment is still evaluated below.
    if (id === DUP_SINK && !isInit) return;

    // The player plays ONE song at a time. While a current track exists and is
    // still fresh, EVERY init belongs to it — re-init from auto-seek, a new
    // SourceBuffer, etc. Never guess from init bytes; just reuse the current
    // track. Only a recognized song click (openSession) clears activeTrackId.
    var active = activeTrackId ? tracks[activeTrackId] : null;
    var activeFresh = active && (active.status === 'Capturing' ||
        (Date.now() - (active.endedAt || active.startedAt) < ACTIVE_GRACE_MS));
    // Same song as the active track unless both durations are known and differ.
    // Different init bytes mean a different song (a same-song re-init appends
    // identical bytes), so a song switched to while the previous one is still
    // loading is never merged into the old track.
    var sameAsActive = !!(active && isInit && (
        (sig && active.initSig && sig === active.initSig) ||
        (timing && active.duration && active.timescale &&
         timing.duration === active.duration && timing.timescale === active.timescale)));
    if (isInit && activeFresh && sameAsActive) {
      active._seekDone = true;
      sbToSession.set(sb, active.id);
      if (timing) { active.duration = timing.duration; active.timescale = timing.timescale; }
      if (active.status !== 'Capturing' && active.status !== 'Incomplete' && !active.complete) {
        active.status = 'Capturing'; // reopen if quiet timer had finished it
        active.endedAt = 0;
      }
      armQuietTimer(active);
      postUpdate();
      return;
    }

    // A song we already hold (same full init bytes, or the same exact
    // duration): never capture it twice. Still capturing -> keep appending to
    // that track; already finished -> ignore this replay. To capture a song
    // again, remove its track with the x button first.
    if (isInit) {
      var same = null;
      for (var si = 0; si < order.length; si++) {
        var st = tracks[order[si]];
        if (!st) continue;
        if ((sig && st.initSig && sig === st.initSig) ||
            (timing && st.duration && st.timescale &&
             timing.duration === st.duration && timing.timescale === st.timescale)) { same = st; break; }
      }
      if (same) {
        if (same.status === 'Capturing') {
          sbToSession.set(sb, same.id);
          activeTrackId = same.id;
          armQuietTimer(same);
          postUpdate();
        } else {
          sbToSession.set(sb, DUP_SINK);
        }
        return;
      }
      // A different song starts: close the previous one.
      if (active && active.status === 'Capturing') finalizeTrack(active, true);
    }

    // No current song (or it was explicitly switched away) => new song.
    if (tr && isInit && tr.sawMedia) {
      finalizeTrack(tr, true);
      sbToSession.delete(sb);
      tr = null;
    }
    // A media segment whose track no longer exists (evicted, superseded by
    // the network layer) must not spawn a junk track: MSE always appends the
    // init segment first, so media-only appends belong to a dead session.
    if (!tr && !isInit) return;
    if (!tr) {
      tr = newSession();
      if (!tr) return;
      sbToSession.set(sb, tr.id);
      if (isInit) {
        // Pre-link identity: if the active track is a just-created moonlit
        // track (the network layer captured this song before its MSE stream
        // started), or a moonlit track already carries the exact same title,
        // bind them so the gate adopts instead of duplicating.
        var prevActive = activeTrackId ? tracks[activeTrackId] : null;
        if (prevActive && prevActive.source === 'moonlit' &&
            Date.now() - prevActive.startedAt < 10000) {
          tr.linkedClip = prevActive.clipId;
        } else if (tr.named && tr.title) {
          for (var li = 0; li < order.length; li++) {
            var lt = tracks[order[li]];
            if (lt && lt.source === 'moonlit' && lt.title === tr.title) {
              tr.linkedClip = lt.clipId;
              break;
            }
          }
        } else if (lastDecryptClip && Date.now() - lastDecryptClip.at < 8000) {
          // The player decrypted this clip before appending any MSE data
          // (no track existed to link to): claim the pending clip now.
          tr.linkedClip = lastDecryptClip.id;
        }
        activeTrackId = tr.id;
        scheduleMediaTitle(tr);
      }
    }
    if (tr.status !== 'Capturing') return;
    if (tr.bytes + buf.byteLength > MAX_BYTES) {
      tr.status = 'Incomplete';
      clearTimer(tr);
      postUpdate();
      return;
    }

    if (isInit) {
      tr.initSig = sig;
      if (timing) { tr.duration = timing.duration; tr.timescale = timing.timescale; }
    } else {
      var mt = parseMediaTime(buf);
      // A seek (ours or the player's) can make the player append a segment it
      // already appended; keeping both would repeat that audio in the file.
      if (mt >= 0) {
        tr._seen = tr._seen || {};
        if (tr._seen[mt]) return; // duplicate: must not reset the quiet timer
        tr._seen[mt] = 1;
        noteSegTime(tr, mt);
      }
      if (mt > tr.maxMediaTime) tr.maxMediaTime = mt;
      if (mt >= 0) tr.sawMedia = true;
    }

    tr.chunks.push(buf);
    tr.bytes += buf.byteLength;
    onFirstMediaSegment(tr);
    armQuietTimer(tr);
    if (!autoSeek && isComplete(tr)) finalizeTrack(tr);
    if (preSeek && tr === seekTrack) armRestore(900); // buffering done ~0.9 s after the last segment
    postUpdate();
  }

  function markReadyByMediaSource(ms) {
    var sbs = msToSbs.get(ms) || [];
    var changed = false;
    sbs.forEach(function (sb) {
      var id = sbToSession.get(sb);
      var tr = id ? tracks[id] : null;
      if (tr && tr.status === 'Capturing' && tr.bytes > 0) {
        tr.eos = true; // the player says every segment has been appended
        finalizeTrack(tr, true);
        changed = true;
      }
    });
    if (changed) postUpdate();
  }

  // Hook 1: SourceBuffer.appendBuffer — decrypted init + media segments.
  try {
    if (typeof SourceBuffer !== 'undefined' && SourceBuffer.prototype && SourceBuffer.prototype.appendBuffer) {
      var origAppend = SourceBuffer.prototype.appendBuffer;
      SourceBuffer.prototype.appendBuffer = function (data) {
        var r = origAppend.call(this, data);
        try { recordAppend(this, data); } catch (e) { /* ignore */ }
        return r;
      };
    }
  } catch (e) { /* ignore */ }

  // NOTE: we deliberately do NOT hook SourceBuffer.abort to finalize a track.
  // The player calls abort() on every seek — including the preload seek below.
  // Finalizing there would mark the track Ready and drop all segments appended
  // after the seek. Quiet timer / EOS / new-init already finalize safely.

  // Hooks 2+3: MediaSource addSourceBuffer (map SB -> MS) and endOfStream
  // (all segments appended => Ready). Same for ManagedMediaSource if present.
  function hookMediaSourceCtor(Ctor) {
    if (!Ctor || !Ctor.prototype) return;
    try {
      if (Ctor.prototype.addSourceBuffer) {
        var origAddSB = Ctor.prototype.addSourceBuffer;
        Ctor.prototype.addSourceBuffer = function (mime) {
          var sb = origAddSB.call(this, mime);
          try {
            var list = msToSbs.get(this) || [];
            list.push(sb);
            msToSbs.set(this, list);
          } catch (e) { /* ignore */ }
          return sb;
        };
      }
    } catch (e) { /* ignore */ }
    try {
      if (Ctor.prototype.endOfStream) {
        var origEOS = Ctor.prototype.endOfStream;
        Ctor.prototype.endOfStream = function () {
          var r = origEOS.apply(this, arguments);
          try { markReadyByMediaSource(this); } catch (e) { /* ignore */ }
          return r;
        };
      }
    } catch (e) { /* ignore */ }
  }
  try { hookMediaSourceCtor(typeof MediaSource !== 'undefined' ? MediaSource : null); } catch (e) { /* ignore */ }
  try { hookMediaSourceCtor(typeof ManagedMediaSource !== 'undefined' ? ManagedMediaSource : null); } catch (e) { /* ignore */ }

  // Hook 4: URL.createObjectURL — progressive path: one whole decrypted
  // audio Blob handed to an <audio> element. That blob is a complete file.
  try {
    var origCreateObjectURL = URL.createObjectURL;
    URL.createObjectURL = function (obj) {
      var url = origCreateObjectURL.call(this, obj);
      try {
        if (obj instanceof Blob && captureOn) {
          var t = (obj.type || '').toLowerCase();
          if (t.indexOf('audio/') === 0 || (t === '' && obj.size >= 1048576)) {
            // The fetch+decrypt layer usually delivers the same song seconds
            // earlier: never keep two complete copies of one track.
            var recentMoonlit = null;
            for (var mi = 0; mi < order.length; mi++) {
              var mt = tracks[order[mi]];
              if (mt && mt.source === 'moonlit' && Date.now() - mt.startedAt < 10000) { recentMoonlit = mt; break; }
            }
            if (recentMoonlit) return url;
            var tr = newSession();
            if (tr) {
              tr.source = 'blob';
              tr.chunks = [obj];
              tr.bytes = obj.size;
              tr.status = 'Ready to save';
              // The blob being handed over IS the song the player is playing
              // right now: fold the in-flight MSE copy into this one.
              var at = activeTrackId ? tracks[activeTrackId] : null;
              if (at && at.source === 'mse' && at.status === 'Capturing') {
                if (!tr.named && at.named && at.title) { tr.title = at.title; tr.named = true; }
                if (at.initSig && tombstoneInits.indexOf(at.initSig) < 0) tombstoneInits.push(at.initSig);
                if (tombstoneInits.length > 32) tombstoneInits.shift();
                clearTimer(at);
                delete tracks[at.id];
                order = order.filter(function (x) { return x !== at.id; });
              }
              activeTrackId = tr.id;
              postUpdate();
            }
          }
        }
      } catch (e) { /* ignore */ }
      return url;
    };
  } catch (e) { /* ignore */ }

  // --- Layer A: passive network + key observation (moonlit-style) ---
  // Suno's progressive path fetches the WHOLE encrypted clip in one response
  // and decrypts it in page JS with AES-CTR. Listen on both, touch nothing:
  // clone the response (the player's own promise is returned untouched) and
  // observe decrypt calls to learn the key, then decrypt the full ciphertext
  // ourselves. Zero player interaction => zero pause. If this layer delivers
  // a complete file for the current song, the MSE track is dropped and the
  // auto-seek fallback never fires. If it cannot (streaming path, Worker
  // decrypt, partial response), the MSE layer + auto-seek still cover it.
  var moonlitOK = false;
  var MOONLIT_WAIT_MS = 6000;   // how long to wait for the network layer before fallback seek
  var MAX_CIPHERS = 8;
  var subtle = (window.crypto && window.crypto.subtle) || null;
  var origFetch = null, origDecrypt = null, decryptDesc = null;
  var playbackKeys = new Map(); // ciphertext-head fingerprint -> {key, counter, length}
  var ciphers = new Map();      // clip id -> {data, ext, state}
  var lastDecryptClip = null;   // {id, at}: a decrypt fired while no MSE track existed yet

  function u8view(v) {
    return ArrayBuffer.isView(v)
      ? new Uint8Array(v.buffer, v.byteOffset, v.byteLength)
      : new Uint8Array(v);
  }
  function headFp(v) {
    var b = u8view(v), s = '';
    for (var i = 0; i < 16 && i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    return s;
  }
  function sniffFormat(v) {
    var b = u8view(v);
    if (b.length >= 12 && b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70)
      return { ext: 'm4a', mime: 'audio/mp4' };
    if (b.length >= 4 && b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3)
      return { ext: 'webm', mime: 'audio/webm' };
    return null;
  }

  // A full decrypted clip arrived: register it as a Ready track and drop any
  // MSE track of the same song. Identity is decided by the decrypt-side LINK
  // (the player decrypted this exact clip while this MSE track was active),
  // falling back to mvhd duration + timescale. Duration alone is NOT enough:
  // Suno's streaming init segment often carries an unknown (0xFFFFFFFF)
  // duration, which is why the old duration-only check let duplicates live.
  function moonlitReady(clipId, pt, ext, fetchedAt) {
    if (!captureOn) return;
    var fmt = sniffFormat(pt);
    if (!fmt) return;
    var timing = parseInitTiming(pt);
    for (var k = 0; k < order.length; k++) {
      var e = tracks[order[k]];
      if (e && e.source === 'moonlit' && e.clipId === clipId) return; // already held
    }
    var m = newSession();
    if (!m) {
      // The moonlit copy is already complete: it must not be lost. Evict the
      // oldest in-flight MSE track to make room.
      for (var i = 0; i < order.length; i++) {
        var t0 = tracks[order[i]];
        if (t0 && t0.source === 'mse') {
          clearTimer(t0);
          delete tracks[t0.id];
          order = order.filter(function (x) { return x !== t0.id; });
          break;
        }
      }
      m = newSession();
      if (!m) return;
    }
    m.source = 'moonlit';
    m.clipId = clipId;
    m.chunks = [pt.buffer.slice(pt.byteOffset, pt.byteOffset + pt.byteLength)];
    m.bytes = pt.byteLength;
    m.status = 'Ready to save';
    m.complete = true;
    m.extension = ext || fmt.ext;
    if (timing) { m.duration = timing.duration; m.timescale = timing.timescale; }
    activeTrackId = m.id;
    scheduleMediaTitle(m);
    // The same song may also be streaming via MSE: keep one copy only.
    for (var j = order.length - 1; j >= 0; j--) {
      var t = tracks[order[j]];
      if (!t || t === m || t.source !== 'mse') continue;
      var sameSong = (t.linkedClip === clipId) ||
        (m.duration && t.duration && m.timescale === t.timescale && m.duration === t.duration) ||
        (m.named && t.named && t.title && t.title === m.title);
      if (sameSong) {
        if (!m.named && t.named && t.title) { m.title = t.title; m.named = true; }
        if (t.initSig && tombstoneInits.indexOf(t.initSig) < 0) tombstoneInits.push(t.initSig);
        if (tombstoneInits.length > 32) tombstoneInits.shift();
        clearTimer(t);
        delete tracks[t.id];
        order = order.filter(function (x) { return x !== t.id; });
      }
    }
    // Last resort for the race where the clip download started at play time
    // and finishes AFTER the MSE track was created, with the decrypt-side
    // link never set (no track existed at decrypt time): the clip being
    // decrypted IS the song playing now, so if the current MSE track began
    // right around this cipher's fetch, it is the same song. Guarded by the
    // fetch timestamp so a late-arriving OLD song's clip can never swallow
    // the NEW song's MSE track.
    var at2 = activeTrackId ? tracks[activeTrackId] : null;
    if (at2 && at2.source === 'mse' && at2.status === 'Capturing' &&
        typeof fetchedAt === 'number' &&
        Math.abs(at2.startedAt - fetchedAt) < 8000) {
      if (!m.named && at2.named && at2.title) { m.title = at2.title; m.named = true; }
      if (at2.initSig && tombstoneInits.indexOf(at2.initSig) < 0) tombstoneInits.push(at2.initSig);
      if (tombstoneInits.length > 32) tombstoneInits.shift();
      clearTimer(at2);
      delete tracks[at2.id];
      order = order.filter(function (x) { return x !== at2.id; });
      if (activeTrackId === at2.id) activeTrackId = m.id;
    }
    postUpdate();
  }

  function moonlitHasMatch(tr) {
    if (!moonlitOK || !tr) return null;
    for (var i = 0; i < order.length; i++) {
      var t = tracks[order[i]];
      if (!t || t.source !== 'moonlit') continue;
      if ((tr.linkedClip && t.clipId === tr.linkedClip) ||
          (tr.duration && t.duration === tr.duration && t.timescale === tr.timescale)) return t;
    }
    return null;
  }

  // The network layer just proved it covers the song the MSE layer was
  // capturing: drop the MSE copy (transfer its name if it had one).
  function adoptMoonlitMatch(tr) {
    var m = moonlitHasMatch(tr);
    if (!m) return false;
    if (!m.named && tr.named && tr.title) { m.title = tr.title; m.named = true; }
    if (tr.initSig && tombstoneInits.indexOf(tr.initSig) < 0) tombstoneInits.push(tr.initSig);
    if (tombstoneInits.length > 32) tombstoneInits.shift();
    clearTimer(tr);
    delete tracks[tr.id];
    order = order.filter(function (x) { return x !== tr.id; });
    if (activeTrackId === tr.id) activeTrackId = m.id;
    postUpdate();
    return true;
  }

  // Final safety net: an MSE track that ended up with the exact title of an
  // already-held moonlit copy is a duplicate (its init carried no usable
  // duration and no link survived the switch race). Keep the complete copy.
  function adoptMoonlitByTitle(tr) {
    if (!tr || tr.source !== 'mse' || !tr.named || !tr.title) return false;
    for (var i = 0; i < order.length; i++) {
      var t = tracks[order[i]];
      if (t && t.source === 'moonlit' && t.named && t.title === tr.title) {
        if (t.initSig || tr.initSig) {
          var s = tr.initSig || t.initSig;
          if (tombstoneInits.indexOf(s) < 0) tombstoneInits.push(s);
          if (tombstoneInits.length > 32) tombstoneInits.shift();
        }
        clearTimer(tr);
        delete tracks[tr.id];
        order = order.filter(function (x) { return x !== tr.id; });
        if (activeTrackId === tr.id) activeTrackId = t.id;
        postUpdate();
        return true;
      }
    }
    return false;
  }

  function tryMoonlitDecrypt(id) {
    var c = ciphers.get(id);
    if (!c || c.state !== 'waiting for key' || !origDecrypt) return;
    var pk = playbackKeys.get(headFp(c.data));
    if (!pk) return;
    c.state = 'decrypting';
    origDecrypt.call(subtle, { name: 'AES-CTR', counter: pk.counter, length: pk.length }, pk.key, c.data)
      .then(function (pt) {
        ciphers.delete(id);
        moonlitReady(id, new Uint8Array(pt), c.ext, c.fetchedAt);
      })
      .catch(function () { c.state = 'waiting for key'; });
  }

  function moonlitCapture(response, request) {
    if (!captureOn || !response || !response.ok) return;
    var url;
    try { url = new URL(response.url || (request && request.url) || String(request || ''), location.href); }
    catch (e) { return; }
    var host = url.hostname;
    if (!/(^|\.)suno\.(com|ai)$/i.test(host) && host !== 'd2lwuy8qc234o3.cloudfront.net') return;
    var match = url.pathname.match(/\/clip\/([0-9a-f-]{36})\.(m4a|mp4|webm)$/i);
    if (!match) return;
    var id = match[1];
    for (var i = 0; i < order.length; i++) {
      var t = tracks[order[i]];
      if (t && t.source === 'moonlit' && t.clipId === id) return; // already held
    }
    if (ciphers.has(id)) return;
    var range = response.headers.get('content-range');
    if (response.status === 206 || range) {
      var r = range ? range.match(/^bytes (\d+)-(\d+)\/(\d+)$/i) : null;
      // Only a full response (byte 0 through the end) can be reassembled.
      if (!r || Number(r[1]) !== 0 || Number(r[2]) + 1 !== Number(r[3])) return;
    }
    var clone = response.clone();
    if (!clone.body) return;
    var reader = clone.body.getReader();
    var chunks = [], received = 0;
    var stop = function () { try { reader.cancel(); } catch (e) { /* ignore */ } };
    var finish = function () {
      if (received < 16) return;
      var out = new Uint8Array(received), off = 0;
      for (var j = 0; j < chunks.length; j++) { out.set(chunks[j], off); off += chunks[j].byteLength; }
      chunks = [];
      if (received >= 65536) {
        var zeros = true;
        for (var z = out.length - 65536; z < out.length; z++) { if (out[z] !== 0) { zeros = false; break; } }
        if (zeros) return; // zero-filled tail = truncated response, useless
      }
      ciphers.set(id, { data: out, ext: match[2].toLowerCase(), state: 'waiting for key',
                        clipId: id, linkedTrackId: null, fetchedAt: Date.now() });
      if (ciphers.size > MAX_CIPHERS) {
        var oldest = ciphers.keys().next().value;
        if (oldest !== id) ciphers.delete(oldest);
      }
      tryMoonlitDecrypt(id);
    };
    (function pump() {
      reader.read().then(function (res) {
        if (!captureOn) { stop(); return; }
        if (res.done) { finish(); return; }
        received += res.value.byteLength;
        if (received > MAX_BYTES) { stop(); return; }
        chunks.push(res.value);
        pump();
      }).catch(function () {});
    })();
  }

  // Install the passive hooks. Both wrappers return the ORIGINAL result
  // synchronously; all observation happens in promise callbacks, so the
  // player never waits for us.
  try {
    if (subtle && subtle.decrypt) {
      origFetch = window.fetch;
      origDecrypt = subtle.decrypt;
      decryptDesc = Object.getOwnPropertyDescriptor(subtle, 'decrypt');
      window.fetch = function () {
        var result = origFetch.apply(this, arguments);
        var req = arguments[0];
        try {
          result.then(function (resp) {
            try { moonlitCapture(resp, req); } catch (e) { /* ignore */ }
          }).catch(function () {});
        } catch (e) { /* ignore */ }
        return result;
      };
      subtle.decrypt = function () {
        var result = origDecrypt.apply(this, arguments);
        try {
          var algo = arguments[0], key = arguments[1], input = arguments[2];
          if (algo && String(algo.name).toUpperCase() === 'AES-CTR' && input) {
            var sig = headFp(input);
            var counter = u8view(algo.counter).slice();
            var length = algo.length;
            result.then(function (pt) {
              if (!captureOn || !sniffFormat(pt)) return;
              if (!playbackKeys.has(sig) && playbackKeys.size >= 16) {
                playbackKeys.delete(playbackKeys.keys().next().value);
              }
              playbackKeys.set(sig, { key: key, counter: counter, length: length });
              // The player is decrypting a clip we captured: LINK the current
              // MSE track to that clip. This is the reliable song identity —
              // mvhd duration in streaming init segments is often unknown.
              var matched = null;
              ciphers.forEach(function (c) {
                if (c.linkedTrackId || headFp(c.data) !== sig) return;
                matched = c;
                var at = activeTrackId ? tracks[activeTrackId] : null;
                if (at && at.source === 'mse' &&
                    (at.status === 'Capturing' || Date.now() - at.startedAt < 8000)) {
                  c.linkedTrackId = at.id;
                  at.linkedClip = c.clipId;
                  matched = null;
                }
              });
              // Decrypt fired while no MSE track existed (the click's
              // openSession cleared the active one, and the player decrypts
              // before its first append): remember the clip so the MSE track
              // appearing seconds later can still be linked to it. Without
              // this, moonlitReady lands with no link and no duration to
              // match — exactly the duplicate-track window.
              if (matched) lastDecryptClip = { id: matched.clipId, at: Date.now() };
              var ids = [];
              ciphers.forEach(function (c, cid) { if (c.state === 'waiting for key') ids.push(cid); });
              for (var q = 0; q < ids.length; q++) tryMoonlitDecrypt(ids[q]);
            }).catch(function () {});
          }
        } catch (e) { /* observation must not interrupt playback */ }
        return result;
      };
      moonlitOK = window.fetch !== origFetch && subtle.decrypt !== origDecrypt;
      if (!moonlitOK) { // browser refused the hooks: restore, fall back to MSE only
        window.fetch = origFetch;
        if (decryptDesc) Object.defineProperty(subtle, 'decrypt', decryptDesc);
        else try { delete subtle.decrypt; } catch (e) { /* ignore */ }
      }
    }
  } catch (e) { moonlitOK = false; }

  // --- Auto preload: nudge the player to buffer the whole song (FALLBACK) ---
  // Suno's player buffers lazily (only the part near the playhead, ~0.5-0.7 MB).
  // Seeking near the end makes it append the remaining segments immediately —
  // exactly what a user does by dragging the slider to the end. We replicate
  // that by setting the media element's currentTime. This uses only the
  // player's own buffering path; no network/API/decrypt/download changes.
  var autoSeek = true;            // internal strategy: passive network layer first, seek fallback when it cannot deliver
  var seekAttempts = 0;
  var seekTrack = null;           // track we are trying to preload
  var SEEK_MAX_TRIES = 16;        // retry while duration is still unknown
  var SEEK_RETRY_MS = 250;
  var SEEK_FROM_END = 0.25;       // seconds before end to seek to
  var SEEK_WARMUP_MS = 3000;      // let the player buffer normally before seeking —
                                  // seeking instantly races MSE init and causes re-init duplicates
  var lastSeekSig = '';           // global throttle: avoid re-seeking same song
  var lastSeekAt = 0;
  var SEEK_THROTTLE_MS = 8000;    // ignore repeat seeks for the same song within 8 s

  function findPlayerMedia() {
    var els = document.querySelectorAll('audio, video');
    var best = null;
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      var src = el.currentSrc || el.src || '';
      if (src.indexOf('blob:') === 0) return el; // MediaSource-backed player
      best = best || el;
    }
    return best;
  }

  // Duration source priority: media element, then mvhd parsed from init segment,
  // then seekable range. MSE duration is often NaN until EOS, so the mvhd value
  // (from the player's own init segment) is the reliable fallback.
  function seekDuration(el) {
    if (el.duration && isFinite(el.duration) && el.duration > 0) return el.duration;
    if (seekTrack && seekTrack.duration && seekTrack.timescale) {
      var sec = seekTrack.duration / seekTrack.timescale;
      if (sec > 0 && isFinite(sec)) return sec;
    }
    try { if (el.seekable && el.seekable.length && el.seekable.end(0) > 0) return el.seekable.end(0); } catch (e) {}
    return 0;
  }

  // The preload seek jumps the playhead to the end of the song. Remember where
  // the listener was and put them back there once the buffering has finished,
  // otherwise the song "ends" a moment later and Suno restarts it.
  var preSeek = null, restoreTimer = null;
  function armRestore(ms) {
    if (!preSeek) return;
    if (restoreTimer) clearTimeout(restoreTimer);
    restoreTimer = setTimeout(restorePlayback, ms);
  }
  function restorePlayback() {
    var ps = preSeek;
    preSeek = null; restoreTimer = null;
    if (!ps) return;
    // The user switched songs meanwhile: the media element now belongs to the
    // new song, leave it alone.
    if (!seekTrack || activeTrackId !== seekTrack.id) return;
    var el = ps.el;
    if ((el.currentSrc || el.src || '') !== ps.src) return;
    try { el.currentTime = ps.time; } catch (e) { /* ignore */ }
    if (ps.wasPlaying) {
      try { var pr = el.play(); if (pr && pr.catch) pr.catch(function () {}); } catch (e) { /* ignore */ }
    }
  }

  function seekToEnd() {
    if (!autoSeek || !captureOn || seekAttempts >= SEEK_MAX_TRIES) return;
    if (seekTrack && activeTrackId !== seekTrack.id) return; // song was switched
    var el = findPlayerMedia();
    if (!el) { scheduleSeekRetry(); return; }
    var d = seekDuration(el);
    if (!d || !isFinite(d) || d <= 0) { scheduleSeekRetry(); return; }
    var target = Math.max(0, d - SEEK_FROM_END);
    // Don't re-seek if already at/near the target (avoids loops).
    if (Math.abs((el.currentTime || 0) - target) < 0.5) return;
    try {
      if (!preSeek) {
        preSeek = { el: el, time: el.currentTime || 0, wasPlaying: !el.paused,
                    src: el.currentSrc || el.src || '' };
      }
      // Pause so the song cannot reach its end (and restart) while buffering.
      try { el.pause(); } catch (e2) { /* ignore */ }
      el.currentTime = target;
      seekAttempts++;
      armRestore(6000); // fallback if no further segments arrive
    } catch (e) { scheduleSeekRetry(); }
  }

  function scheduleSeekRetry() {
    if (seekAttempts >= SEEK_MAX_TRIES) return;
    setTimeout(seekToEnd, SEEK_RETRY_MS);
  }

  // Start capture handling once the first media segment of a song arrives.
  // With the passive network layer active we WAIT first: if it delivers the
  // complete file, the MSE track is dropped and the player is never touched
  // (no pause). Only when that fails within the wait window do we fall back
  // to the preload seek (pause + jump to end + restore).
  function onFirstMediaSegment(tr) {
    if (!captureOn) return;
    if (!moonlitOK && !autoSeek) return; // fully passive, old behaviour
    if (tr._seekDone) return;
    tr._seekDone = true;
    if (moonlitOK && moonlitHasMatch(tr)) { adoptMoonlitMatch(tr); return; }
    tr._warming = true; // suppress the quiet timer while we decide
    clearTimer(tr);
    var decide = function () {
      tr._warming = false;
      if (tracks[tr.id] !== tr) return; // dropped: the network layer got it
      if (moonlitOK && moonlitHasMatch(tr)) { adoptMoonlitMatch(tr); return; }
      // A captured cipher is linked to THIS song but not decrypted yet:
      // give the network layer more time before touching the player.
      var pending = false;
      ciphers.forEach(function (c) {
        if ((c.linkedTrackId === tr.id || (tr.linkedClip && c.clipId === tr.linkedClip)) &&
            (c.state === 'waiting for key' || c.state === 'decrypting')) pending = true;
      });
      if (pending && (tr._gateRetries || 0) < 2) {
        tr._gateRetries = (tr._gateRetries || 0) + 1;
        tr._warming = true;
        setTimeout(function () { decide(); }, 5000);
        return;
      }
      if (tr.named && adoptMoonlitByTitle(tr)) return;
      if (!autoSeek) { armQuietTimer(tr); return; }
      // Fallback: nudge the player to buffer the whole song.
      var key = tr.initSig || (tr.duration + ':' + tr.timescale) || '';
      var now = Date.now();
      if (key && key === lastSeekSig && (now - lastSeekAt) < SEEK_THROTTLE_MS) { armQuietTimer(tr); return; }
      lastSeekSig = key;
      lastSeekAt = now;
      seekAttempts = 0;
      seekTrack = tr;
      seekToEnd();
      if (tr.status === 'Capturing') armQuietTimer(tr);
    };
    setTimeout(function () { decide(); }, moonlitOK ? MOONLIT_WAIT_MS : SEEK_WARMUP_MS);
  }

  // Our own download blobs must NOT go through the createObjectURL hook:
  // that hook treats any audio/* blob as the player's audio and would add a
  // new "Suno track" entry for every file we save.
  function rawObjectURL(b) {
    var fn = (typeof origCreateObjectURL === 'function') ? origCreateObjectURL : URL.createObjectURL;
    return fn.call(URL, b);
  }

  // --- Minimal store-only ZIP writer (no libraries) for "Download all" ---
  var CRC_TABLE = null;
  function crc32(u8) {
    if (!CRC_TABLE) {
      CRC_TABLE = new Uint32Array(256);
      for (var n = 0; n < 256; n++) {
        var c0 = n;
        for (var k = 0; k < 8; k++) c0 = (c0 & 1) ? (0xEDB88320 ^ (c0 >>> 1)) : (c0 >>> 1);
        CRC_TABLE[n] = c0 >>> 0;
      }
    }
    var c = 0xFFFFFFFF;
    for (var i = 0; i < u8.length; i++) c = CRC_TABLE[(c ^ u8[i]) & 0xFF] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }
  function trackBytes(tr) {
    return Promise.all(tr.chunks.map(function (ch) {
      return (ch instanceof Blob) ? ch.arrayBuffer() : Promise.resolve(ch);
    })).then(function (bufs) {
      var total = 0, o = 0;
      bufs.forEach(function (b) { total += b.byteLength; });
      var out = new Uint8Array(total);
      bufs.forEach(function (b) { out.set(new Uint8Array(b), o); o += b.byteLength; });
      return out;
    });
  }
  function zipBlob(entries) {
    var enc = new TextEncoder(), parts = [], central = [], offset = 0;
    var d = new Date();
    var dosTime = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
    var dosDate = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
    entries.forEach(function (e) {
      var name = enc.encode(e.name), crc = crc32(e.data), size = e.data.length;
      var lh = new DataView(new ArrayBuffer(30));
      lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint16(6, 0x0800, true);
      lh.setUint16(8, 0, true); lh.setUint16(10, dosTime, true); lh.setUint16(12, dosDate, true);
      lh.setUint32(14, crc, true); lh.setUint32(18, size, true); lh.setUint32(22, size, true);
      lh.setUint16(26, name.length, true); lh.setUint16(28, 0, true);
      parts.push(lh.buffer, name, e.data);
      var ch = new DataView(new ArrayBuffer(46));
      ch.setUint32(0, 0x02014b50, true); ch.setUint16(4, 20, true); ch.setUint16(6, 20, true);
      ch.setUint16(8, 0x0800, true); ch.setUint16(10, 0, true); ch.setUint16(12, dosTime, true);
      ch.setUint16(14, dosDate, true); ch.setUint32(16, crc, true); ch.setUint32(20, size, true);
      ch.setUint32(24, size, true); ch.setUint16(28, name.length, true);
      ch.setUint32(42, offset, true);
      central.push(ch.buffer, name);
      offset += 30 + name.length + size;
    });
    var cdSize = 0;
    central.forEach(function (p) { cdSize += p.byteLength; });
    var eocd = new DataView(new ArrayBuffer(22));
    eocd.setUint32(0, 0x06054b50, true);
    eocd.setUint16(8, entries.length, true); eocd.setUint16(10, entries.length, true);
    eocd.setUint32(12, cdSize, true); eocd.setUint32(16, offset, true);
    return new Blob(parts.concat(central, [eocd.buffer]), { type: 'application/zip' });
  }
  function safeName(s) {
    return String(s || 'Suno track').replace(/[\\/:*?"<>|]/g, '-').trim() || 'Suno track';
  }
  // One click: every "Ready to save" track goes into a single .zip.
  function saveAllZip(names) {
    var ready = order.filter(function (id) {
      return tracks[id] && tracks[id].status === 'Ready to save';
    });
    if (!ready.length) return;
    if (ready.length === 1) { downloadTrack(ready[0], names[ready[0]] || tracks[ready[0]].title); return; }
    var used = {};
    Promise.all(ready.map(function (id) { return trackBytes(tracks[id]); })).then(function (datas) {
      var entries = ready.map(function (id, i) {
        var base = safeName(names[id] || tracks[id].title), name = base + '.m4a', n = 2;
        while (used[name.toLowerCase()]) name = base + ' (' + (n++) + ').m4a';
        used[name.toLowerCase()] = 1;
        return { name: name, data: datas[i] };
      });
      var url = rawObjectURL(zipBlob(entries));
      var a = document.createElement('a');
      var t = new Date(), p2 = function (x) { return (x < 10 ? '0' : '') + x; };
      a.href = url;
      a.download = 'suno-mimi-' + t.getFullYear() + p2(t.getMonth() + 1) + p2(t.getDate()) +
        '-' + p2(t.getHours()) + p2(t.getMinutes()) + p2(t.getSeconds()) + '.zip';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 30000);
      ready.forEach(function (id) {
        window.postMessage({ source: 'mimi-capture-main', type: 'save-done', id: id }, '*');
      });
    }).catch(function () {
      ready.forEach(function (id) {
        window.postMessage({ source: 'mimi-capture-main', type: 'save-failed', id: id, reason: 'error' }, '*');
      });
    });
  }

  // Download one track in page origin: build blob URL here (MAIN world), click
  // an anchor, then revoke. The bridge never touches audio bytes.
  function downloadTrack(id, filename) {
    var tr = tracks[id];
    if (!tr || tr.status !== 'Ready to save') {
      window.postMessage({ source: 'mimi-capture-main', type: 'save-failed', id: id, reason: 'not-ready' }, '*');
      return;
    }
    try {
      var blob = new Blob(tr.chunks, { type: 'audio/mp4' });
      var url = rawObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = (filename || tr.title || 'Suno track').replace(/[\\/:*?"<>|]/g, '-') + '.' + (tr.extension || 'm4a');
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
      window.postMessage({ source: 'mimi-capture-main', type: 'save-done', id: id }, '*');
    } catch (e) {
      window.postMessage({ source: 'mimi-capture-main', type: 'save-failed', id: id, reason: 'error' }, '*');
    }
  }

  // Listen for control messages from the isolated bridge (toggle, clear, remove).
  window.addEventListener('message', function (event) {
    if (!event.data || event.data.source !== 'mimi-bridge') return;
    var d = event.data;
    if (d.type === 'set-capture-on') {
      captureOn = !!d.value;
      try { localStorage.setItem('mimi-capture-on', captureOn ? '1' : '0'); } catch (e) { /* ignore */ }
      postUpdate();
    } else if (d.type === 'clear-all') {
      order.forEach(function (id) { if (tracks[id]) clearTimer(tracks[id]); });
      tracks = {};
      order = [];
      sbToSession = new WeakMap();
      ciphers.clear();
      playbackKeys.clear();
      lastSeekSig = '';
      lastSeekAt = 0;
      activeTrackId = null;
      postUpdate();
    } else if (d.type === 'remove-track') {
      var id = d.id;
      if (tracks[id]) {
        clearTimer(tracks[id]);
        delete tracks[id];
        order = order.filter(function (x) { return x !== id; });
        postUpdate();
      }
    } else if (d.type === 'set-auto-seek') {
      autoSeek = !!d.value;
    } else if (d.type === 'request-tracks') {
      postUpdate();
    } else if (d.type === 'save-track') {
      downloadTrack(d.id, d.filename);
    } else if (d.type === 'save-all') {
      // One zip with every ready track (names come from the popup inputs).
      saveAllZip(d.names || {});
    }
  });

  // Restore toggle (page memory only; the stored on/off preference is the
  // only thing persisted, matching Mimi's rule).
  try {
    var saved = localStorage.getItem('mimi-capture-on');
    if (saved === '0') captureOn = false;
  } catch (e) { /* ignore */ }

  // Expose a minimal read-only handle for the bridge to pull bytes on Save.
  window.__mimiCapture = {
    getTrackBlob: function (id) {
      var tr = tracks[id];
      if (!tr || tr.status !== 'Ready to save') return null;
      return new Blob(tr.chunks, { type: 'audio/mp4' });
    },
    getTrackTitle: function (id) {
      return tracks[id] ? tracks[id].title : '';
    },
    debugTitle: function () {
      return {
        resolved: titleFromPage(),
        clicked: lastPlayTitle,
        clickedAgeMs: lastPlayAt ? Date.now() - lastPlayAt : -1,
        documentTitle: document.title
      };
    },
    debugTracks: function () {
      return order.map(function (id) {
        var tr = tracks[id];
        return {
          id: tr.id, title: tr.title, status: tr.status, source: tr.source,
          bytes: tr.bytes, duration: tr.duration, timescale: tr.timescale,
          maxMediaTime: tr.maxMediaTime, coverage: coverage(tr), sawMedia: tr.sawMedia
        };
      });
    },
    setAutoSeek: function (on) { autoSeek = !!on; return autoSeek; },
    getAutoSeek: function () { return autoSeek; },
    // Diagnostic: click the PLAY button of one song, then run this in console.
    // It reports the DOM/fiber signals around the last click so we can find a
    // reliable title source instead of guessing.
    probeTitle: function () {
      var out = { lastPlayTitle: lastPlayTitle, docTitle: document.title, media: [], clicks: clickLog.slice() };
      var els = document.querySelectorAll('audio, video');
      for (var i = 0; i < els.length; i++) {
        var el = els[i];
        out.media.push({ src: (el.currentSrc || el.src || '').slice(0, 120), duration: el.duration });
      }
      // Look for React fiber titles across any elements marked as playing/
      // selected. Report raw strings, filtered only by length.
      var samples = [];
      var all = document.querySelectorAll('[class*="play"], [aria-label], [title]');
      for (var j = 0; j < all.length && samples.length < 40; j++) {
        var node = all[j];
        var fk = null;
        try { for (var k in node) { if (k.indexOf('__reactFiber$') === 0) fk = k; } } catch (e) {}
        if (!fk) continue;
        var f = node[fk], t = '';
        for (var n = 0; f && n < 40 && !t; n++, f = f.return) {
          t = titleFromObject(f.memoizedProps, 2) || titleFromHooks(f.memoizedState);
        }
        if (t) samples.push(t);
      }
      out.fiberSamples = samples;
      return out;
    }
  };
})();