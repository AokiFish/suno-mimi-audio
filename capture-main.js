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
  var msToSbs = new WeakMap(); // MediaSource -> [SourceBuffer]

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
  var TITLE_MAX_AGE = 300000; // remember the clicked name for 5 min
  var TITLE_ATTACH_MS = 5000; // a name arriving this soon after a track may fill it

  // Session gate: ONE click == ONE song. Every init segment arriving inside
  // the session window belongs to that song (auto-seek re-inits included), so
  // a single click can never spawn two tracks. The next click opens a new one.
  var sessionTrackId = null;
  var sessionStart = 0;
  var SESSION_WINDOW_MS = 12000;

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
  // A real song click starts a fresh session: clear which track belongs to it.
  // Called only when a click yields a song name (i.e. clicked a song card).
  function openSession() {
    sessionTrackId = null;
    sessionStart = Date.now();
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
    clickLog.push({
      tag: (e.target.tagName || '').toLowerCase(),
      text: ((e.target.innerText || e.target.textContent || '') + '').trim().slice(0, 60),
      title: found || null,
      at: Date.now()
    });
    if (clickLog.length > 20) clickLog.shift();
    if (found) { openSession(); setSongTitle(found); }
  }, true);

  // NOTE: the earlier fetch/XHR title scrape was removed. It grabbed the first
  // clip-like object out of ANY json response — including recommendation feeds
  // with unrelated songs — which is why titles became wrong/random. Without
  // seeing Suno's real DOM/JSON we cannot reliably map a network clip to the
  // song actually playing. The click on a song card is the only signal tied to
  // the specific song the user chose, so it is the only title source now.
  // A diagnostic (window.__mimiCapture.probeTitle) is provided below to capture
  // real data if clicking still fails.

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
  function finalizeTrack(tr) {
    if (!tr || tr.status !== 'Capturing' || tr.bytes <= 0) return;
    tr.status = 'Ready to save';
    clearTimer(tr);
    postUpdate();
  }

  function armQuietTimer(tr) {
    if (tr.timer) clearTimeout(tr.timer);
    tr.timer = setTimeout(function () {
      if (tr.status === 'Capturing' && tr.bytes > 0) finalizeTrack(tr);
    }, QUIET_MS);
  }

  function clearTimer(tr) {
    if (tr.timer) { clearTimeout(tr.timer); tr.timer = null; }
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
      var step = Math.max(1, Math.floor(d.length / 256)); // sample up to 256 bytes
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

    var id = sbToSession.get(sb);
    var tr = id ? tracks[id] : null;

    // Session gate: if this click's song already has a track, ANY init arriving
    // in the window is that same song being re-initialized by auto-seek. Bind
    // it to the session track and skip the duplicate init — never spawn a new
    // track. This is based on the click (a real event), not on guessing bytes.
    if (isInit && sessionTrackId && tracks[sessionTrackId] &&
        (Date.now() - sessionStart < SESSION_WINDOW_MS)) {
      var sess = tracks[sessionTrackId];
      sess._seekDone = true;
      sbToSession.set(sb, sess.id);
      if (timing) { sess.duration = timing.duration; sess.timescale = timing.timescale; }
      // A re-init may arrive after the quiet timer marked it Ready; reopen it.
      if (sess.status !== 'Capturing' && sess.status !== 'Incomplete') sess.status = 'Capturing';
      armQuietTimer(sess);
      postUpdate();
      return;
    }

    // Fallback: content-based same-song match (covers cases where no click was
    // captured, e.g. autoplay / keyboard). Reuse instead of duplicating.
    if (isInit) {
      var same = findTrackForInit(sig, timing);
      if (same) {
        same._seekDone = true;
        sbToSession.set(sb, same.id);
        if (timing) { same.duration = timing.duration; same.timescale = timing.timescale; }
        armQuietTimer(same);
        postUpdate();
        return;
      }
    }

    // No session track and no content match => a genuinely new song. Create it
    // and make it this session's track.
    if (tr && isInit && tr.sawMedia) {
      finalizeTrack(tr);
      sbToSession.delete(sb);
      tr = null;
    }
    if (!tr) {
      tr = newSession();
      if (!tr) return;
      sbToSession.set(sb, tr.id);
      if (isInit && !sessionTrackId) sessionTrackId = tr.id;
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
      if (mt > tr.maxMediaTime) tr.maxMediaTime = mt;
      if (mt >= 0) tr.sawMedia = true;
    }

    tr.chunks.push(buf);
    tr.bytes += buf.byteLength;
    onFirstMediaSegment(tr);
    armQuietTimer(tr);
    postUpdate();
  }

  function markReadyByMediaSource(ms) {
    var sbs = msToSbs.get(ms) || [];
    var changed = false;
    sbs.forEach(function (sb) {
      var id = sbToSession.get(sb);
      var tr = id ? tracks[id] : null;
      if (tr && tr.status === 'Capturing' && tr.bytes > 0) {
        finalizeTrack(tr);
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
            var tr = newSession();
            if (tr) {
              tr.source = 'blob';
              tr.chunks = [obj];
              tr.bytes = obj.size;
              tr.status = 'Ready to save';
              postUpdate();
            }
          }
        }
      } catch (e) { /* ignore */ }
      return url;
    };
  } catch (e) { /* ignore */ }

  // --- Auto preload: nudge the player to buffer the whole song ---
  // Suno's player buffers lazily (only the part near the playhead, ~0.5-0.7 MB).
  // Seeking near the end makes it append the remaining segments immediately —
  // exactly what a user does by dragging the slider to the end. We replicate
  // that by setting the media element's currentTime. This uses only the
  // player's own buffering path; no network/API/decrypt/download changes.
  var autoSeek = true;            // on by default; matches "no need to wait"
  var seekAttempts = 0;
  var seekTrack = null;           // track we are trying to preload
  var SEEK_MAX_TRIES = 16;        // retry while duration is still unknown
  var SEEK_RETRY_MS = 250;
  var SEEK_FROM_END = 0.25;       // seconds before end to seek to
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

  function seekToEnd() {
    if (!autoSeek || !captureOn || seekAttempts >= SEEK_MAX_TRIES) return;
    var el = findPlayerMedia();
    if (!el) { scheduleSeekRetry(); return; }
    var d = seekDuration(el);
    if (!d || !isFinite(d) || d <= 0) { scheduleSeekRetry(); return; }
    var target = Math.max(0, d - SEEK_FROM_END);
    // Don't re-seek if already at/near the target (avoids loops).
    if (Math.abs((el.currentTime || 0) - target) < 0.5) return;
    try {
      el.currentTime = target;
      seekAttempts++;
    } catch (e) { scheduleSeekRetry(); }
  }

  function scheduleSeekRetry() {
    if (seekAttempts >= SEEK_MAX_TRIES) return;
    setTimeout(seekToEnd, SEEK_RETRY_MS);
  }

  // Start seeking once the first media segment of a song arrives. Reset the
  // attempt counter for each new session (new song).
  function onFirstMediaSegment(tr) {
    if (!autoSeek || !captureOn) return;
    if (tr._seekDone) return;
    tr._seekDone = true;
    // If we just seeked this same song moments ago, don't do it again even if
    // a fresh track somehow appeared — this is the last defense against the
    // seek -> re-init -> new-track loop.
    var key = tr.initSig || (tr.duration + ':' + tr.timescale) || '';
    var now = Date.now();
    if (key && key === lastSeekSig && (now - lastSeekAt) < SEEK_THROTTLE_MS) return;
    lastSeekSig = key;
    lastSeekAt = now;
    seekAttempts = 0;
    seekTrack = tr;
    setTimeout(seekToEnd, 120);
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
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = (filename || tr.title || 'Suno track').replace(/[\\/:*?"<>|]/g, '-') + '.m4a';
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
      lastSeekSig = '';
      lastSeekAt = 0;
      sessionTrackId = null;
      sessionStart = 0;
      postUpdate();
    } else if (d.type === 'remove-track') {
      var id = d.id;
      if (tracks[id]) {
        clearTimer(tracks[id]);
        delete tracks[id];
        order = order.filter(function (x) { return x !== id; });
        postUpdate();
      }
    } else if (d.type === 'request-tracks') {
      postUpdate();
    } else if (d.type === 'save-track') {
      downloadTrack(d.id, d.filename);
    } else if (d.type === 'save-all') {
      // Queue all ready tracks with a gap between each. Chrome can block or
      // prompt on a burst of synchronous programmatic downloads; spacing them
      // out and using a real user gesture from the popup avoids that.
      var ready = order.filter(function (id) {
        return tracks[id] && tracks[id].status === 'Ready to save';
      });
      ready.forEach(function (id, i) {
        setTimeout(function () { downloadTrack(id, tracks[id] ? tracks[id].title : ''); }, i * 700);
      });
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
