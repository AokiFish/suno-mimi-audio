# Mimi Audio (Chrome MV3, v1.0.0)

Original code, built from Mimi Audio's observed behavior (its help text and
UI screenshots). No Mimi or Suno Downloader source was copied — their source
was never available to read.

## What a plugin (extension) is, in one paragraph

A Chrome extension is a folder of files, not a website and not a space. This
folder is the whole plugin: `manifest.json` declares what it is and what it may
touch; `capture-main.js` runs inside the Suno page; `bridge.js` relays messages;
`background.js` keeps the daily count and the license check; `popup.html` +
`popup.js` are the toolbar panel you click. Chrome loads the folder as-is. That
is why it has to be installed locally on your Windows Chrome — a cloud computer
cannot install into your browser for you.

## How capture works (corrected 2026-11-16)

- `capture-main.js` (MAIN world, `document_start` on suno.com) hooks
  `SourceBuffer.prototype.appendBuffer`. Suno's player fetches encrypted
  chunks, decrypts them in page JS, runs them through MP4Box.js, and appends
  the result to a MediaSource SourceBuffer in order: init segment (ftyp+moov)
  first, then media segments (moof+mdat). There is no EME/Widevine, so the
  bytes reaching `appendBuffer` are always plaintext. Concatenated in append
  order they form a valid fragmented MP4, saved as `.m4a`. A second hook on
  `URL.createObjectURL` catches the player's progressive path, which builds
  one whole decrypted audio Blob and hands it to an `<audio>` element.
- The first build hooked `fetch`/`XMLHttpRequest` alone. That was the bug:
  it grabbed the encrypted stream bytes (no ftyp/moov, entropy 7.99996
  bit/byte, length not a multiple of 16). The save step and the file assembly
  were never the problem.
- Since 2026-11-17 capture is dual-layer. Layer A (primary, zero player
  interaction, no pause): hook `fetch` (clone the response, read the whole
  ENCRYPTED clip in the background) and hook `crypto.subtle.decrypt`
  (observe the player's own AES-CTR call to learn the key), then decrypt the
  full ciphertext ourselves. Layer B (fallback): the existing MSE
  `appendBuffer` capture of plaintext segments. When a new song starts via
  MSE, the extension waits up to 6 s for Layer A to deliver the complete
  file; if it does, the MSE track is dropped and the player is never touched.
  Only if Layer A fails (streaming path, Worker decrypt, partial response)
  does the auto-seek fallback fire (pause + jump to end + restore), which is
  why that path can briefly pause playback.
- A track is Ready to save when the player calls `MediaSource.endOfStream`,
  or when no new segment arrives for 8 seconds after segments started
  arriving. A song is only a few MB; in practice the segments arrive within
  seconds of pressing play. No need to play the whole song.
- Max 4 tracks held at once, max 64 MiB each. Captures belong to the Suno tab;
  reloading the tab clears them. Capture on/off is remembered and applies to
  all Suno tabs. Pause stops new captures; existing ones stay.
- Audio bytes stay in page memory until you click Save audio. No uploads, no
  analytics, no token/cookie/key reads. It does not call Suno's download menu
  or download endpoint.

## Freemium

- Free: 5 saves per day (resets daily, Asia/Shanghai).
- Subscription: unlimited (provider not wired yet — see TODO in
  `background.js`; the Upgrade link is a placeholder, `https://example.com/subscribe`).
- Owner: keys starting with `MIMI-OWNER-` are unlimited (stub only, no server).

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 declaration, permissions `["storage"]`, Suno hosts |
| `capture-main.js` | MAIN-world SourceBuffer.appendBuffer + createObjectURL hook, assembles .m4a in page memory |
| `bridge.js` | ISOLATED-world relay, metadata only |
| `background.js` | Daily count, `FREE_DAILY_LIMIT = 5`, license stub |
| `popup.html` / `popup.js` | Toolbar panel (matches Mimi screenshots + quota footer) |
| `help.html` | Usage + privacy notes |
| `rea-finding-ledger.md` | REA finding ledger for the Suno Downloader analysis |

## Install (on your Windows Chrome)

1. Download the zip `mimi-audio-v1.0.0.zip` and unzip it to a folder.
2. Open `chrome://extensions`, turn on Developer mode (top right).
3. Click "Load unpacked", select the unzipped folder.
4. Open a Suno tab, reload it once, keep Capture on, press play on a song,
   wait for Ready to save in the toolbar popup, click Save audio.

## Not verified

Live capture on real Suno playback has NOT been verified for this build. The
capture layer is now grounded in static analysis of Suno's own player JS (120
chunks downloaded 2026-11-16, player core in `_next/static/immutable/chunks/
1e15t1v9xc__t.js`: "SW HLS" manifest, JS decryption with bytesDecrypted
counter, MP4Box.js, MSE appends, no EME), not in Mimi's source — but no
real playback has been captured with this build yet.
Test on one song first: press play, wait a few seconds, check the popup shows
Ready to save, save it, and confirm the .m4a starts with ftyp and plays
(`ffprobe` should find the moov atom; the old build's output had none).
