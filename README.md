# Mimi Audio (Chrome MV3, v1.0.0)

## Disclaimer

This project is provided **for research and learning purposes only**. Do not
use it for any commercial purpose or in any way that violates the terms of
service of third-party platforms, infringes copyright, or breaks applicable
laws. All captured audio belongs to its respective rights holders. Use at
your own risk; the authors assume no liability for any misuse.

> 本项目仅供技术研究和学习使用，禁止用于商业用途或任何违反第三方平台服务条款、
> 侵犯版权或法律法规的用途。所捕获音频的版权归各自权利人所有。使用风险自负。

Original code, built from Mimi Audio's observed behavior (its help text and
UI screenshots). No Mimi or Suno Downloader source was copied — their source
was never available to read.

## What a plugin (extension) is, in one paragraph

A Chrome extension is a folder of files, not a website and not a space. This
folder is the whole plugin: `manifest.json` declares what it is and what it may
touch; `capture-main.js` runs inside the Suno page; `bridge.js` relays messages;
`background.js` keeps the capture on/off state; `popup.html` +
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
  why that path can briefly pause playback. There is no Fast capture switch
  in the popup — the layering decision is made internally per song.
- One song, one entry (dedupe). A moonlit (Layer A) copy and an MSE (Layer B)
  stream of the SAME song are merged by identity, not by guessing. Identity
  signals, strongest first: (1) decrypt-side link — when the player decrypts
  a clip we captured, the then-active MSE track is bound to that clip id; if
  no track existed yet, the next MSE track created within 8 s claims the
  pending clip; (2) mvhd duration + timescale exact match; (3) proximity —
  the current capturing MSE track that started within 8 s of the cipher's
  fetch (guarded by the fetch timestamp so a late OLD song's clip can never
  swallow the NEW song's track); (4) exact title match as a final net. A
  merged/dropped MSE track's init signature goes into a tombstone so a
  seek-triggered re-init cannot respawn a duplicate.
- A track is Ready to save when the player calls `MediaSource.endOfStream`,
  or when no new segment arrives for 8 seconds after segments started
  arriving. A song is only a few MB; in practice the segments arrive within
  seconds of pressing play. No need to play the whole song.
- Max 8 tracks held at once, max 64 MiB each. Captures belong to the Suno tab;
  reloading the tab clears them. Capture on/off is remembered and applies to
  all Suno tabs. Pause stops new captures; existing ones stay.
- Audio bytes stay in page memory until you click Save audio. No uploads, no
  analytics, no token/cookie/key reads. It does not call Suno's download menu
  or download endpoint.

## Open source free · Invite author for a cup of coffee

This open source project is free, and if the project helps you, you can buy me a cup of coffee. Your support is the motivation for continuous maintenance.

<p align="center">
  <img src="assets/donate-usdt-bsc.jpg" alt="USDT · BSC (BEP20)" width="220">
  &nbsp;&nbsp;
  <img src="assets/donate-usdc-bsc.jpg" alt="USDC · BSC (BEP20)" width="220">
</p>

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 declaration, permissions `["storage", "scripting"]`, Suno hosts |
| `capture-main.js` | MAIN world, dual-layer capture: `fetch` + `crypto.subtle.decrypt` passive layer (Layer A), `SourceBuffer.appendBuffer` + `URL.createObjectURL` hooks (Layer B fallback), auto-seek preload, track identity/dedupe, in-page .m4a/.webm assembly |
| `bridge.js` | ISOLATED-world relay: popup commands into the page, tracks metadata out |
| `background.js` | Capture on/off state, content-script re-injection into open Suno tabs |
| `popup.html` / `popup.js` | Toolbar panel: capture toggle, track list, save / download-all |
| `help.html` | Usage + privacy notes |
| `rea-finding-ledger.md` | REA finding ledger for the Suno Downloader analysis |

## Install (on your Windows Chrome)

1. Download the zip `mimi-audio-v1.0.0.zip` and unzip it to a folder.
2. Open `chrome://extensions`, turn on Developer mode (top right).
3. Click "Load unpacked", select the unzipped folder.
4. Open a Suno tab, reload it once, keep Capture on, press play on a song,
   wait for Ready to save in the toolbar popup, click Save audio.

## Verified status (2026-11-17)

Live-tested on real Suno playback through multiple rounds of fixes:

- Layer A (passive fetch + key observation) delivers a complete file within
  seconds of pressing play, with no playback pause, on Suno's progressive
  whole-file path — this is the common case.
- The MSE fallback covers the streaming path: when Layer A cannot deliver
  (partial/206 response, Worker decrypt, path change), the gate falls back to
  the auto-seek preload after ~6 s, which briefly pauses playback (~1 s).
- Duplicate-track dedupe (moonlit copy vs MSE stream of the same song) has
  been hardened against the switch-song race: pending clip claim, fetch-time
  proximity match, and exact-title fallback keep one entry per song.
- Known limitation: Layer A depends on Suno still fetching whole encrypted
  clips and decrypting them in page JS. If Suno moves decryption into a
  Worker or switches fully to range/segment streaming, capture silently
  degrades to the MSE layer (slight pause, still works).

If a song ever shows two entries again, run `__mimiCapture.debugTracks()` in
the page console and report the output.
