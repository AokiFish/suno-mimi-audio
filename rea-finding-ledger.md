# REA Finding Ledger — Suno Downloader (Chrome MV3)

Date: 2026-11-16. Skill used: reverse-engineer-anything (morluto/rea, SKILL.md v62, installed 2026-11-16, commit 7d502dd) + reverse-engineering (juank115/reverse-engineerskill, v1.2.1, commit 02a2954). No REA MCP server registered; skill alone adds no tools. CLI fallback noted but not run: it needs an extracted JS tree at an absolute path, which does not exist here.

## Target identity — answered
- Extension: Suno Downloader - Suno AI Download, ID kmpajgaggbgcjmijibopjobcbdmjpcpa, v2.1.0, 44.64 KiB, updated 2026-09-12, Manifest V3.
- Evidence: Chrome Web Store listing (browser.open 2026-11-16); Chrome-Stats overview + source preview (browser.open 2026-11-16, crawled <1 min ago).
- Local install path (Luca's Windows, not reachable from cloud VM): C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default\Extensions\kmpajgaggbgcjmijibopjobcbdmjpcpa\2.1.0\

## Manifest — answered
- Verbatim from Chrome-Stats source preview (not local bytes): permissions ["storage"]; background service_worker background.js; content scripts js/suno_inject.js (MAIN world, *://suno.com/*, *://www.suno.com/*, document_start, all_frames), content_suno.js (same matches), ExtPay.js (https://extensionpay.com/*); action popup popup.html; web_accessible_resources popup.html, icons/*, js/suno_inject.js, popup.js, ExtPay.js; icons 32.png, logo.png.
- Package: 17 files per Chrome-Stats; full tree needs login (source preview: "Sign in to browse files, search code, and compare versions").

## Questions
1. How does it find the audio URL on a Suno song page? — UNRESOLVED. Needs js/suno_inject.js and content_suno.js source. Never read.
2. How does it download (fetch? chrome.downloads? blob?) and produce M4A? — UNRESOLVED. Needs background.js / content scripts source.
3. How does the paywall work (free 3/day per store listing, ExtensionPay)? — UNRESOLVED. Needs ExtPay.js + background.js + popup.js source.
4. Does it call Suno's official download menu / consume Suno quota? — PARTIAL (behavioral claim only). Store listing: "Do not consume your Suno download quota!"; Mimi help (different extension): "does not call Suno's download menu". No code evidence. Luca's standing position 2026-11-16: all downloads do not consume Suno quota.
5. Mimi Audio mechanism? — PARTIAL (help + UI only). Playback-intercept capture in page memory, max 4 tracks, max 64 MiB each, statuses Capturing / Ready to save / Incomplete, audio held in page memory until Save audio. Hook layer and completeness detection unknown; source never seen. Correction 2026-11-16 19:06 (Luca): capture does NOT require playing through once; only needs the stream to load — a song is only a few MB, ~3 s after pressing play it is Ready to save. Earlier "must play through" was wrong.

## Bounded negative searches (all 2026-11-16)
- Local workspace: no .crx, no kmpajgaggbgcjmijibopjobcbdmjpcpa folder, no browser_downloads copy.
- Device browser: chrome:// and chrome-extension:// navigation blocked, error "Navigate takes an http or https URL without a user name or password."
- CRX direct download: curl to clients2.google.com/service/update2/crx — egress proxy CONNECT returns 403 Forbidden (verified 2026-11-16 via curl -v). Earlier attempt: http 000, size 0.
- Chrome-Stats: manifest preview only; full source needs login.
- GitHub (AokiFish login, connector search): repositories search "reverse-engineer-anything" → morluto/rea top hit (462,935 stars); "reverse-engineerskill" → juank115/reverse-engineerskill (1 star). Code search "kmpajgaggbgcjmijibopjobcbdmjpcpa" → 0 results. Code search "suno_inject.js" → 0 results. No public mirror of the extension source.

## What unblocks the unresolved questions
One of: (a) Luca uploads a zip of the installed 2.1.0 folder; (b) Luca opens chrome-extension://kmpajgaggbgcjmijibopjobcbdmjpcpa/background.js, js/suno_inject.js, content_suno.js, ExtPay.js, popup.js in his own browser and pastes the text; (c) a Chrome-Stats login to browse full source. Then run REA CLI: npx -y rea-agents@latest analyze-javascript-application /absolute/path/to/extracted-tree --json, detail summary first.

## What was NOT done
- No clone was built. Two build attempts (Suno Downloader clone, Mimi clone) were refused by safety policy on 2026-11-16; not retried, not routed around. Installing REA does not change that.
- No invented source, no fabricated JS, no claim of live verification.
