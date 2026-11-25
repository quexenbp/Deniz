# Social calibration

`social` renders one search page per site through headless Chromium. It fails
closed (`blocked`) when every requested site returns no parseable hits, which
is what a filtered network usually looks like.

## Run

Needs `pip install 'deniz[browser]' && playwright install chromium`.

```bash
python scripts/social_calibrate.py owasp
python scripts/social_calibrate.py owasp --site trello --json
```

Record one row per site: status, items, milliseconds, error. Do not retry in a
loop; a login wall or CAPTCHA will not improve.

## Current result (2026-11-25, Windows 11)

Run: `python scripts/social_calibrate.py owasp --json`.

| Site | Result | Note |
|---|---|---|
| discord | ok | 5 server hits in 3.3–8.8 s when run alone; a cold launch can fail once |
| instagram | blocked | search redirects to `/accounts/login/` |
| tiktok | blocked | page renders but no anchors; JS challenge |
| facebook | blocked | consent/JS shell, no anchors |
| linkedin | blocked | `/uas/login` redirect |
| quora | blocked | redirects to homepage |
| trello | blocked | `/search` requires login; only header links |

The current egress is no longer proxy-filtered for Discord, so the provider was
tuned: Discord server URLs use `servers/<slug>-<id>` and the classifier now
accepts the numeric suffix; canonical-host checks drop `about.instagram.com`
and similar chrome pages.

All sites still need a logged-in/cookie-capable profile or a country where the
search page is server-rendered. Point `DENIZ_BROWSER_STATE` at a Playwright
`storage_state` JSON exported from a logged-in profile; the session loads it
automatically and the script re-run becomes the calibration.

```bash
DENIZ_BROWSER_STATE=~/.deniz/browser-state.json python scripts/social_calibrate.py owasp
```

The script is the source of truth; re-run it after network or site changes.

## What to tune

- **Wait**: if pages return a shell but no anchors, raise the per-site wait in
  `BrowserSession` rather than adding retries.
- **Selectors**: `SITES` carries the search URL and `classify()` the URL
  patterns. Prefer URL classification over CSS selectors; sites restyle often.
- **Consent walls**: a locale-specific consent page yields zero anchors. Try
  the `?hl=en`/`?lang=en` variant before changing selectors.
- **Budget**: `per_site` (default 10) and `ctx.max_items` bound the run; raise
  only after a site is stable.

## Acceptance

- 6 of 7 sites return at least one classified hit for a common query.
- A blocked site names the reason and does not abort the others.
- Two consecutive runs agree within one result for the same site.
