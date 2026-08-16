# lynis-ui

_Web-based front-end for interacting with Lynis audit reports and custom profile configuration._

A small local web app that shows your latest Lynis scan findings in a browser
table. Check the boxes next to findings you've decided to accept as risk,
click **Exempt Selected**, and it appends the matching `skip-test=` lines to
`/etc/lynis/custom.prf` so those tests are excluded from future scans.

## Usage

### Option A: run from source (development)

```bash
cd ~/Documents/GitHub/lynis-ui
./run.sh
```

This opens `http://localhost:5000` in your default browser. Leave the
terminal running; press `Ctrl+C` to stop the server when you're done.

### Option B: standalone AppImage (no Python/Flask install required)

Build it once:

```bash
cd ~/Documents/GitHub/lynis-ui
./build_appimage.sh
```

This produces `dist/Lynis-Findings-Dashboard-x86_64.AppImage` — a single
portable file. Run it directly (double-click in a file manager, or from a
terminal):

```bash
./dist/Lynis-Findings-Dashboard-x86_64.AppImage
```

A graphical PolicyKit (`pkexec`) password prompt will appear to authorize
the backend; your browser opens automatically once it's ready. See
[Packaging as an AppImage](#packaging-as-an-appimage) below for details.

## Why does it need sudo?

The app needs root privileges for two things:
- Reading `/var/log/lynis-report.dat` (root-owned, written by the scheduled
  `lynis.timer` job)
- Writing `/etc/lynis/custom.prf` (root-owned Lynis config directory)

`run.sh` runs the Flask server with `sudo`. The server binds only to
`localhost` and is never exposed to the network.

## Configuration (environment variables)

By default the app looks for the Lynis report at `/var/log/lynis-report.dat`
(falling back to `~/lynis-report.dat` for local development without sudo),
and reads/writes exemptions at `/etc/lynis/custom.prf`. Both can be
overridden with environment variables if your Lynis reports or custom
profile live somewhere else (e.g. a non-standard install, a container, or a
report copied in from another host):

| Variable | Overrides | Default |
|---|---|---|
| `LYNIS_REPORT_PATH` | The exact `report.dat` file to read | `/var/log/lynis-report.dat`, then `~/lynis-report.dat` |
| `LYNIS_CUSTOM_PROFILE_PATH` | The exact `custom.prf` file to read/write exemptions in | `/etc/lynis/custom.prf` |

**Behavior notes:**
- `LYNIS_REPORT_PATH` is exclusive when set — the app uses only that path and
  does *not* fall back to the two defaults. If the file doesn't exist or
  isn't readable, you'll get a clear error naming the variable and the path
  you set, rather than a generic "no report found" message.
- `LYNIS_CUSTOM_PROFILE_PATH` simply replaces the default path everywhere
  (reading existing exemptions, appending new ones, and un-exempting).
- Both are read once at process start (they're resolved when
  `lynis_report_parser.py` is imported / at request time via
  `os.environ`), so set them *before* launching the app.

**Running from source** (`run.sh` forwards them through `sudo` automatically):
```bash
LYNIS_REPORT_PATH=/path/to/lynis-report.dat \
LYNIS_CUSTOM_PROFILE_PATH=/path/to/custom.prf \
./run.sh
```

**Running the AppImage:** `AppRun` elevates the backend via `pkexec`, and
`pkexec` strips almost all environment variables for security — so these
overrides are *not* currently forwarded through the AppImage's normal
`pkexec` path. If you need an override with the AppImage, use the documented
`sudo` fallback instead, which does inherit your shell's environment:
```bash
sudo LYNIS_REPORT_PATH=/path/to/lynis-report.dat ./dist/Lynis-Findings-Dashboard-x86_64.AppImage
```

## How it works

1. On page load, the backend parses `/var/log/lynis-report.dat` for
   `suggestion[]` / `warning[]` entries and reads scan metadata (hostname,
   Lynis version, hardening index, scan date).
2. It also parses `/etc/lynis/custom.prf` to see which tests are already
   exempted (`skip-test=TEST-ID` lines), so those rows show as *Exempted*
   with a toggle switch instead of a checkbox.
3. Each finding is enriched with curated metadata (category, severity,
   impact, remediation, explanation) from `lynis_knowledge.json`. Any test ID
   not yet in that file still shows up, just with generic placeholder text —
   feel free to add entries for it.
4. Checking rows and clicking **Exempt Selected** posts the chosen test IDs
   (plus an optional free-text reason) to the backend, which appends a dated
   comment and `skip-test=` line per test ID to `/etc/lynis/custom.prf`.
5. Flipping an exempted row's toggle off calls `/api/unexempt`, which
   comments out that `skip-test=` line (with a removal note, preserving
   history) so the test runs again next scan.
6. Re-running a Lynis scan (`sudo lynis audit system --cronjob`, or waiting
   for the weekly `lynis.timer` run) will skip all currently-exempted tests.

## Files

| File | Purpose |
|---|---|
| `app.py` | Flask routes: serves the page, `/api/findings`, `/api/exempt`, `/api/unexempt`, `/api/system-info` |
| `lynis_report_parser.py` | Parsing logic for report.dat and custom.prf (no Flask dependency) |
| `lynis_knowledge.json` | Curated category/severity/impact/remediation/explanation per test ID |
| `templates/index.html` | Bootstrap 5 (via CDN) page shell |
| `static/app.js` | Fetches findings, renders the table, handles selection + exempt/unexempt requests |
| `static/styles.css` | Layout/theme tweaks on top of Bootstrap |
| `run.sh` | Installs Flask if missing, launches the app with sudo, opens the browser |
| `build_appimage.sh` | Builds a PyInstaller onefile backend and packs it into an AppImage |
| `packaging/AppRun` | AppImage entry point: self-elevates the backend via `pkexec`, opens the browser unprivileged |
| `packaging/lynis-webui.desktop` | Desktop entry metadata bundled into the AppImage |
| `packaging/lynis-webui.png` | AppImage icon |

## Packaging as an AppImage

`build_appimage.sh`:
1. Creates an isolated build venv (only used at build time) and installs
   `flask` + `pyinstaller` into it.
2. Runs PyInstaller `--onefile` on `app.py`, bundling `templates/`,
   `static/`, and `lynis_knowledge.json` into a single executable
   (`lynis-webui-backend`) that needs no separate Python/Flask install.
3. Assembles an `AppDir` with that executable plus `packaging/AppRun`, the
   `.desktop` file, and the icon.
4. Downloads/caches `appimagetool` and packs everything into
   `dist/Lynis-Findings-Dashboard-<arch>.AppImage`.

### How privilege elevation works in the AppImage

The AppImage is meant to be double-clicked rather than run from a `sudo`
terminal, so `AppRun` self-elevates just the backend process via `pkexec`
(a graphical PolicyKit password prompt), while opening the browser as your
normal user — mirroring how `run.sh` only elevates `python3 app.py`, never
the browser.

One important detail: an AppImage's contents are only reachable through a
FUSE mount owned by the user who launched it, so `pkexec` (running as root)
can't read files inside that mount directly. `AppRun` works around this by
copying the backend binary to a real temp file (`/tmp/lynis-webui-backend.*`,
cleaned up automatically on exit) before calling `pkexec` on that copy.

If `pkexec` isn't available or isn't authorized on your system, run the
AppImage manually with `sudo` instead:

```bash
sudo ./dist/Lynis-Findings-Dashboard-x86_64.AppImage
```

## Current limitations

- **Whole-test exemptions only**: both the exempt and un-exempt actions work
  on entire tests (`skip-test=TEST-ID`). Lynis also supports skipping a
  single sub-check, e.g. `skip-test=KRNL-6000:net.ipv4.conf.all.rp_filter` —
  that still has to be added/removed by hand for now.
- **On-demand only**: neither `run.sh` nor the AppImage installs a
  persistent background service. Launch it whenever you want to review
  findings.
- **Single-user tool**: no authentication, meant to be run locally by you
  only.
- **AppImage is x86_64 only** as built by `build_appimage.sh` (matches the
  architecture it's built on); rebuild on other architectures as needed.

## Customizing the theme

The frontend is plain HTML/CSS/JS with Bootstrap loaded from a CDN — no
build step. Edit `static/styles.css` for colors/spacing, or swap the
Bootstrap CDN link in `templates/index.html` for a different Bootswatch
theme if you want a different look.

## Development notes

`build/` and `dist/` are git-ignored (see `.gitignore`) since they're
regenerable build output — `build/` contains a disposable build-time venv
plus PyInstaller intermediate artifacts with absolute paths baked in, and
`dist/` holds the final `.AppImage`. Run `./build_appimage.sh` any time to
regenerate both from source.
