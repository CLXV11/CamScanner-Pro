![CI](https://github.com/CLXV11/CamScanner-Pro/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux-green)
![Bash](https://img.shields.io/badge/bash-%3E%3D4.3-4EAA25)


# CAM-SEC Scanner v3.0.0

Defensive IP-camera security assessment for **Termux/Android (rootless)** and Linux.
Single-file Bash architecture, evidence-first: every finding carries evidence and an
explicit verification state — no guessed results, no fake detections.

> **AUTHORIZED USE ONLY.** This tool performs non-destructive verification probes
> against devices **you own** or are **explicitly permitted** to assess.
> Unauthorized access to devices you do not own is illegal in most jurisdictions.
> The tool enforces this by design: private-scope targets by default, an
> interactive authorization gate, and a logged `--allow-public` escape hatch.

## Features

- **Evidence-weighted fingerprinting** — vendor/model/firmware with confidence
  scores; `UNKNOWN` when evidence is insufficient (never guessed).
- **Vulnerability assessment with 7 verification states** —
  `NOT_CHECKED | NOT_APPLICABLE | NO_EVIDENCE | INCONCLUSIVE |
   POTENTIALLY_VULNERABLE | LIKELY_VULNERABLE | VERIFIED`.
  `VERIFIED` is only emitted on concrete technical evidence
  (e.g. an XML user list from CVE-2017-7921's unauthenticated endpoint).
- **RTSP/ONVIF checks** — bounded path testing, handshake + authentication-state
  detection, timeout-guarded (no hung `ffprobe`/`ffmpeg`, no orphans).
- **Authentication assessment (opt-in)** — `--auth-test` only; capped attempts,
  lockout delay, stop-on-success; **passwords are never printed, logged or
  exported** (SHA-256 of `user:pass` only).
- **Evidence captures (opt-in)** — `--captures` saves RTSP frames with disk-space
  checks and guaranteed cleanup.
- **Machine-readable reports** — validated JSON + human TXT.
- **Safe config** — strict `KEY=VALUE` parser (no `source`), mode `0600`,
  env-var override (`SHODAN_API_KEY`); secrets are redacted from logs.
- **Leveled logging** — `DEBUG/INFO/WARN/ERROR/SECURITY` with rotation.
- **Scope guard** — refuses public targets unless `--allow-public` (logged).
- **`--self-test`** — 19 installation/runtime checks.
- **Shodan lookup** — real API queries (optional, key never logged).

## Requirements

Hard: `bash >= 4.3`, `curl`.
Recommended: `jq`, `python3`, `openssl` (credential hashing), `ffmpeg` (RTSP/captures), `nmap` (LAN discovery accelerator).
Everything missing degrades to an explicit `NOT_SUPPORTED` — the tool never fabricates capability.

### Termux

```bash
pkg update -y && pkg install -y bash curl jq python3 openssl-tool nmap ffmpeg
```

## Install & run

```bash
chmod +x cam_scanner.sh

# verify installation (expect: SELF TEST: PASS)
./cam_scanner.sh --self-test

# assess a camera you own
./cam_scanner.sh --target 192.168.1.10

# fast profile, both report formats
./cam_scanner.sh --target 192.168.1.10 --quick --report both

# full assessment incl. RTSP evidence captures
./cam_scanner.sh --target 192.168.1.10 --full --captures

# whole LAN (authorization confirmation required)
./cam_scanner.sh --cidr 192.168.1.0/24

# interactive menuون
./cam_scanner.sh
```

Reports: `~/.camsec/reports/` · Logs: `~/.camsec/logs/` · Captures: `~/.camsec/captures/`

## CLI reference

```
--target IP          single IPv4/IPv6 target (private/loopback by default)
--cidr CIDR          IPv4 CIDR range (LAN)
--interface NAME     network interface for discovery (default: auto-detect)
--quick | --normal | --full     scan profile (default: normal)
--timeout SECS       per-probe timeout (default: 4)
--ports LIST         comma-separated port list
--auth-test          enable default-credential check (authorized lab use)
--auth-cred U:P      add credential pair (repeatable)
--captures           capture RTSP screenshots as evidence
--report txt|json|both
--shodan "QUERY"     Shodan host search (key via menu 4 or $SHODAN_API_KEY)
--allow-public       permit non-private targets (logged; requires confirmation)
--i-own-targets      skip authorization prompt (CI use)
--self-test          run the 19-check self test
--deps               dependency status report
--version / --help
```

Exit codes: `0` ok · `1` general · `2` bad args · `3` missing dependency ·
`4` target validation/scope failure · `5` scan incomplete.

## Architecture (single file, 20 modules)

Constants → Safe config → Logging → UI → Dependency manager → Input validation →
Network discovery → Service detection → Fingerprinting → RTSP/ONVIF →
Vulnerability assessment → Auth assessment → Evidence collection → Risk engine →
Report engine (JSON+TXT) → Cleanup/traps → Self-test → Shodan → CLI parser → Main/menu.

## Testing

```bash
# static + self test
bash -n cam_scanner.sh
shellcheck -S warning cam_scanner.sh   # advisory
./cam_scanner.sh --self-test

# integration: full pipeline against a local mock camera (no internet needed)
tests/run_tests.sh
```

CI (GitHub Actions) runs the same suite on every push (`.github/workflows/ci.yml`).

## Accuracy policy

No finding is emitted without `WHY_DETECTED / WHAT_WAS_TESTED /
WHAT_RESPONSE_WAS_RECEIVED`. When evidence is insufficient the result is
`INCONCLUSIVE` or `NO_EVIDENCE` — never inflated to look impressive.

## LicenseghbLicenseghbLcensevvghbccicenseghbc

MIT — see [LICENSE](LICENSE).


