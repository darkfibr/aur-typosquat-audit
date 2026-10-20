#!/usr/bin/env bash
# arch_audit.sh — READ-ONLY host audit for the 2026-10-13 AUR typosquat wave
# ("marchos1as" / yyay family) and the 2026-09-29 "DirtyBlanket" npm worm.
# Case aur_20261019. This script MODIFIES NOTHING, follows no network, and
# prints PASS / FAIL / SKIP per check. Exit codes: 0 = clean, 1 = findings,
# 2 = inconclusive (one or more checks could not be evaluated).
#
# Checks (each explained in one line):
#  a) pacman local DB (.install scriptlets): staging-URL string and known
#     scriptlet/implant hashes in /var/lib/pacman/local/*/install (pacman keeps
#     the installed scriptlet verbatim as "install" in each package dir).
#  b) the 29 known malicious typosquat package names (15 yay cluster +
#     14 brave-beta-bin cluster) via pacman -Q.
#  c) systemd units/timers named systemd-fontd / systemd-fontrenderd /
#     fontrenderd, and any unit with Description=Font Rendering Service.
#  d) the CHAOS implant binary on disk, by name (systemd-fontrenderd,
#     systemd-fontcached) and by SHA-256 4ab643f4… (also the Sep-29 build
#     2c9dbc14…).
#  e) cron entries and systemd timers referencing the staging URL or fontd.
#  f) ssh known_hosts + authorized_keys: counts, timestamps, fingerprints for
#     review — key material is NEVER printed, only counts/fingerprints/mtimes.
#  g) npm config token surface: ~/.npmrc and NPM_CONFIG_USERCONFIG for auth
#     tokens and unexpected registries — token VALUES are never printed.
#  h) local AUR build dirs: read-only scan of common AUR clone locations for
#     injected "bash <(curl …)" lines in .install files and PKGBUILDs.
#  i) the Wayback-wrapped staging URL string anywhere in /etc,
#     /var/lib/pacman/local, ~/.config, ~/.npmrc, ~/.bash_history — counts
#     only, history contents are never dumped.
#
# Scope notes: scans system paths and the invoking user's own files by default.
# Other users' home directories are NOT opened without saying so — they are
# reported as skipped with an explicit notice. No check contacts the network.

set -u

# ---- known campaign artifacts (from case aur_20261019, see ANALYSIS.md) ----
K_SCRIPTLET_SHA='4b46e7374d148e207d2a4b5d2931b16d0fdce83ece2e05823d211c07ac9eb75d' # wave .install (x29, both clusters)
K_IMPLANT_SHA_NOW='4ab643f49ee2a86c36ba665d7a3e5b91997d1da2840d64a0483d2b477c7ca7e0'  # systemd-fontd, Oct build
K_IMPLANT_SHA_OLD='2c9dbc14809f1e1aebda114194368b002acf74c8760b88fc101f625d179793c2'  # systemd-fontd, Sep-29 build
K_LINUX_SHA_NOW='402781973739d057cf3e91d14fce1fb0c12ca95683e2ba43c035ae43314995dd'   # linux.sh, Oct build
K_LINUX_SHA_OLD='65f0a95b24e30305146346cbc2452cfabadab9e1ca35053e1134b67c38919577'   # linux.sh, Sep-29 build
K_NODE_SHA='b4fdaf46a9817f828eb7bc29c9319953a9e06fba2bc2325c972bc25d4ed219d5'        # node.js stage loader
K_STAGING_URL='hellscripter/install-scripts'                                        # shared staging repo path
K_WAYBACK_WRAP='web.archive.org/web/https://'                                        # wrapper technique
# Package-name source of truth: reporting/trustsight_aur-typosquat-2026-10.json
# TrustSight campaign yay-typosquat-2026-10 (15 names, all typosquats of "yay")
K_YAY_PKGS='ay ayy hay tay uay ya yaay yat yau yayy yqy ysy yya yyay yzy'
# TrustSight campaign brave-typosquat-2026-10 (14 names, all typosquats of brave-beta-bin)
K_BRAVE_PKGS='bravve-beta-bin bravw-beta-bin brqve-beta-bin brrave-beta-bin brsve-beta-bin brvae-beta-bin brve-beta-bin brzve-beta-bin btave-beta-bin grave-beta-bin nrave-beta-bin rave-beta-bin rbave-beta-bin vrave-beta-bin'

FAILS=0; SKIPS=0; PASSES=0

pass() { PASSES=$((PASSES+1)); printf 'PASS  %-4s %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS+1)); printf 'FAIL  %-4s %s\n' "$1" "$2"; }
skip() { SKIPS=$((SKIPS+1)); printf 'SKIP  %-4s %s\n' "$1" "$2"; }
info() { printf '        - %s\n' "$1"; }

echo "arch_audit.sh — AUR typosquat wave (2026-10-13) / DirtyBlanket (2026-09-29) — READ-ONLY"
echo "host: $(uname -n 2>/dev/null)  kernel: $(uname -r 2>/dev/null)  date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')  user: $(id -un)  uid: $(id -u)"
echo "--------------------------------------------------------------------------------"

# ============================ a) pacman local DB ============================
# pacman stores the installed .install scriptlet verbatim as the file "install"
# inside /var/lib/pacman/local/<pkg>-<ver>/. We verify that layout first.
check_a() {
  local db=/var/lib/pacman/local
  if [ ! -d "$db" ]; then
    skip a "no $db — not an Arch/pacman host (or pacman DB unavailable); scriptlet check not evaluated"
    return
  fi
  local sample
  sample=$(find "$db" -maxdepth 2 -name install -type f 2>/dev/null | head -1)
  if [ -z "$sample" ]; then
    skip a "$db exists but holds no */install scriptlets — cannot verify scriptlet layout here"
    return
  fi
  info "verified: pacman keeps installed scriptlets at $db/<pkg>-<ver>/install (e.g. ${sample#$db/})"

  local hits=0 hash_hits=0 f h
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if grep -q -e "$K_STAGING_URL" -e "$K_WAYBACK_WRAP" "$f" 2>/dev/null; then
      fail a "malicious scriptlet string in ${f#$db/}"
      hits=$((hits+1))
    fi
    h=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)
    if [ "$h" = "$K_SCRIPTLET_SHA" ]; then
      fail a "scriptlet hash match ($K_SCRIPTLET_SHA) in ${f#$db/}"
      hash_hits=$((hash_hits+1))
    fi
  done < <(find "$db" -maxdepth 2 -name install -type f 2>/dev/null)

  if [ "$hits" -eq 0 ] && [ "$hash_hits" -eq 0 ]; then
    pass a "no staging-URL string and no scriptlet-hash match in $(find "$db" -maxdepth 2 -name install -type f 2>/dev/null | wc -l) installed scriptlets"
  fi
}

# ============================ b) typosquat names ============================
check_b() {
  if ! command -v pacman >/dev/null 2>&1; then
    skip b "pacman not available — package-name check not evaluated"
    return
  fi
  local found=0 p total=0 cluster names label
  for cluster in yay brave; do
    case "$cluster" in
      yay)   names=$K_YAY_PKGS;   label='yay cluster' ;;
      brave) names=$K_BRAVE_PKGS; label='brave-beta-bin cluster' ;;
    esac
    for p in $names; do
      total=$((total+1))
      if pacman -Q "$p" >/dev/null 2>&1; then
        fail b "wave typosquat installed: $p ($label)"
        info "$(pacman -Q "$p" 2>/dev/null)"
        found=$((found+1))
      fi
    done
  done
  if [ "$found" -eq 0 ]; then
    pass b "none of the $total known typosquat names is installed (yay cluster: $K_YAY_PKGS; brave-beta-bin cluster: $K_BRAVE_PKGS)"
    info "note: names come from TrustSight campaigns yay-typosquat-2026-10 and brave-typosquat-2026-10 (reporting/trustsight_aur-typosquat-2026-10.json); only these exact names are checked — a sibling typo not on the list cannot be caught by name, so review any unfamiliar AUR helper package's PKGBUILD/.install manually (check h)"
  fi
}

# ============================ c) systemd fontd units ============================
check_c() {
  local found=0 d f
  local unitdirs="/etc/systemd/system /usr/lib/systemd/system /usr/local/lib/systemd/system /lib/systemd/system"
  for d in $unitdirs; do
    [ -d "$d" ] || continue
    for f in "$d"/*fontd* "$d"/*fontrender*; do
      [ -e "$f" ] || continue
      fail c "suspicious unit present: $f"
      found=$((found+1))
    done
    if grep -rl 'Description=Font Rendering Service' "$d" 2>/dev/null | head -5 | grep -q .; then
      grep -rl 'Description=Font Rendering Service' "$d" 2>/dev/null | head -5 | while IFS= read -r f; do
        fail c "unit with 'Description=Font Rendering Service': $f"
      done
      found=$((found+1))
    fi
  done
  # user-level units (invoking user only)
  local udir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
  if [ -d "$udir" ]; then
    for f in "$udir"/*fontd* "$udir"/*fontrender* "$udir"/*fontcached*; do
      [ -e "$f" ] || continue
      fail c "suspicious user unit present: $f"
      found=$((found+1))
    done
  fi
  # live systemd view (read-only)
  if command -v systemctl >/dev/null 2>&1; then
    local live
    live=$(systemctl list-units --all --no-legend 2>/dev/null | grep -Ei 'fontd|fontrender|fontcached' | head -5)
    if [ -n "$live" ]; then
      fail c "live systemd unit(s) matching fontd/fontrender/fontcached:"
      printf '%s\n' "$live" | while IFS= read -r f; do info "$f"; done
      found=$((found+1))
    fi
    local tu
    tu=$(systemctl list-timers --all --no-legend 2>/dev/null | grep -Ei 'fontd|fontrender|install-script|hellscripter' | head -5)
    if [ -n "$tu" ]; then
      fail c "suspicious systemd timer(s):"
      printf '%s\n' "$tu" | while IFS= read -r f; do info "$f"; done
      found=$((found+1))
    fi
  else
    info "systemctl unavailable — on-disk unit scan only"
  fi
  [ "$found" -eq 0 ] && pass c "no fontd/fontrenderd units or Font Rendering Service descriptions on disk or in systemd"
  return 0
}

# ============================ d) implant binary ============================
check_d() {
  local found=0 f h d
  local scandirs="/usr/lib/systemd /etc/systemd /usr/bin /usr/local/bin /usr/lib /opt /var/lib"
  for d in $scandirs; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      h=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)
      if [ "$h" = "$K_IMPLANT_SHA_NOW" ] || [ "$h" = "$K_IMPLANT_SHA_OLD" ]; then
        fail d "IMPLANT HASH MATCH $h at $f"
      else
        fail d "implant-name match (hash $h, not a known build) at $f — real systemd has no such binary"
      fi
      found=$((found+1))
    done < <(find "$d" -maxdepth 4 \( -name 'systemd-fontrenderd' -o -name 'systemd-fontcached' -o -name 'systemd-fontd' \) -type f 2>/dev/null)
  done
  # invoking user's own config tree
  local udir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd"
  if [ -d "$udir" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      h=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)
      fail d "implant-name match in user config (hash $h) at $f"
      found=$((found+1))
    done < <(find "$udir" -maxdepth 4 \( -name 'systemd-fontrenderd' -o -name 'systemd-fontcached' -o -name 'systemd-fontd' \) -type f 2>/dev/null)
  fi
  [ "$found" -eq 0 ] && pass d "no systemd-fontrenderd / systemd-fontcached / systemd-fontd binaries in system paths or ~/.config/systemd"
  info "weakened: full-disk SHA-256 sweep not performed (impractical read-only); name-based search over standard install paths only"
  return 0
}

# ============================ e) cron + timers ============================
check_e() {
  local found=0 f
  for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
    [ -f "$f" ] || continue
    if grep -q -e "$K_STAGING_URL" -e 'fontd' -e 'fontrender' "$f" 2>/dev/null; then
      fail e "cron entry references staging URL or fontd: $f"
      found=$((found+1))
    fi
  done
  if [ -d /var/spool/cron ]; then
    if [ -r /var/spool/cron ]; then
      while IFS= read -r f; do
        if grep -q -e "$K_STAGING_URL" -e 'fontd' -e 'fontrender' "$f" 2>/dev/null; then
          fail e "cron spool entry references staging URL or fontd: $f"
          found=$((found+1))
        fi
      done < <(find /var/spool/cron -type f 2>/dev/null)
    else
      info "/var/spool/cron not readable as $(id -un) — other users' crontabs NOT inspected (run as root to include)"
    fi
  fi
  if command -v systemctl >/dev/null 2>&1; then
    local t
    t=$(systemctl list-timers --all --no-legend 2>/dev/null | grep -Ei 'hellscripter|install-script|fontrender|fontcached' | head -5)
    if [ -n "$t" ]; then
      fail e "suspicious systemd timer(s):"
      printf '%s\n' "$t" | while IFS= read -r f; do info "$f"; done
      found=$((found+1))
    fi
  fi
  [ "$found" -eq 0 ] && pass e "no cron entries or timers referencing the staging URL or fontd (within the readable scope)"
  return 0
}

# ============================ f) ssh known_hosts / authorized_keys ============================
check_f() {
  local kh
  for kh in "$HOME/.ssh/known_hosts" /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2; do
    [ -f "$kh" ] || continue
    local n mt
    n=$(grep -cve '^\(#\|$\)' "$kh" 2>/dev/null); n=${n:-0}
    mt=$(date -u -r "$kh" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown)
    info "$kh: $n entries, last modified $mt"
  done
  local ak="$HOME/.ssh/authorized_keys"
  if [ -f "$ak" ]; then
    local kn mt kn2
    kn=$(grep -cve '^\(#\|$\)' "$ak" 2>/dev/null); kn=${kn:-0}
    mt=$(date -u -r "$ak" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown)
    info "$ak: $kn keys, last modified $mt — review fingerprints below"
    if command -v ssh-keygen >/dev/null 2>&1; then
      ssh-keygen -lf "$ak" 2>/dev/null | while IFS= read -r kn2; do info "fp: $kn2"; done
    fi
  fi
  # recency surface: files touched in the last 30 days (advisory, for human review)
  local recent=0 kh2
  for kh2 in "$HOME/.ssh/known_hosts" "$HOME/.ssh/authorized_keys" /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2; do
    [ -f "$kh2" ] || continue
    if [ -n "$(find "$kh2" -mtime -30 2>/dev/null)" ]; then
      recent=$((recent+1))
      info "recently modified (last 30 days): $kh2 — verify its entries are yours"
    fi
  done
  # hard indicator only: staging/wrapper string inside ssh files
  local hard=0
  for kh2 in "$HOME/.ssh/known_hosts" "$HOME/.ssh/authorized_keys" /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2; do
    [ -f "$kh2" ] || continue
    if grep -q -e "$K_STAGING_URL" -e "$K_WAYBACK_WRAP" "$kh2" 2>/dev/null; then
      fail f "staging-URL/wrapper string inside $kh2"
      hard=$((hard+1))
    fi
  done
  if [ "$hard" -eq 0 ]; then
    if [ "$recent" -gt 0 ]; then
      pass f "no campaign strings in ssh files; $recent file(s) modified in last 30 days — advisory review required (counts/timestamps/fingerprints above; key material never printed)"
    else
      pass f "no campaign strings in ssh files; no ssh file modified in the last 30 days"
    fi
  fi
  info "weakened: known_hosts has no per-entry timestamps and hashed entries (|1|…) hide hostnames — only file mtimes/counts can be reported; 'unusual' entries are a human judgement from the fingerprints above"
  return 0
}

# ============================ g) npm token surface ============================
check_g() {
  local found=0 rc f
  for rc in "$HOME/.npmrc" "${NPM_CONFIG_USERCONFIG:-/nonexistent}" /root/.npmrc /etc/npmrc "${PREFIX:-/nonexistent}/etc/npmrc"; do
    [ -f "$rc" ] || continue
    local tok reg
    tok=$(grep -c -E '_authToken|_auth|_password' "$rc" 2>/dev/null); tok=${tok:-0}
    reg=$(grep -E '^\s*registry\s*=' "$rc" 2>/dev/null | grep -cv 'registry.npmjs.org'); reg=${reg:-0}
    info "$rc: $tok auth-token line(s), $reg non-npmjs registry line(s) — values not shown"
    if [ "$reg" -gt 0 ]; then
      fail g "unexpected npm registry configured in $rc (count $reg)"
      found=$((found+1))
    fi
    if [ "$tok" -gt 0 ]; then
      fail g "npm auth token present in $rc — treat as compromised and rotate if this host ran any DirtyBlanket-era package (worm publishes via every .npmrc token it finds)"
      found=$((found+1))
    fi
  done
  [ "$found" -eq 0 ] && pass g "no npm auth tokens and no unexpected registries in reachable npm configs"
  info "weakened: presence-only check — whether a token was actually abused requires npm/GitHub audit logs, not local files"
  return 0
}

# ============================ h) local AUR build dirs ============================
check_h() {
  local found=0 d f
  local dirs="$HOME/build $HOME/aur $HOME/AUR $HOME/packages $HOME/.cache/yay $HOME/.cache/paru"
  local scanned=0
  for d in $dirs; do
    [ -d "$d" ] || continue
    scanned=$((scanned+1))
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      if grep -q -e 'bash <(curl' -e "$K_STAGING_URL" "$f" 2>/dev/null; then
        fail h "injected loader line in ${f#$HOME/}"
        found=$((found+1))
      fi
    done < <(find "$d" -maxdepth 6 \( -name '*.install' -o -name PKGBUILD -o -name .SRCINFO \) -type f 2>/dev/null)
  done
  # also: clones named after the wave packages
  for d in $HOME/*; do
    [ -d "$d" ] || continue
    local base="${d##*/}" w
    for w in $K_YAY_PKGS $K_BRAVE_PKGS; do
      if [ "$base" = "$w" ]; then
        fail h "directory named after a wave typosquat exists: $d — inspect its PKGBUILD/.install"
        found=$((found+1))
      fi
    done
  done
  if [ "$found" -eq 0 ]; then
    if [ "$scanned" -eq 0 ]; then
      skip h "no common AUR build locations exist on this host (looked in: $dirs)"
    else
      pass h "no injected 'bash <(curl …)' loader in .install/PKGBUILD/.SRCINFO across $scanned AUR build location(s)"
    fi
  fi
  return 0
}

# ============================ i) staging URL string sweep ============================
check_i() {
  local total=0 d c
  local targets="/etc /var/lib/pacman/local"
  for d in $targets; do
    [ -d "$d" ] || continue
    c=$(grep -r -l -e "$K_STAGING_URL" -e "$K_WAYBACK_WRAP" "$d" 2>/dev/null | wc -l)
    if [ "$c" -gt 0 ]; then
      fail i "$c file(s) under $d contain the staging URL / Wayback wrapper (names not printed here; see check a/c/h)"
      total=$((total+c))
    fi
  done
  for d in "${XDG_CONFIG_HOME:-$HOME/.config}" "$HOME/.npmrc"; do
    [ -e "$d" ] || continue
    c=$(grep -r -l -e "$K_STAGING_URL" -e "$K_WAYBACK_WRAP" "$d" 2>/dev/null | wc -l)
    if [ "$c" -gt 0 ]; then
      fail i "$c file(s) under $d contain the staging URL / Wayback wrapper"
      total=$((total+c))
    fi
  done
  if [ -f "$HOME/.bash_history" ]; then
    c=$(grep -c -e "$K_STAGING_URL" -e "$K_WAYBACK_WRAP" "$HOME/.bash_history" 2>/dev/null); c=${c:-0}
    if [ "$c" -gt 0 ]; then
      fail i "$HOME/.bash_history: $c matching line(s) (counts only — history contents not dumped)"
      total=$((total+c))
    fi
  fi
  [ "$total" -eq 0 ] && pass i "no staging-URL / Wayback-wrapper strings in /etc, pacman local DB, ~/.config, ~/.npmrc, ~/.bash_history"
  local notice=0 hdir
  for hdir in /home/*; do
    [ -d "$hdir" ] || continue
    [ "$hdir" = "$HOME" ] && continue
    notice=$((notice+1))
  done
  [ "$notice" -gt 0 ] && info "NOTICE: $notice other user home(s) under /home were NOT scanned by default — run as root with explicit scope to include them"
  return 0
}

check_a; echo
check_b; echo
check_c; echo
check_d; echo
check_e; echo
check_f; echo
check_g; echo
check_h; echo
check_i

echo
echo "================================================================================"
echo "WHAT TO PRESERVE BEFORE CLEANUP (collect first, remediate second)"
echo "  1. unit files:   /etc/systemd/system/systemd-fontrenderd.service (and the"
echo "     multi-user.target.wants link), ~/.config/systemd/user/systemd-font{renderd,cached}.service"
echo "  2. implant binary: /usr/lib/systemd/systemd-fontrenderd, ~/.config/systemd/systemd-fontcached"
echo "     (note: the worm sets chattr +i — record lsattr output, then chattr -i before removal)"
echo "  3. the .install copy: /var/lib/pacman/local/<pkg>-<ver>/install plus the same"
echo "     package's 'files' and 'desc' entries, and pacman -Q output"
echo "  4. timestamps: stat every item above (mtime/ctime), and save"
echo "     /var/log/pacman.log lines for the install/upgrade in question"
echo "  5. journal excerpts: journalctl -u systemd-fontrenderd -u systemd-fontcached"
echo "     (system and --user), and systemctl status output for both units"
echo "  6. ssh surface: known_hosts copies and the LIST of key fingerprints (never ship"
echo "     private keys off-host), ~/.npmrc presence (redact token values)"
echo "  7. worm traces: /tmp/log if present, and any AUR clone with an unexpected commit"
echo "     (git log --format='%H %an <%ae> %cn <%ce> %ad %s')"
echo "================================================================================"
echo "SUMMARY: passes=$PASSES fails=$FAILS skips=$SKIPS"
if [ "$FAILS" -gt 0 ]; then
  echo "VERDICT: FINDINGS PRESENT — treat the host as compromised per the runbook in ARCH_DETECTION.md"
  exit 1
elif [ "$SKIPS" -gt 0 ]; then
  echo "VERDICT: INCONCLUSIVE — one or more checks were skipped (missing data/paths)"
  exit 2
else
  echo "VERDICT: CLEAN within the checked scope"
  exit 0
fi
