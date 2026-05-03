#!/usr/bin/env bash
# ---------------------------------------------------------------
# logsentry — POSIX shell collector
# Collects normalized log evidence from a Linux host into a single
# JSON bundle that can be analyzed offline by the Python engine.
#
# Usage:
#   sudo ./collect.sh [--since "24 hours ago"] [--out evidence.json]
# ---------------------------------------------------------------
set -euo pipefail

SINCE="24 hours ago"
OUT="evidence.json"

while [ $# -gt 0 ]; do
    case "$1" in
        --since) SINCE="$2"; shift 2 ;;
        --out)   OUT="$2";   shift 2 ;;
        -h|--help)
            sed -n '2,11p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# --------------------------- helpers ---------------------------
have() { command -v "$1" >/dev/null 2>&1; }

json_escape() {
    # minimal JSON string escaper for shell-collected text
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
        -e ':a;N;$!ba;s/\n/\\n/g' -e 's/\r/\\r/g' -e 's/\t/\\t/g'
}

emit_array() {
    # emit a JSON array of strings from stdin (one per line)
    local first=1
    printf '['
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if [ $first -eq 1 ]; then first=0; else printf ','; fi
        printf '"%s"' "$(printf '%s' "$line" | json_escape)"
    done
    printf ']'
}

# --------------------------- meta ------------------------------
HOSTNAME_VAL="$(hostname 2>/dev/null || echo unknown)"
KERNEL_VAL="$(uname -r 2>/dev/null || echo unknown)"
OS_VAL="$( ( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$NAME}" ) || echo unknown)"
NOW_VAL="$(date '+%d/%m/%Y %H:%M:%S')"

# --------------------------- sources ---------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

collect_journal() {
    local unit="$1" file="$2"
    if have journalctl; then
        journalctl --since "$SINCE" -u "$unit" --no-pager -o short-iso 2>/dev/null \
            > "$TMP/$file" || true
    fi
}

collect_journal_id() {
    local id="$1" file="$2"
    if have journalctl; then
        journalctl --since "$SINCE" SYSLOG_IDENTIFIER="$id" --no-pager -o short-iso 2>/dev/null \
            > "$TMP/$file" || true
    fi
}

# auth & sudo
collect_journal_id sshd      auth_sshd.log
collect_journal_id sudo      sudo.log
collect_journal_id systemd-logind logind.log

# kernel & firewall
if have journalctl; then
    journalctl --since "$SINCE" -k --no-pager -o short-iso 2>/dev/null > "$TMP/kernel.log" || true
fi
have dmesg && dmesg -T 2>/dev/null > "$TMP/dmesg.log" || true

collect_journal ufw.service       ufw.log
collect_journal nftables.service  nft.log
collect_journal firewalld.service firewalld.log

# fallback for Debian/Ubuntu without journalctl coverage
[ -r /var/log/auth.log ] && tail -n 5000 /var/log/auth.log > "$TMP/auth_file.log" || true

# logins
have last  && last  -F -n 200 2>/dev/null > "$TMP/last.log"  || true
have lastb && lastb -F -n 200 2>/dev/null > "$TMP/lastb.log" || true

# users / groups snapshot
getent passwd > "$TMP/passwd.snap" 2>/dev/null || true
getent group  > "$TMP/group.snap"  2>/dev/null || true

# packages timeline
if   have pacman; then pacman -Q 2>/dev/null > "$TMP/pkg.list" || true
                       grep -E "installed|removed|upgraded" /var/log/pacman.log 2>/dev/null \
                           | tail -n 500 > "$TMP/pkg.log" || true
elif have dnf;    then dnf history 2>/dev/null | head -n 200 > "$TMP/pkg.log" || true
                       rpm -qa 2>/dev/null > "$TMP/pkg.list" || true
elif have apt;    then grep -hE "install |remove |upgrade " /var/log/dpkg.log* 2>/dev/null \
                           | tail -n 500 > "$TMP/pkg.log" || true
                       apt list --installed 2>/dev/null > "$TMP/pkg.list" || true
fi

# usb plug events
grep -iE "usb [0-9]+-[0-9.]+: new|usb-storage|disconnect" "$TMP/dmesg.log" 2>/dev/null \
    > "$TMP/usb.log" || true

# --------------------------- emit ------------------------------
{
    printf '{\n'
    printf '  "schema": "logsentry/1",\n'
    printf '  "meta": {\n'
    printf '    "hostname": "%s",\n' "$(printf '%s' "$HOSTNAME_VAL" | json_escape)"
    printf '    "os": "%s",\n'       "$(printf '%s' "$OS_VAL"       | json_escape)"
    printf '    "kernel": "%s",\n'   "$(printf '%s' "$KERNEL_VAL"   | json_escape)"
    printf '    "since": "%s",\n'    "$(printf '%s' "$SINCE"        | json_escape)"
    printf '    "collected_at": "%s"\n' "$(printf '%s' "$NOW_VAL"   | json_escape)"
    printf '  },\n'
    printf '  "sources": {\n'

    sources=(
        "auth_sshd:auth_sshd.log"
        "auth_file:auth_file.log"
        "sudo:sudo.log"
        "logind:logind.log"
        "kernel:kernel.log"
        "dmesg:dmesg.log"
        "ufw:ufw.log"
        "nft:nft.log"
        "firewalld:firewalld.log"
        "last:last.log"
        "lastb:lastb.log"
        "passwd:passwd.snap"
        "group:group.snap"
        "pkg_log:pkg.log"
        "pkg_list:pkg.list"
        "usb:usb.log"
    )

    n=${#sources[@]}
    i=0
    for entry in "${sources[@]}"; do
        i=$((i+1))
        key="${entry%%:*}"
        file="${entry##*:}"
        printf '    "%s": ' "$key"
        if [ -s "$TMP/$file" ]; then
            emit_array < "$TMP/$file"
        else
            printf '[]'
        fi
        if [ $i -lt $n ]; then printf ','; fi
        printf '\n'
    done

    printf '  }\n'
    printf '}\n'
} > "$OUT"

echo "✅ evidence written to $OUT"
echo "   sources: $(wc -l < "$OUT") lines, $(du -h "$OUT" | awk '{print $1}')"
