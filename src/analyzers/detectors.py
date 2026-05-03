"""
logsentry.analyzers.detectors — 20+ log detectors.

Each detector receives the evidence bundle (parsed JSON from collect.sh)
and returns a DetectorResult. Source arrays are lists of raw log lines.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Iterable, List

from .engine import DetectorResult, Severity, detector


# --------------------------- helpers --------------------------- #

def _src(ev: dict, key: str) -> List[str]:
    return list(ev.get("sources", {}).get(key, []) or [])


def _all_auth(ev: dict) -> List[str]:
    return _src(ev, "auth_sshd") + _src(ev, "auth_file")


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_RE = re.compile(r"user[= ](\S+)", re.I)


def _make(ok: bool, **kw) -> DetectorResult:
    kw.setdefault("status", "PASS" if ok else "FAIL")
    if ok:
        kw["severity"] = Severity.CLEAN
    return DetectorResult(**kw)


# =============================================================== #
#                            AUTH
# =============================================================== #

@detector
def auth_failed_logins(ev: dict) -> DetectorResult:
    lines = [l for l in _all_auth(ev) if "Failed password" in l or "authentication failure" in l]
    n = len(lines)
    iocs = list({m for l in lines for m in IP_RE.findall(l)})[:20]
    if n == 0:
        return _make(True, check_id="AUTH-001", category="Auth",
                     title="Failed SSH logins", severity=Severity.CLEAN,
                     detail="No failed SSH login attempts in window.")
    sev = Severity.HIGH if n > 50 else Severity.MEDIUM if n > 10 else Severity.LOW
    return _make(False, check_id="AUTH-001", category="Auth",
                 title="Failed SSH logins", severity=sev, status="WARN",
                 detail=f"{n} failed SSH login attempts from {len(iocs)} unique IP(s).",
                 recommendation="Review sources, enable fail2ban, restrict SSH to keys.",
                 reference="MITRE T1110", iocs=iocs)


@detector
def auth_brute_force_burst(ev: dict) -> DetectorResult:
    counter = Counter()
    for l in _all_auth(ev):
        if "Failed password" in l:
            for ip in IP_RE.findall(l):
                counter[ip] += 1
    bursts = [(ip, c) for ip, c in counter.items() if c >= 50]
    if not bursts:
        return _make(True, check_id="AUTH-002", category="Auth",
                     title="SSH Brute-force burst", severity=Severity.CLEAN,
                     detail="No source crossed 50 failed logins.")
    bursts.sort(key=lambda x: -x[1])
    top = bursts[0]
    return _make(False, check_id="AUTH-002", category="Auth",
                 title="SSH Brute-force burst", severity=Severity.CRITICAL,
                 status="FAIL",
                 detail=f"{top[1]} failed logins from {top[0]} (and {len(bursts)-1} other source(s)).",
                 recommendation=f"Block source via 'ufw deny from {top[0]}' and rotate SSH keys.",
                 reference="MITRE T1110.001",
                 iocs=[ip for ip, _ in bursts[:20]])


@detector
def auth_root_success(ev: dict) -> DetectorResult:
    hits = [l for l in _all_auth(ev)
            if "Accepted" in l and re.search(r"\bfor root\b", l)]
    if not hits:
        return _make(True, check_id="AUTH-003", category="Auth",
                     title="Successful root SSH login", severity=Severity.CLEAN,
                     detail="No successful root SSH login in window.")
    iocs = list({m for l in hits for m in IP_RE.findall(l)})[:10]
    return _make(False, check_id="AUTH-003", category="Auth",
                 title="Successful root SSH login", severity=Severity.HIGH, status="FAIL",
                 detail=f"{len(hits)} successful root login(s) from {iocs or 'unknown'}.",
                 recommendation="Disable root SSH (PermitRootLogin no) and audit access.",
                 reference="MITRE T1078.003", iocs=iocs)


@detector
def auth_new_keys(ev: dict) -> DetectorResult:
    hits = [l for l in _all_auth(ev) if "Accepted publickey" in l]
    fingerprints = list({l.split("SHA256:")[-1].split()[0]
                          for l in hits if "SHA256:" in l})
    if not fingerprints:
        return _make(True, check_id="AUTH-004", category="Auth",
                     title="SSH keys observed", severity=Severity.CLEAN,
                     detail="No publickey logins observed.")
    return _make(False, check_id="AUTH-004", category="Auth",
                 title="SSH keys observed", severity=Severity.INFO, status="INFO",
                 detail=f"{len(fingerprints)} unique SSH key fingerprint(s) accepted.",
                 recommendation="Cross-check fingerprints with your key inventory.",
                 reference="MITRE T1098.004", iocs=fingerprints[:20])


@detector
def auth_login_new_ip(ev: dict) -> DetectorResult:
    last = _src(ev, "last")
    ips = []
    for l in last:
        ips += IP_RE.findall(l)
    uniq = list(dict.fromkeys(ips))
    if len(uniq) <= 1:
        return _make(True, check_id="AUTH-005", category="Auth",
                     title="Logins from new IPs", severity=Severity.CLEAN,
                     detail=f"{len(uniq)} unique source IP in login history.")
    sev = Severity.MEDIUM if len(uniq) > 5 else Severity.LOW
    return _make(False, check_id="AUTH-005", category="Auth",
                 title="Logins from new IPs", severity=sev, status="WARN",
                 detail=f"Logins observed from {len(uniq)} distinct IP(s).",
                 recommendation="Confirm all sources are expected; alert on novel IPs.",
                 reference="MITRE T1078", iocs=uniq[:20])


# =============================================================== #
#                            SUDO
# =============================================================== #

@detector
def sudo_failed(ev: dict) -> DetectorResult:
    lines = [l for l in _src(ev, "sudo") if "authentication failure" in l or "incorrect password" in l]
    if not lines:
        return _make(True, check_id="SUDO-001", category="Sudo",
                     title="Failed sudo attempts", severity=Severity.CLEAN,
                     detail="No failed sudo attempts.")
    users = list({m.group(1) for l in lines for m in [USER_RE.search(l)] if m})
    sev = Severity.HIGH if len(lines) > 10 else Severity.MEDIUM
    return _make(False, check_id="SUDO-001", category="Sudo",
                 title="Failed sudo attempts", severity=sev, status="FAIL",
                 detail=f"{len(lines)} failed sudo attempt(s) by users: {users or 'unknown'}.",
                 recommendation="Review user activity; consider revoking sudo for repeat offenders.",
                 reference="MITRE T1548.003", iocs=users[:20])


@detector
def sudo_nopasswd(ev: dict) -> DetectorResult:
    lines = [l for l in _src(ev, "sudo") if "NOPASSWD" in l]
    if not lines:
        return _make(True, check_id="SUDO-002", category="Sudo",
                     title="NOPASSWD sudo usage", severity=Severity.CLEAN,
                     detail="No NOPASSWD sudo invocations observed.")
    return _make(False, check_id="SUDO-002", category="Sudo",
                 title="NOPASSWD sudo usage", severity=Severity.MEDIUM, status="WARN",
                 detail=f"{len(lines)} NOPASSWD sudo invocation(s).",
                 recommendation="Audit /etc/sudoers.d for NOPASSWD entries.",
                 reference="MITRE T1548.003")


@detector
def sudo_suspicious_cmd(ev: dict) -> DetectorResult:
    bad = ("rm -rf /", "wget http", "curl http", "base64 -d", "/dev/tcp/",
           "nc -l", "chmod 777", "passwd ", "useradd ", "visudo")
    hits = [l for l in _src(ev, "sudo") if any(b in l for b in bad)]
    if not hits:
        return _make(True, check_id="SUDO-003", category="Sudo",
                     title="Suspicious sudo commands", severity=Severity.CLEAN,
                     detail="No suspicious command patterns in sudo log.")
    return _make(False, check_id="SUDO-003", category="Sudo",
                 title="Suspicious sudo commands", severity=Severity.HIGH, status="FAIL",
                 detail=f"{len(hits)} sudo command(s) match suspicious patterns.",
                 recommendation="Investigate matching invocations and the responsible user.",
                 reference="MITRE T1059.004")


# =============================================================== #
#                            USERS
# =============================================================== #

@detector
def users_new_user(ev: dict) -> DetectorResult:
    lines = [l for l in _all_auth(ev) + _src(ev, "logind")
             if "new user" in l.lower() or "useradd" in l.lower()]
    if not lines:
        return _make(True, check_id="USR-001", category="Users",
                     title="New user created", severity=Severity.CLEAN,
                     detail="No user creation events observed.")
    return _make(False, check_id="USR-001", category="Users",
                 title="New user created", severity=Severity.HIGH, status="FAIL",
                 detail=f"{len(lines)} user creation event(s) detected.",
                 recommendation="Verify accounts in /etc/passwd against inventory.",
                 reference="MITRE T1136.001")


@detector
def users_password_changed(ev: dict) -> DetectorResult:
    lines = [l for l in _all_auth(ev) if "password changed" in l.lower() or "passwd" in l.lower()]
    if not lines:
        return _make(True, check_id="USR-002", category="Users",
                     title="Password changes", severity=Severity.CLEAN,
                     detail="No password change events.")
    return _make(False, check_id="USR-002", category="Users",
                 title="Password changes", severity=Severity.MEDIUM, status="WARN",
                 detail=f"{len(lines)} password change event(s).",
                 recommendation="Confirm change was user-initiated.",
                 reference="MITRE T1098")


@detector
def users_admin_group(ev: dict) -> DetectorResult:
    group_lines = _src(ev, "group")
    admins = []
    for l in group_lines:
        parts = l.split(":")
        if len(parts) >= 4 and parts[0] in ("wheel", "sudo", "admin"):
            for u in parts[3].split(","):
                if u: admins.append(f"{parts[0]}:{u}")
    if not admins:
        return _make(True, check_id="USR-003", category="Users",
                     title="Admin group membership", severity=Severity.CLEAN,
                     detail="No admin-group members observed (snapshot).")
    sev = Severity.MEDIUM if len(admins) > 3 else Severity.LOW
    return _make(False, check_id="USR-003", category="Users",
                 title="Admin group membership", severity=sev, status="INFO",
                 detail=f"{len(admins)} admin-group membership(s) in snapshot.",
                 recommendation="Ensure each admin account is justified.",
                 reference="MITRE T1078.003", iocs=admins[:20])


# =============================================================== #
#                            FIREWALL
# =============================================================== #

@detector
def fw_drops(ev: dict) -> DetectorResult:
    lines = _src(ev, "ufw") + _src(ev, "nft") + _src(ev, "firewalld")
    drops = [l for l in lines if "BLOCK" in l or "DROP" in l or "REJECT" in l]
    if not drops:
        return _make(True, check_id="FW-001", category="Firewall",
                     title="Firewall drops", severity=Severity.CLEAN,
                     detail="No firewall drops in window.")
    ips = Counter()
    for l in drops:
        for ip in IP_RE.findall(l):
            ips[ip] += 1
    top = ips.most_common(5)
    sev = Severity.HIGH if any(c > 100 for _, c in top) else Severity.MEDIUM
    return _make(False, check_id="FW-001", category="Firewall",
                 title="Firewall drops", severity=sev, status="WARN",
                 detail=f"{len(drops)} firewall drops; top sources: {top}.",
                 recommendation="Persist blocks for repeat offenders, consider geo-block.",
                 reference="MITRE T1190",
                 iocs=[ip for ip, _ in top])


@detector
def fw_repeat_source(ev: dict) -> DetectorResult:
    lines = _src(ev, "ufw") + _src(ev, "nft")
    ips = Counter()
    for l in lines:
        if "BLOCK" in l or "DROP" in l:
            for ip in IP_RE.findall(l):
                ips[ip] += 1
    repeat = [ip for ip, c in ips.items() if c >= 50]
    if not repeat:
        return _make(True, check_id="FW-002", category="Firewall",
                     title="Repeated firewall drops from same source",
                     severity=Severity.CLEAN,
                     detail="No source crossed 50 drops.")
    return _make(False, check_id="FW-002", category="Firewall",
                 title="Repeated firewall drops from same source",
                 severity=Severity.HIGH, status="FAIL",
                 detail=f"{len(repeat)} source(s) with 50+ drops.",
                 recommendation="Add permanent deny rules and log to SIEM.",
                 reference="MITRE T1595", iocs=repeat[:20])


# =============================================================== #
#                            KERNEL
# =============================================================== #

@detector
def kern_oops(ev: dict) -> DetectorResult:
    lines = [l for l in _src(ev, "kernel") + _src(ev, "dmesg")
             if "Oops" in l or "kernel panic" in l.lower()]
    if not lines:
        return _make(True, check_id="KRN-001", category="Kernel",
                     title="Kernel oops/panic", severity=Severity.CLEAN,
                     detail="No kernel oops or panics.")
    return _make(False, check_id="KRN-001", category="Kernel",
                 title="Kernel oops/panic", severity=Severity.CRITICAL, status="FAIL",
                 detail=f"{len(lines)} kernel oops/panic line(s) — instability or exploit attempt.",
                 recommendation="Inspect surrounding dmesg and consider memory tests.",
                 reference="MITRE T1499")


@detector
def kern_oom(ev: dict) -> DetectorResult:
    lines = [l for l in _src(ev, "kernel") + _src(ev, "dmesg")
             if "Out of memory" in l or "oom-killer" in l.lower() or "Killed process" in l]
    if not lines:
        return _make(True, check_id="KRN-002", category="Kernel",
                     title="OOM killer activity", severity=Severity.CLEAN,
                     detail="No OOM kills observed.")
    return _make(False, check_id="KRN-002", category="Kernel",
                 title="OOM killer activity", severity=Severity.MEDIUM, status="WARN",
                 detail=f"{len(lines)} OOM event(s).",
                 recommendation="Investigate memory leak or tune cgroup limits.",
                 reference="MITRE T1499.004")


@detector
def kern_segfault(ev: dict) -> DetectorResult:
    lines = [l for l in _src(ev, "kernel") + _src(ev, "dmesg") if "segfault" in l]
    if not lines:
        return _make(True, check_id="KRN-003", category="Kernel",
                     title="Segfault burst", severity=Severity.CLEAN,
                     detail="No segfaults in window.")
    procs = Counter()
    for l in lines:
        m = re.search(r"(\S+)\[\d+\]: segfault", l)
        if m: procs[m.group(1)] += 1
    sev = Severity.HIGH if any(c > 5 for c in procs.values()) else Severity.LOW
    return _make(False, check_id="KRN-003", category="Kernel",
                 title="Segfault burst", severity=sev, status="WARN",
                 detail=f"{len(lines)} segfault(s); top procs: {procs.most_common(3)}.",
                 recommendation="Possible exploit attempt; review the binary.",
                 reference="MITRE T1499.004",
                 iocs=[p for p, _ in procs.most_common(10)])


@detector
def kern_usb_plug(ev: dict) -> DetectorResult:
    lines = [l for l in _src(ev, "usb") if l.strip()]
    if not lines:
        return _make(True, check_id="KRN-004", category="Kernel",
                     title="USB device plug events", severity=Severity.CLEAN,
                     detail="No USB plug events observed.")
    return _make(False, check_id="KRN-004", category="Kernel",
                 title="USB device plug events", severity=Severity.LOW, status="INFO",
                 detail=f"{len(lines)} USB-related kernel event(s).",
                 recommendation="On servers, consider USBGuard to block unknown devices.",
                 reference="MITRE T1200")


@detector
def kern_module_load(ev: dict) -> DetectorResult:
    lines = [l for l in _src(ev, "kernel") if "module" in l.lower() and "loaded" in l.lower()]
    if not lines:
        return _make(True, check_id="KRN-005", category="Kernel",
                     title="Runtime kernel module load", severity=Severity.CLEAN,
                     detail="No runtime module loads.")
    return _make(False, check_id="KRN-005", category="Kernel",
                 title="Runtime kernel module load", severity=Severity.MEDIUM, status="WARN",
                 detail=f"{len(lines)} module load event(s).",
                 recommendation="Confirm module list against expected kernel modules.",
                 reference="MITRE T1547.006")


# =============================================================== #
#                            PACKAGES
# =============================================================== #

@detector
def pkg_changes(ev: dict) -> DetectorResult:
    lines = _src(ev, "pkg_log")
    if not lines:
        return _make(True, check_id="PKG-001", category="Packages",
                     title="Package changes", severity=Severity.CLEAN,
                     detail="No package changes recorded.")
    return _make(False, check_id="PKG-001", category="Packages",
                 title="Package changes", severity=Severity.LOW, status="INFO",
                 detail=f"{len(lines)} package transaction line(s) since window start.",
                 recommendation="Confirm changes match a known maintenance event.",
                 reference="MITRE T1072")


@detector
def pkg_security_removal(ev: dict) -> DetectorResult:
    bad = ("ufw", "fail2ban", "auditd", "apparmor", "selinux", "firewalld")
    hits = [l for l in _src(ev, "pkg_log")
            if "remove" in l.lower() and any(b in l.lower() for b in bad)]
    if not hits:
        return _make(True, check_id="PKG-002", category="Packages",
                     title="Removal of security packages", severity=Severity.CLEAN,
                     detail="No removal of security-relevant packages.")
    return _make(False, check_id="PKG-002", category="Packages",
                 title="Removal of security packages", severity=Severity.CRITICAL, status="FAIL",
                 detail=f"{len(hits)} removal(s) of security-relevant packages.",
                 recommendation="Reinstall and audit who triggered the removal.",
                 reference="MITRE T1562.001")
