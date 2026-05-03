# 🛰️ logsentry

**Linux log forensics — collects, scores and surfaces suspicious activity from system logs**

🐍 Python · 🐚 Shell · 🐧 Linux · 🔐 Security · 📊 Excel

---

## 📖 About

`logsentry` is a hybrid **Shell + Python** CLI tool that turns raw Linux logs into a scored security report. A POSIX shell collector pulls evidence directly from `journalctl`, `/var/log/auth.log`, `last`, `lastb`, `sudo`, `ufw` and `dmesg`, and a Python engine parses, correlates and scores the events — producing terminal output and a professional **Excel report**.

The project:

- Runs **20+ log analyzers** across 6 categories
- Assigns a **threat score (0–100) and grade (A–F)** to recent log activity
- Maps findings to **MITRE ATT&CK** technique IDs
- Outputs a 4-sheet **Excel report** with color-coded events, IOC list, and per-category breakdown
- Exports to **JSON** for SIEM / dashboards
- Supports a **CI mode** (`--fail-on-critical`) that exits with code 1 on critical findings

Built specifically for Arch / Fedora / Debian / Ubuntu with zero external API calls — just your own logs.

---

## ✨ Features

- 🐚 Native **shell collector** (`scripts/collect.sh`) — works without Python on the target host
- 🐍 Pure-Python analyzer engine — no heavy deps
- 🔐 20+ detectors: brute-force SSH, sudo abuse, new users, kernel OOPS, firewall drops, failed logins, suspicious cron, USB plug events, package tampering, etc.
- 📊 Professional Excel report (4 sheets: Summary, Events, By Category, IOCs)
- 🎯 Score + grade system (A–F)
- 🗂️ MITRE ATT&CK mapping per finding
- 🔍 Filter by category, severity, or time window
- 🤖 CI-friendly (`--fail-on-critical` exit code)
- 📄 JSON export for scripting / SIEM ingestion
- 🐧 Works on Arch, Fedora, Debian, Ubuntu

---

## 📋 Detectors Covered

| Category | Detectors |
|---|---|
| **Auth** | Failed SSH logins · Brute-force bursts · Successful root login · New SSH keys · Login from new IP |
| **Sudo** | NOPASSWD usage · Failed sudo · Sudo by non-admin user · Suspicious command patterns |
| **Users** | New user created · Password changed · Group membership change · `wheel`/`sudo` additions |
| **Firewall** | UFW/nftables drops · Repeated drops from same source · Outbound to known-bad ports |
| **Kernel** | OOPS / panic · OOM kills · Segfaults burst · USB device plugged · Module loaded at runtime |
| **Packages** | Pacman/dnf/apt installs since boot · Removal of security packages · Repo file modified |

---

## 📁 Project Structure

```
logsentry/
├── scripts/
│   └── collect.sh           # POSIX shell collector (journalctl, auth.log, ufw, last...)
├── src/
│   ├── analyzers/
│   │   ├── engine.py        # Core engine, detector registry, AnalysisReport model
│   │   └── detectors.py     # All 20+ detector implementations
│   ├── reporters/
│   │   ├── excel_reporter.py  # 4-sheet Excel report with openpyxl
│   │   └── terminal.py        # Color terminal output
│   └── utils/
├── tests/
│   └── test_engine.py       # Unit tests (pytest)
├── .github/
│   └── workflows/
│       └── ci.yml
├── logsentry.py             # Entry point
├── requirements.txt
└── README.md
```

---

## 🚀 Installation

Clone repository:

```bash
git clone https://github.com/hevkyr/logsentry.git
cd logsentry
```

Install dependencies:

```bash
pip install -r requirements.txt
chmod +x scripts/collect.sh
```

---

## ▶ Usage

### Collect logs (shell, runs on target host)

```bash
sudo ./scripts/collect.sh --since "24 hours ago" --out evidence.json
```

The collector emits a single self-describing JSON bundle with normalized events from `journalctl`, `auth.log`, `last`, `lastb`, `sudo`, `ufw` and `dmesg`. It runs on any POSIX shell with no Python required, so you can ship it to a server, collect, and analyze elsewhere.

### Run analysis (terminal only)

```bash
python logsentry.py evidence.json
```

You can also let `logsentry.py` invoke the collector for you:

```bash
sudo python logsentry.py --collect --since "24 hours ago"
```

Example output:

```
🔍 Analyzing 4.812 log events...

══════════════════════════════════════════════════════════════
  🛰️  LOGSENTRY — Linux Log Forensics
══════════════════════════════════════════════════════════════
  Host    : thinkpad-fedora
  OS      : Fedora Linux 40
  Kernel  : 6.8.9-300.fc40.x86_64
  Window  : 2026-05-02 14:32 → 2026-05-03 14:32
  Time    : 03/05/2026 14:32:01

  Threat Score: 72/100  Grade: C

  [██████████████████████████░░░░░░░░░░░░░░] 14/20 clean

  CRITICAL  : 1
  HIGH      : 2
  MEDIUM    : 3
  Warnings  : 2
  Triggered : 6
```

### Generate Excel report

```bash
python logsentry.py evidence.json --output reports/audit_$(date +%F).xlsx
```

Produces a 4-sheet workbook:

```
📊 Summary       — Score, grade, KPI cards, severity breakdown
🚨 Events        — All triggered detectors with color-coded status and detail
📂 By Category   — Trigger rate per category (Auth, Sudo, Kernel, Firewall...)
🎯 IOCs          — Indicators of compromise: IPs, users, processes, files
```

### Verbose terminal output (shows remediation)

```bash
python logsentry.py evidence.json --verbose
```

Example:

```
❌ [CRITICAL] SSH Brute-force burst (Auth)
       217 failed logins from 45.155.205.233 in 4 minutes — user: root
       Fix: Block source via 'ufw deny from 45.155.205.233' and rotate SSH keys.
       MITRE: T1110.001 (Brute Force: Password Guessing)
```

### Filter by category

```bash
python logsentry.py evidence.json --category Auth --verbose
python logsentry.py evidence.json --category Kernel
python logsentry.py evidence.json --category Firewall
```

### Filter by minimum severity

```bash
python logsentry.py evidence.json --severity HIGH
python logsentry.py evidence.json --severity CRITICAL --verbose
```

### Filter by time window

```bash
python logsentry.py evidence.json --since "2026-05-03 00:00" --until "2026-05-03 12:00"
```

### Export to JSON

```bash
python logsentry.py evidence.json --json findings.json
```

Example `findings.json`:

```json
{
  "meta": {
    "hostname": "thinkpad-fedora",
    "score": 72,
    "grade": "C",
    "total_detectors": 20,
    "clean": 14,
    "triggered": 6,
    "critical": 1,
    "high": 2
  },
  "results": [
    {
      "id": "AUTH-002",
      "category": "Auth",
      "title": "SSH Brute-force burst",
      "severity": "CRITICAL",
      "status": "FAIL",
      "detail": "217 failed logins from 45.155.205.233 in 4 minutes (user: root).",
      "recommendation": "Block source via ufw and rotate SSH keys.",
      "reference": "MITRE T1110.001",
      "iocs": ["45.155.205.233"]
    }
  ]
}
```

### CI mode (exit 1 on critical findings)

```bash
python logsentry.py evidence.json --fail-on-critical
echo $?  # 0 = clean, 1 = critical found
```

Combine with Excel + JSON in CI pipeline:

```bash
sudo ./scripts/collect.sh --since "1 hour ago" --out evidence.json
python logsentry.py evidence.json --output audit.xlsx --json findings.json --fail-on-critical
```

---

## 📊 Excel Report Preview

| Sheet | Content |
|---|---|
| **📊 Summary** | Score card · Grade · KPI boxes · Severity table |
| **🚨 Events** | All triggered detectors · Color by severity · Filterable · Wrap text |
| **📂 By Category** | Trigger rate per category with Excel formulas |
| **🎯 IOCs** | Unique IPs / users / processes / files seen across findings |

Color coding used in Events sheet:

| Color | Meaning |
|---|---|
| 🔴 Red | CRITICAL — Immediate response required |
| 🟠 Orange | HIGH — Investigate within 24h |
| 🟡 Yellow | MEDIUM — Review within the week |
| 🟦 Cyan | LOW — Informational |
| 🟩 Green | CLEAN |

---

## 🐚 The Shell Collector

`scripts/collect.sh` is a self-contained POSIX shell script. It auto-detects the available log sources and emits normalized JSON, so the analyzer never has to touch the system directly.

Detected sources:

- `journalctl` (systemd hosts) — auth, sudo, kernel, package units
- `/var/log/auth.log` (Debian/Ubuntu fallback)
- `last`, `lastb` — login / failed login history
- `ufw status` and `journalctl -u ufw` — firewall drops
- `dmesg` — kernel events (USB, OOPS, OOM)
- `pacman -Q --info`, `dnf history`, `apt list --installed` — package timeline

Run it standalone for portability:

```bash
sudo ./scripts/collect.sh --since "24 hours ago" --out /tmp/evidence.json
scp /tmp/evidence.json analyst@workstation:~/
```

Then analyze offline on your workstation — no Python required on the production host.

---

## 🧪 Tests

```bash
pytest tests/ -v
```

With coverage:

```bash
pytest tests/ --cov=src --cov-report=term-missing
```

The shell collector is also linted in CI:

```bash
shellcheck scripts/collect.sh
```

---

## ⚠ Notes

- Some sources (`/var/log/auth.log`, `lastb`, full `journalctl`) require `sudo` to read fully
- On non-systemd hosts the collector falls back to `/var/log/auth.log` automatically
- Running as a regular user will still produce ~70% of detectors; privileged sources will be marked `WARN`
- Findings reference [MITRE ATT&CK](https://attack.mitre.org/) techniques where applicable

---

## 🛡️ Recommended Incident Response Workflow

```bash
# 1. Collect evidence and analyze
sudo ./scripts/collect.sh --since "24 hours ago" --out evidence.json
python logsentry.py evidence.json --output audit_before.xlsx --verbose

# 2. Block IOCs and apply remediations from the report

# 3. Re-collect and re-analyze to confirm threats are gone
sudo ./scripts/collect.sh --since "1 hour ago" --out evidence_after.json
python logsentry.py evidence_after.json --output audit_after.xlsx

# 4. Compare scores
```

---

## 📜 License

MIT License

[🇺🇸 English](#) · [🇧🇷 Português](#sobre)

---

## 🇧🇷 Sobre

`logsentry` é uma ferramenta CLI híbrida em **Shell + Python** que transforma logs brutos do Linux em um relatório de segurança pontuado. Um coletor POSIX em shell extrai evidências direto de `journalctl`, `/var/log/auth.log`, `last`, `lastb`, `sudo`, `ufw` e `dmesg`, e um motor em Python parseia, correlaciona e pontua os eventos — gerando saída no terminal e **planilha Excel profissional**.

Funcionalidades principais:

- **20+ detectores** de log em 6 categorias
- **Score (0–100) e grade (A–F)** para a janela analisada
- Relatório Excel com **4 abas**: Resumo, Eventos, Por Categoria, IOCs
- Mapeamento **MITRE ATT&CK** por finding
- Filtro por categoria (`--category Auth`), severidade (`--severity HIGH`) ou janela de tempo
- Modo CI (`--fail-on-critical`) para pipelines automatizados
- Exportação JSON para scripts / SIEM
- Datas no formato **dd/mm/yyyy**, compatível com Arch, Fedora, Debian e Ubuntu

### Por que Shell + Python?

O coletor em shell roda em qualquer host POSIX **sem Python instalado**, gera um JSON portátil, e você analisa onde quiser. Ideal para servidores enxutos, contêineres e resposta a incidentes em máquinas que você não controla totalmente.
