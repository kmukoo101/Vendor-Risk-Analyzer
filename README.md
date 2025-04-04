# 🛡️ CVEye Vendor Risk Analyzer

A cybersecurity tool designed for businesses to assess and track the cyber risk posture of third-party vendors. It combines open-source intelligence, email breach checks, IP reputation, and GUI reporting, creasted to be customizable and exportable.

---

## Features

- Domain Analysis: HTTPS check, SSL cert expiration, domain age
- Data Breach Detection: Built-in breach detection and HIBP email check
- Shodan Integration: Open ports and exposure insights
- IP Reputation: Uses IPInfo.io to flag risky IP addresses
- Risk Scoring: Auto-calculated score and High/Medium/Low label
- GUI: Scrollable scan results with export buttons
- Report Export: PDF and HTML supported
- Pluggable API keys: Via environment variables
- Scheduling Support: Automate weekly scans

---

## Requirements

- Python 3.8+
- `requests`, `fpdf` (install via `pip install -r requirements.txt`)
- (Optional) API keys for:
  - `SHODAN_API_KEY`
  - `HIBP_API_KEY`
  - `IPINFO_TOKEN`

---

## ⚙️ Setup

1. Clone repo:

```bash
git clone https://github.com/kmukoo101/vendor-risk-analyzer
cd vendor-risk-analyzer
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Add your vendors to a `vendors.json` file:

```json
[
  {
    "name": "Acme Inc",
    "domain": "acme.com",
    "contact_email": "security@acme.com"
  },
  {
    "name": "Breachy Corp",
    "domain": "riskyvendor.io",
    "contact_email": "contact@riskyvendor.io"
  }
]
```

---

## Run Analyzer

```bash
python your_script_name.py
```

Or you can launch the GUI and click "Run Scan" to get started.

---

## Export Reports

- Use the Export to PDF or Export to HTML buttons in the GUI after your scan
- Reports will include:
  - Risk level
  - Risk score
  - Indicators and data for each vendor

---

## How to Automate Weekly Scans

### Windows (Use Task Scheduler)

1. Create a `run_vendor_scan.bat` file:

```bat
@echo off
cd /d "C:\Path\To\Your\Script"
python your_script_name.py
```

2. Open Task Scheduler
3. Create Basic Task > Choose Weekly > Point to `.bat` file

---

### Linux/macOS (Use `cron`)

1. Open crontab:

```bash
crontab -e
```

2. Add a weekly job:

```cron
0 9 * * 1 python3 /path/to/your_script_name.py
```

