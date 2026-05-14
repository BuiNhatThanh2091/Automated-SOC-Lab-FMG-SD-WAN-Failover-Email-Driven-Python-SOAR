# Fortinet-SecOps-Hardware-Lab

**SD-WAN Resilience & Python Automation on Physical Fortinet Hardware @ HCMUTE**

![Python 3.x](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Fortinet](https://img.shields.io/badge/Fortinet-Hardware-red?style=flat-square&logo=fortinet)
![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## ⚡ TL;DR

This project demonstrates a hands-on university lab implementation of centralized security architecture deployed on physical hardware at HCMUTE Security Lab. Utilizing FortiManager 200F, the infrastructure connects Data Center (DC) and Disaster Recovery (DR) sites via IPsec VPN. As a team member responsible for the SD-WAN and automation components, I tackled two core problems: ensuring network availability through SD-WAN failover verified via CLI session analysis, and building a custom Python polling engine (SOAR) to overcome Read-Only API constraints for automated monitoring.

---

## 🏗️ Core Architecture & Hardware Troubleshooting

```text
[DC Site - Servers Farm]                             [DR Site]
      FortiManager 200F                                  |
            │                                            |
      [DC Internal]                                [DR Internal]
     FortiGate 80E                                 FortiGate 50E
            │                                            │
     [DC Core Switch]                             (IPsec VPN Tunnel)
Allied Telesis x530 L3 Switch                            │
            │                                            |
      [DC External]                                [DR External]
    FortiGate 100E ◄════════(IPsec VPN)════════►   FortiGate 80E
```

<details>
<summary>📋 Full Hardware Inventory</summary>

| Device                  | Model                      | Role                                 | Management IP       |
| ----------------------- | -------------------------- | ------------------------------------ | ------------------- |
| FortiManager            | 200F                       | Centralized management + log storage | IP_FortiManager     |
| FortiGate (DC)          | 100E Bundle                | External firewall — Data Center      | IP_FortiGate-100E   |
| FortiGate (DC Internal) | 80E Bundle                 | Internal firewall — Data Center      | IP_FortiGate-80E-DR |
| FortiGate (DR)          | 80E Bundle                 | External firewall — DR site          | IP_FortiGate-50E    |
| FortiGate (DR Internal) | 50E                        | Internal firewall — DR site          | IP_FortiGate-50E    |
| Switch (Core)           | Allied Telesis x530-28GTXm | L3 Core switching                    | IP_FortiGate-50E    |
| FortiMail               | —                          | SMTP relay for Python alerting       | mail.hcmute.com     |

</details>

**Hardware Troubleshooting Reality:**

Troubleshooting on real enterprise hardware surfaces issues that simulated environments never expose.

- **Incident A:** Security Mode was inadvertently enabled on the FortiGate 100E management interface, blocking all access. Root cause analysis led to physical port reconfiguration to restore operations.
- **Incident B:** During SD-WAN setup on FortiGate 80E-DR, a port misconfiguration caused Web GUI lockout. I recovered the device by connecting directly via a physical console cable (RJ45) and executing CLI commands (`set status up`).

> 11 lab scenarios were completed covering centralized management, policy deployment, logging, event handling, CLI scripting, SNMP monitoring, and SD-WAN failover — all on physical hardware.

---

## 💎 Feature 1: SD-WAN Resilience & CLI Verification

**Business Justification:**

In a modern Data Center and Disaster Recovery (DC-DR) architecture, business continuity is critical. If the primary WAN link fails at the DR site, operations must continue seamlessly without manual intervention. SD-WAN solves this by intelligently routing traffic across available links based on real-time health metrics.

**Implementation:**

- **Architecture:** `port2` (primary, priority 1) → `port1` (backup, priority 2), evaluated via Performance SLA `DefaultGmail`.
- **Config Flow:** Configured centrally on FortiManager and pushed to FortiGate-80E-DR.
- **Validation:** I physically simulated a WAN failure and verified the traffic shift exclusively through FortiOS CLI.

**CLI Verification Trace:**

```bash
# Confirm SD-WAN rule and member status
diagnose sys sdwan service

# Monitor Performance SLA health-check
diagnose sys sdwan health-check

# Verify active traffic path (before failover: sdwanmbrseq=1 = port2)
diagnose sys session filter clear
execute ping 8.8.8.8
diagnose sys session list

# Simulate failover
config system interface
  edit port2
    set status down
  next
end

# Verify failover (sdwanmbrseq=2 = port1)
diagnose sys session list

# Restore
config system interface
  edit port2
    set status up
  next
end
```

**Sample Output (sdwanmbrseq evidence):**

```text
--- BEFORE failover (port2 active) ---
state=00 proto=1 ... sdwanmbrseq=1 ...

--- AFTER failover (port2 down, port1 active) ---
state=00 proto=1 ... sdwanmbrseq=2 ...
```

> Output format is illustrative — actual session data captured during lab verification.

_Result:_ `sdwanmbrseq` confirmed the traffic path dynamically switched from port2 (seq=1) to port1 (seq=2) with zero Internet disruption.

**This is the difference between knowing SD-WAN exists and proving it works under failure conditions.**

---

## 🐍 Feature 2: Custom SOAR Engine (Read-Only API Workaround)

**The Constraint:**

The assigned account was restricted to Read-Only API access on FortiManager — no Write permissions were available.

**The Solution:**

Instead of relying on basic ping tools, I engineered a 4-phase Python polling bot (SOAR) that pulls telemetry from the FortiManager REST API, evaluates state, and leverages a FortiMail server for alerting. FortiMail was selected as the alerting relay — rather than an external SMTP provider — because it was already deployed within the lab network, enabling a zero-dependency, internally-routed alerting chain consistent with an air-gapped enterprise environment.

**Architecture Flow:**

```text
Python Bot (Laptop)
 │
 ├─[GET /jsonrpc]──► FortiManager 200F (Read-Only API)
 │                   │
 │                   JSON: conn_status, config_status
 │
 ├─[if anomaly detected]
 │ └─[smtplib SMTP]──► FortiMail (mail_server) ──► IT Admin
 │
 └─[pandas + openpyxl]──► Audit_Report.xlsx
                          RED = CRITICAL (conn: down)
                          YELLOW = WARNING (config: out-of-sync)
```

**Native Event Handler vs Custom Python Bot:**

| Dimension          | Lab 7 (Event Handler)                | Python Bot (Custom)                     |
| ------------------ | ------------------------------------ | --------------------------------------- |
| **Data Flow**      | Push — FortiGate pushes logs to FMG  | Pull — Python polls FMG API             |
| **Trigger**        | Log-based (past events)              | State-based (real-time DB)              |
| **Blind Spot**     | If FG loses power, no log = no alert | API returns `down` immediately          |
| **Logic Location** | Inside FortiOS on FMG server         | External Python script (portable)       |
| **Flexibility**    | Limited to vendor-defined actions    | Unlimited: Excel, Email, Telegram, etc. |

**Core Code Skeleton:**

```python
import requests, smtplib, pandas as pd
from email.mime.text import MIMEText
from openpyxl import load_workbook
from openpyxl.styles import PatternFill

FMG_IP = "IP_FortiManager"
MAIL_SERVER = "mail_server"   # FortiMail server
MAIL_USER = "mail_user"
IT_EMAIL   = "mail_vanhanh_IT"

def send_alert(device, ip, error):
    msg = MIMEText(f"[ALERT] Device: {device} ({ip})\nError: {error}")
    msg['Subject'] = f"[URGENT] Device Health: {device}"
    msg['From'] = MAIL_USER
    msg['To']   = IT_EMAIL
    with smtplib.SMTP(MAIL_SERVER, 25) as s:
        s.sendmail(MAIL_USER, IT_EMAIL, msg.as_string())

def run_audit():
    # --- Phase 1: Acquire (Real API — requires active FMG session token) ---
    # response = requests.get(
    #     f"https://{FMG_IP}/jsonrpc",
    #     json={"method": "get", "params": [{"url": "/dvmdb/device"}], "session": SESSION_TOKEN},
    #     verify=False
    # )
    # devices = response.json()["result"][0]["data"]

    # --- Mock data for offline demonstration ---
    devices = [
        {"name": "FortiGate-100E", "ip": "IP_FortiGate-100E", "conn_status": "up",   "conf_status": "synchronized"},
        {"name": "FortiGate-80E-DR","ip": "IP_FortiGate-80E-DR", "conn_status": "up",   "conf_status": "out-of-sync"},
        {"name": "FortiGate-50E",   "ip": "IP_FortiGate-50E", "conn_status": "down", "conf_status": "unknown"},
    ]

    # Phase 2 & 3: Validate + Alert
    for dev in devices:
        if dev['conn_status'] == 'down':
            send_alert(dev['name'], dev['ip'], 'Connection Lost')
        elif dev['conf_status'] == 'out-of-sync':
            send_alert(dev['name'], dev['ip'], 'Config Drift Detected')

    # Phase 4: Export colored Excel report
    df = pd.DataFrame(devices)
    df.to_excel("Audit_Report.xlsx", index=False)
    # ... openpyxl color-coding logic

run_audit()
```

**Most automation tutorials assume full API access. This project demonstrates the real-world skill of designing around infrastructure constraints — a core competency for any SOC or NetOps engineer.**

---

## 🎯 Skills Highlight

- ✅ **SD-WAN Architecture & Testing:** Configured Performance SLAs and proved failover mechanics using deep CLI session analysis.
- ✅ **Python REST API Automation:** Built a state-based polling engine (`requests`, `smtplib`, `pandas`) to bypass Read-Only API limitations.
- ✅ **Physical Hardware Troubleshooting:** Recovered devices via console cable (RJ45) access and diagnosed interface Security Mode lockouts.
- ✅ **Centralized Management:** Handled Policy Packages, ADOMs, and Install Wizards on FortiManager 200F.

## 📁 Repository Structure
