# CYBERNOVA AI Threat Hunting Toolkit

> **A Python-based defensive security toolkit for IOC investigation, threat hunting, log analysis, timeline reconstruction, Sigma detection, YARA scanning, automated reporting, and security visualization.**

![Python](https://img.shields.io/badge/Python-3.13-blue)
![Tests](https://img.shields.io/badge/tests-20%20passed-brightgreen)
![Security](https://img.shields.io/badge/focus-Blue%20Team%20%7C%20Threat%20Hunting-red)
![Status](https://img.shields.io/badge/status-Active%20Development-orange)

---

## 📌 Overview

**CYBERNOVA AI Threat Hunting Toolkit** is a modular Python cybersecurity project designed to demonstrate practical **Security Operations Center (SOC)**, **blue-team**, and **threat-hunting** workflows.

The toolkit provides multiple investigation capabilities through a unified command-line interface:

* IOC classification and investigation
* Security log hunting
* File hash analysis
* Threat-intelligence lookup using controlled test data
* Investigation timeline reconstruction
* Sigma rule detection
* YARA rule scanning
* Automated JSON reporting
* HTML security dashboard generation
* Automated unit/integration testing

The project is intentionally built around **safe, controlled sample data** so that security investigation techniques can be demonstrated without requiring access to real-world malicious infrastructure.

---

# 🎯 Project Goals

The primary goals of the project are to demonstrate the ability to:

1. Analyze security evidence.
2. Identify suspicious indicators.
3. Investigate security events.
4. Correlate related activity.
5. Apply detection rules.
6. Reconstruct investigation timelines.
7. Generate structured investigation reports.
8. Present findings through a security dashboard.
9. Automate repetitive security-analysis tasks with Python.
10. Build and test security tooling using professional development practices.

---

# 🏗️ Architecture

The toolkit follows a modular investigation architecture.

```text
                         ┌─────────────────────────┐
                         │     Security Evidence   │
                         │                         │
                         │  Logs / Files / IOCs    │
                         └────────────┬────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────┐
                    │       Investigation Layer       │
                    │                                 │
                    │  IOC Search                     │
                    │  Hash Analysis                  │
                    │  Log Hunting                    │
                    │  Timeline Reconstruction        │
                    └───────────────┬─────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────────┐
                    │        Detection Layer          │
                    │                                 │
                    │  Sigma Rules                    │
                    │  YARA Rules                     │
                    └───────────────┬─────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────────┐
                    │       Analysis & Findings       │
                    │                                 │
                    │  Severity                       │
                    │  Evidence                       │
                    │  Correlation                    │
                    │  Investigation Context          │
                    └───────────────┬─────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────────┐
                    │       Reporting Layer           │
                    │                                 │
                    │  JSON Reports                   │
                    │  HTML Dashboard                 │
                    └───────────────┬─────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────────┐
                    │       Analyst / Reviewer        │
                    └─────────────────────────────────┘
```

---

# 🧩 Core Modules

## 1. IOC Investigation

**Module:**

```text
hunters/ioc_search.py
```

The IOC investigation module identifies and investigates common indicators of compromise.

Supported indicator categories include:

* IPv4 addresses
* Domains
* File hashes
* Other suspicious indicators

The module can:

* Classify an IOC
* Search security logs
* Count matching events
* Determine investigation severity
* Display matching events
* Generate a structured JSON investigation report

Example:

```bash
python3 main.py ioc 45.33.32.156
```

Example output:

```text
=== CYBERNOVA IOC ANALYSIS ===
IOC:      45.33.32.156
Type:     IP Address
Matches:  4
Severity: CRITICAL
```

---

## 2. Hash Analysis

**Module:**

```text
hunters/hash_analyzer.py
```

The hash-analysis module calculates file hashes and performs a controlled threat-intelligence lookup against simulated known indicators.

Supported hashes:

* MD5
* SHA1
* SHA256

Example:

```bash
python3 main.py hash samples/update.bin
```

The analysis produces:

```text
MD5
SHA1
SHA256
Threat Intelligence Result
Risk Level
```

This demonstrates a common SOC workflow for investigating suspicious files.

---

## 3. Log Hunting

**Module:**

```text
hunters/log_hunter.py
```

The log-hunting module parses structured security events and identifies suspicious activity.

The current detection logic includes:

* Repeated failed authentication attempts
* Successful authentication following multiple failures
* Suspicious PowerShell execution
* Suspicious DNS queries
* File-download activity

Findings are assigned severity levels such as:

```text
CRITICAL
HIGH
MEDIUM
LOW
```

Example:

```bash
python3 main.py log samples/threat_hunting.log
```

---

## 4. Timeline Reconstruction

**Module:**

```text
hunters/timeline_builder.py
```

The timeline module reconstructs the chronological sequence of events associated with an IOC.

It extracts information such as:

* Timestamp
* Action
* User
* Source IP
* Destination
* File

The module also performs basic timeline assessment.

For example, it can identify patterns such as:

```text
Repeated authentication failures
        ↓
Successful authentication
        ↓
Suspicious activity
```

Example:

```bash
python3 main.py timeline samples/threat_hunting.log 45.33.32.156
```

---

# 🛡️ Detection Engineering

## 5. Sigma Detection

**Module:**

```text
hunters/sigma_detector.py
```

**Rules:**

```text
rules/sigma/
```

Sigma detection allows the toolkit to apply structured detection rules to security log events.

Example rule:

```text
rules/sigma/failed_login.yml
```

Run Sigma detection with:

```bash
python3 main.py sigma \
    samples/threat_hunting.log \
    rules/sigma/failed_login.yml
```

Example result:

```text
=== CYBERNOVA SIGMA DETECTION ===
Log:     samples/threat_hunting.log
Rule:    rules/sigma/failed_login.yml
Matches: 3

Detection Results:
[MEDIUM] Multiple Failed Login Attempts | Line 1
[MEDIUM] Multiple Failed Login Attempts | Line 2
[MEDIUM] Multiple Failed Login Attempts | Line 3
```

This demonstrates how a detection rule can identify repeated suspicious events within security logs.

---

## 6. YARA Detection

**Module:**

```text
hunters/yara_detector.py
```

**Rules:**

```text
rules/yara/
```

The YARA integration allows the toolkit to scan controlled sample files against YARA detection rules.

Current example rule:

```text
rules/yara/suspicious_sample.yar
```

Run YARA analysis:

```bash
python3 main.py yara \
    samples/update.bin \
    rules/yara/suspicious_sample.yar
```

Example result:

```text
=== CYBERNOVA YARA ANALYSIS ===
Sample:  samples/update.bin
Rule:    rules/yara/suspicious_sample.yar
Matches: 1

Detection Results:
Rule:        CyberNova_Suspicious_Sample
Namespace:   default
Severity:    medium
Description: Detects suspicious indicators in a safe analysis sample
```

The YARA engine is implemented as a reusable Python module rather than being limited to a standalone command.

---

# 🖥️ Command-Line Interface

The main CLI is implemented in:

```text
main.py
```

The toolkit provides the following commands:

```text
cybernova
├── ioc
├── hash
├── log
├── timeline
├── sigma
└── yara
```

View all commands:

```bash
python3 main.py --help
```

Example:

```text
usage: cybernova [-h] {ioc,hash,log,timeline,sigma,yara} ...

CYBERNOVA AI Threat Hunting Toolkit
```

---

# 📊 Security Dashboard

The project includes an HTML dashboard for presenting threat-hunting findings.

Dashboard generator:

```text
dashboards/dashboard_generator.py
```

Generated dashboard:

```text
dashboards/index.html
```

Generate the dashboard:

```bash
python3 dashboards/dashboard_generator.py
```

The dashboard presents investigation results including:

* Total findings
* Critical findings
* High findings
* Medium findings
* Low findings
* Finding type
* User
* Destination
* File
* Investigation details

Open the dashboard on Linux:

```bash
google-chrome dashboards/index.html
```

A dashboard screenshot is also included:

```text
screenshots/threat-hunting-dashboard.png
```

---

# 📄 Automated Reporting

Investigation results are stored as structured JSON data.

Runtime-generated reports are stored in:

```text
reports/generated/
```

Current reports include:

```text
reports/generated/
├── hash_analysis_report.json
├── ioc_investigation_report.json
├── threat_hunting_report.json
└── timeline_report.json
```

Example reports are stored separately:

```text
reports/examples/
├── hash_analysis_report.json
├── ioc_investigation_report.json
├── threat_hunting_report.json
└── timeline_report.json
```

Structured JSON reporting makes investigation results easier to:

* Review
* Archive
* Process
* Automate
* Integrate into future security workflows

---

# 🧪 Testing

The project includes an automated test suite using `pytest`.

Run all tests:

```bash
pytest -v
```

Current test result:

```text
20 passed
```

The tests cover functionality including:

* IOC classification
* IPv4 validation
* Domain classification
* Hash classification
* Hash calculation
* Severity assessment
* Brute-force timeline assessment
* PowerShell timeline assessment
* IOC log searching
* IOC report generation
* Sigma rule loading
* Sigma event matching
* Sigma detection
* YARA rule compilation
* YARA sample detection
* YARA missing-file handling

The project also includes a GitHub Actions workflow:

```text
.github/workflows/python-tests.yml
```

This provides automated testing within the development workflow.

---

# 📁 Project Structure

```text
cybernova-threat-hunting-toolkit/
│
├── .github/
│   └── workflows/
│       └── python-tests.yml
│
├── dashboards/
│   ├── dashboard_generator.py
│   └── index.html
│
├── hunters/
│   ├── __init__.py
│   ├── hash_analyzer.py
│   ├── ioc_search.py
│   ├── log_hunter.py
│   ├── sigma_detector.py
│   ├── timeline_builder.py
│   └── yara_detector.py
│
├── reports/
│   ├── examples/
│   │   ├── hash_analysis_report.json
│   │   ├── ioc_investigation_report.json
│   │   ├── threat_hunting_report.json
│   │   └── timeline_report.json
│   │
│   └── generated/
│       ├── hash_analysis_report.json
│       ├── ioc_investigation_report.json
│       ├── threat_hunting_report.json
│       └── timeline_report.json
│
├── rules/
│   ├── sigma/
│   │   └── failed_login.yml
│   │
│   └── yara/
│       └── suspicious_sample.yar
│
├── samples/
│   ├── threat_hunting.log
│   └── update.bin
│
├── screenshots/
│   └── threat-hunting-dashboard.png
│
├── tests/
│   ├── conftest.py
│   └── test_toolkit.py
│
├── main.py
├── requirements.txt
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
└── .gitignore
```

---

# 🔬 Investigation Workflow

A typical investigation can follow this workflow:

```text
                    Security Evidence
                           │
                           ▼
                    ┌──────────────┐
                    │ Log Hunting  │
                    └──────┬───────┘
                           │
                           ▼
                    Identify IOC
                           │
                           ▼
              ┌─────────────────────────┐
              │ IOC / Hash Investigation│
              └────────────┬────────────┘
                           │
                           ▼
                 Apply Detection Rules
                    ┌──────┴──────┐
                    ▼             ▼
                  Sigma         YARA
                    │             │
                    └──────┬──────┘
                           ▼
                  Correlate Findings
                           │
                           ▼
                  Build Investigation
                      Timeline
                           │
                           ▼
                  Generate JSON Report
                           │
                           ▼
                  Security Dashboard
```

This architecture demonstrates how individual security-analysis components can work together as part of a simplified defensive investigation workflow.

---

# 🎯 Blue-Team Use Cases

## Suspicious Authentication

Identify repeated failed logins and determine whether a successful authentication occurred afterward.

## Suspicious PowerShell Activity

Detect PowerShell execution events that may require additional investigation.

## Suspicious DNS Activity

Identify DNS queries involving controlled suspicious-domain indicators.

## Suspicious File Investigation

Calculate file hashes and compare them against controlled threat-intelligence indicators.

## IOC Investigation

Search security logs for a specific IP address, domain, or hash.

## Detection Rule Testing

Apply Sigma and YARA rules against controlled security samples.

## Timeline Analysis

Reconstruct the sequence of events associated with an indicator.

## Security Reporting

Convert investigation findings into structured JSON reports.

## Security Visualization

Present important findings through the HTML dashboard.

---

# 💻 Installation

## 1. Clone the repository

```bash
git clone <repository-url>
```

## 2. Enter the project

```bash
cd cybernova-threat-hunting-toolkit
```

## 3. Create a virtual environment

```bash
python3 -m venv venv
```

## 4. Activate the environment

Linux:

```bash
source venv/bin/activate
```

Windows:

```powershell
venv\Scripts\activate
```

## 5. Install dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Quick Start

Check the CLI:

```bash
python3 main.py --help
```

Run IOC investigation:

```bash
python3 main.py ioc 45.33.32.156
```

Run hash analysis:

```bash
python3 main.py hash samples/update.bin
```

Run log hunting:

```bash
python3 main.py log samples/threat_hunting.log
```

Build an investigation timeline:

```bash
python3 main.py timeline \
    samples/threat_hunting.log \
    45.33.32.156
```

Run Sigma detection:

```bash
python3 main.py sigma \
    samples/threat_hunting.log \
    rules/sigma/failed_login.yml
```

Run YARA detection:

```bash
python3 main.py yara \
    samples/update.bin \
    rules/yara/suspicious_sample.yar
```

Generate the dashboard:

```bash
python3 dashboards/dashboard_generator.py
```

Run the test suite:

```bash
pytest -v
```

---

# 🧠 Skills Demonstrated

## Cybersecurity

* Threat hunting
* SOC workflows
* IOC investigation
* Security log analysis
* Detection engineering
* Sigma rule detection
* YARA rule scanning
* Hash analysis
* Timeline reconstruction
* Incident investigation
* Security reporting
* Blue-team operations

## Python

* Python 3
* Modular application design
* CLI development
* File processing
* Regular expressions
* JSON processing
* Exception handling
* Automation
* Report generation
* Unit and integration testing

## Security Engineering

* Detection logic
* Rule-based detection
* Evidence processing
* Event correlation
* Severity classification
* Investigation workflows
* Structured security output

## Linux & Development

* Linux command line
* Python virtual environments
* Git
* GitHub
* Git branching and commits
* Automated testing
* Project organization
* Security-tool development

---

# 🔐 Defensive Security Philosophy

The toolkit follows a simplified defensive security lifecycle:

```text
        DETECT
           │
           ▼
      INVESTIGATE
           │
           ▼
       CORRELATE
           │
           ▼
       UNDERSTAND
           │
           ▼
       DOCUMENT
           │
           ▼
        IMPROVE
```

The objective is not simply to identify suspicious activity.

A useful security investigation should help an analyst understand:

* What happened?
* When did it happen?
* What indicator is involved?
* Which events are related?
* How severe is the activity?
* What evidence supports the finding?
* What should be investigated next?

---

# 🧰 Development Practices

The project uses several practices intended to reflect real-world software and security engineering:

* Modular Python components
* Reusable detection functions
* Command-line integration
* Controlled sample data
* Automated testing
* Git version control
* Structured JSON output
* Detection-rule organization
* Dashboard generation
* Continuous testing through GitHub Actions
* Clear project documentation

---

# 🚧 Project Status

**Status: Active Development**

The core investigation architecture is currently implemented.

### Implemented

* [x] IOC classification
* [x] IOC investigation
* [x] Hash analysis
* [x] Threat-intelligence lookup
* [x] Security log hunting
* [x] Timeline reconstruction
* [x] Sigma detection
* [x] YARA detection
* [x] Unified CLI
* [x] JSON investigation reports
* [x] HTML security dashboard
* [x] Automated tests
* [x] GitHub Actions workflow
* [x] Controlled sample data

### Planned Improvements

* [ ] Expanded IOC types
* [ ] Additional Sigma rules
* [ ] Additional YARA rules
* [ ] More log formats
* [ ] Advanced event correlation
* [ ] External threat-intelligence integrations
* [ ] SIEM integration
* [ ] Improved alert prioritization
* [ ] Expanded dashboard analytics
* [ ] Additional test coverage
* [ ] Enhanced CLI options
* [ ] Detection-rule management
* [ ] Additional investigation reports

---

# 📚 Learning Objectives

This project was developed to strengthen practical skills in:

* Security Operations Center workflows
* Threat hunting
* Detection engineering
* Incident investigation
* Python security automation
* Security log analysis
* IOC analysis
* Sigma detection
* YARA detection
* Timeline analysis
* Security reporting
* Defensive security engineering

The broader objective is to demonstrate the ability to **analyze security evidence, develop detection logic, automate investigation tasks, correlate findings, and communicate security results clearly.**

---

# 👨‍💻 Author

## Ibrahim Mukhtar Saidu

Cybersecurity learner and security project developer focused on:

* Security Operations
* Threat Hunting
* Defensive Security
* Python Security Automation
* Detection Engineering
* Cybersecurity Research

### CYBERNOVA AI

This project is part of the **CYBERNOVA AI cybersecurity portfolio**.

---

# ⚠️ Security Disclaimer

This project is intended for:

* Educational purposes
* Defensive security research
* Authorized security testing
* Cybersecurity laboratory environments
* Controlled security-analysis demonstrations

Only analyze systems, files, logs, or data for which you have appropriate authorization.

The project should not be used to conduct unauthorized monitoring, intrusion, or malicious activity.

The author is not responsible for misuse of this project.

---

# 🤝 Contributing

Contributions, suggestions, improvements, detection rules, documentation improvements, and security-focused ideas are welcome.

Please review:

```text
CONTRIBUTING.md
```

before submitting changes.

---

# 📄 License

See:

```text
LICENSE
```

for licensing information.

---

# ⭐ Project Summary

**CYBERNOVA AI Threat Hunting Toolkit** demonstrates a practical defensive-security workflow that combines:

```text
IOC Investigation
        +
Hash Analysis
        +
Log Hunting
        +
Timeline Reconstruction
        +
Sigma Detection
        +
YARA Detection
        +
Automated Testing
        +
JSON Reporting
        +
Security Dashboard
        =
Integrated Threat Hunting Toolkit
```

The project is designed to demonstrate practical cybersecurity engineering skills through a modular, testable, and extensible Python implementation.
