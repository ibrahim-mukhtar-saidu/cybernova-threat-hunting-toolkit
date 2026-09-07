# CYBERNOVA AI Threat Hunting Toolkit

A local, file-based Python toolkit for practicing **IOC investigation, log hunting, hash analysis, timeline reconstruction, and Sigma/YARA detection** against controlled security data.

The project is designed as a **defensive cybersecurity learning and demonstration toolkit** for understanding core SOC and threat-hunting workflows in a small, inspectable, and highly tested codebase.

> **Scope:** This is not a SIEM, EDR, production detection platform, or threat-intelligence service. It operates on local files and does not connect to external APIs, threat-intelligence feeds, or network services.

---

## Project Metadata

| Field                    | Details                                                                   |
| ------------------------ | ------------------------------------------------------------------------- |
| **Project**              | CYBERNOVA AI Threat Hunting Toolkit                                       |
| **Author**               | Ibrahim Mukhtar Saidu                                                     |
| **Organization / Brand** | CYBERNOVA AI                                                              |
| **Language**             | Python                                                                    |
| **Interface**            | Command-Line Interface (CLI)                                              |
| **Security Domain**      | SOC / Threat Hunting / Detection Engineering                              |
| **Primary Purpose**      | Defensive cybersecurity learning and research                             |
| **Python**               | 3.11+                                                                     |
| **Tested With**          | Python 3.13                                                               |
| **Test Suite**           | 177 tests                                                                 |
| **Coverage**             | 99%                                                                       |
| **License**              | See `LICENSE`                                                             |
| **GitHub Profile**       | https://github.com/ibrahim-mukhtar-saidu                                  |
| **Repository**           | https://github.com/ibrahim-mukhtar-saidu/cybernova-threat-hunting-toolkit |

---

## Features

| Capability                                  | Module                              | Status        |
| ------------------------------------------- | ----------------------------------- | ------------- |
| IOC classification                          | `hunters/ioc_search.py`             | ✅ Implemented |
| IOC search in log files                     | `hunters/ioc_search.py`             | ✅ Implemented |
| Shared IOC validation and boundary matching | `hunters/matching.py`               | ✅ Implemented |
| MD5/SHA1/SHA256 file hashing                | `hunters/hash_analyzer.py`          | ✅ Implemented |
| Static known-bad hash lookup                | `hunters/hash_analyzer.py`          | ✅ Implemented |
| Suspicious activity log hunting             | `hunters/log_hunter.py`             | ✅ Implemented |
| Authentication anomaly detection            | `hunters/log_hunter.py`             | ✅ Implemented |
| IOC timeline reconstruction                 | `hunters/timeline_builder.py`       | ✅ Implemented |
| Simplified Sigma detection                  | `hunters/sigma_detector.py`         | ✅ Implemented |
| YARA rule scanning                          | `hunters/yara_detector.py`          | ✅ Implemented |
| JSON investigation reports                  | `hunters/*`                         | ✅ Implemented |
| Static HTML dashboard                       | `dashboards/dashboard_generator.py` | ✅ Implemented |
| Automated testing                           | `tests/test_toolkit.py`             | ✅ 177 tests   |
| Code coverage                               | `pytest-cov`                        | ✅ 99%         |

---

## Project Purpose

The toolkit demonstrates the core mechanics of a simplified SOC investigation workflow:

```text
Collect
   ↓
Parse
   ↓
Search / Analyze
   ↓
Detect
   ↓
Assess Severity
   ↓
Generate Report
   ↓
Review Dashboard
```

It provides separate investigation capabilities while keeping the implementation small enough to inspect, test, and understand.

### Investigation capabilities

* Search logs for IP addresses, domains, hashes, and other IOCs.
* Classify IOC values using structural validation.
* Calculate MD5, SHA1, and SHA256 hashes for files.
* Compare hashes against a small static known-bad dataset.
* Detect suspicious authentication and activity patterns.
* Reconstruct chronological events associated with an IOC.
* Apply simplified Sigma-style detection rules.
* Scan files using YARA rules.
* Generate JSON investigation reports.
* Render a static HTML threat-hunting dashboard.

---

## Problem Being Solved

Security analysts repeatedly need to answer questions such as:

* Does this IP, domain, or hash appear in the available telemetry?
* Is this file associated with a known-bad hash?
* What events occurred around a suspicious indicator?
* Did a suspicious authentication sequence occur?
* Does an event match a detection rule?
* Can the investigation results be represented in a structured report?

This project implements these investigative tasks as isolated, testable Python functionality exposed through a unified command-line interface.

The goal is not to reproduce a complete enterprise SIEM. Instead, it demonstrates the underlying mechanics of:

```text
Parse → Search → Detect → Assess → Report
```

---

## Architecture

The toolkit is a single-process Python CLI application.

```text
                         Local Files
                            │
             ┌──────────────┼──────────────┐
             │              │              │
             ▼              ▼              ▼
          Log Data      Sample File     Rule File
             │              │              │
             └──────────────┼──────────────┘
                            ▼
                     ┌─────────────┐
                     │   main.py   │
                     │     CLI     │
                     └──────┬──────┘
                            │
        ┌───────────────────┼────────────────────┐
        │                   │                    │
        ▼                   ▼                    ▼
   IOC Hunting         Log Hunting         File Analysis
        │                   │                    │
        │                   │              ┌─────┴─────┐
        │                   │              │           │
        │                   │            Hash         YARA
        │                   │              │           │
        └───────────────────┼──────────────┴───────────┘
                            │
                            ▼
                    Detection / Analysis
                            │
                            ▼
                       JSON Reports
                            │
                            ▼
                  Static HTML Dashboard
```

`main.py` provides the command-line interface and integrates the individual investigation modules.

The hunter modules can also be imported directly, allowing the test suite to exercise the underlying functions without relying exclusively on CLI execution.

---

## Data Flow

```text
Local Input
    │
    ├── Log
    ├── File
    └── Detection Rule
    │
    ▼
CLI Argument Parsing
    │
    ▼
Investigation Module
    │
    ├── IOC Classification / Matching
    ├── Log Hunting
    ├── Hash Analysis
    ├── Timeline Reconstruction
    ├── Sigma Evaluation
    └── YARA Scanning
    │
    ▼
Detection / Severity Assessment
    │
    ▼
Structured JSON Report
    │
    ▼
Static Dashboard
```

The application does not maintain a persistent daemon or background process. Investigation commands operate on local inputs during each invocation.

---

## Repository Structure

```text
cybernova-threat-hunting-toolkit/
│
├── main.py
├── requirements.txt
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
│
├── hunters/
│   ├── matching.py
│   ├── ioc_search.py
│   ├── hash_analyzer.py
│   ├── log_hunter.py
│   ├── timeline_builder.py
│   ├── sigma_detector.py
│   └── yara_detector.py
│
├── dashboards/
│   ├── __init__.py
│   ├── dashboard_generator.py
│   └── index.html
│
├── rules/
│   ├── sigma/
│   │   ├── .gitkeep
│   │   └── failed_login.yml
│   │
│   └── yara/
│       ├── .gitkeep
│       └── suspicious_sample.yar
│
├── samples/
│   ├── threat_hunting.log
│   └── update.bin
│
├── screenshots/
│   └── threat-hunting-dashboard.png
│
├── reports/
│   ├── examples/
│   └── generated/
│
├── scripts/
│   └── run_demo.sh
│
└── tests/
    ├── conftest.py
    └── test_toolkit.py
```

The bundled sample data, detection rules, and dashboard screenshot are tracked in Git so that the documented examples can be reproduced from a fresh checkout.

Runtime-generated reports under `reports/generated/` are excluded from normal Git tracking.

---

## Requirements

* Python **3.11+**
* `PyYAML`
* `yara-python`
* `pytest`
* `pytest-cov`

The project was developed and tested with **Python 3.13**.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/ibrahim-mukhtar-saidu/cybernova-threat-hunting-toolkit.git
cd cybernova-threat-hunting-toolkit
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install project dependencies:

```bash
pip install -r requirements.txt
```

Install the test tools if required:

```bash
pip install pytest pytest-cov
```

Verify the CLI:

```bash
python main.py --help
```

---

## CLI Usage

The toolkit provides six main commands:

```text
python main.py {ioc,hash,log,timeline,sigma,yara}
```

Display the main help menu:

```bash
python main.py --help
```

Individual command help:

```bash
python main.py ioc --help
python main.py hash --help
python main.py log --help
python main.py timeline --help
python main.py sigma --help
python main.py yara --help
```

---

## Example Commands

### IOC Investigation

Search for an IOC in a specific log file:

```bash
python main.py ioc 45.33.32.156 --log samples/threat_hunting.log
```

The IOC investigation performs classification, matching, severity assessment, and report generation.

---

### File Hash Analysis

Calculate file hashes and perform a static known-bad lookup:

```bash
python main.py hash samples/update.bin
```

The analyzer calculates:

```text
MD5
SHA1
SHA256
```

The resulting hashes are compared against the project's illustrative known-malicious hash dataset.

This dataset is intentionally static and **must not be interpreted as live threat intelligence**.

---

### Log Hunting

Analyze the bundled log:

```bash
python main.py log samples/threat_hunting.log
```

The log hunter can identify:

* multiple failed login attempts;
* successful authentication following repeated failures;
* PowerShell execution;
* suspicious DNS activity;
* file downloads.

---

### Timeline Reconstruction

Reconstruct the event sequence associated with an IOC:

```bash
python main.py timeline samples/threat_hunting.log 45.33.32.156
```

Timeline assessment considers chronological ordering instead of merely checking whether failed and successful authentication events both exist.

---

### Sigma Detection

Apply the bundled Sigma-style rule:

```bash
python main.py sigma \
  samples/threat_hunting.log \
  rules/sigma/failed_login.yml
```

The implementation intentionally supports a limited Sigma subset.

---

### YARA Detection

Scan the sample file using the bundled YARA rule:

```bash
python main.py yara \
  samples/update.bin \
  rules/yara/suspicious_sample.yar
```

---

### Dashboard Generation

Generate the static dashboard:

```bash
python dashboards/dashboard_generator.py
```

The generator reads:

```text
reports/generated/threat_hunting_report.json
```

and produces:

```text
dashboards/index.html
```

---

## Detection Methodology

### IOC Matching

IOC matching is centralized in:

```text
hunters/matching.py
```

The shared implementation performs IOC validation and case-insensitive boundary-aware matching.

For example, an IOC such as:

```text
5.5.5.5
```

should not match inside:

```text
125.5.5.55
```

The matching remains text-based rather than structured-field-aware.

---

### IOC Classification

The IOC classifier identifies common indicator types including:

* IPv4;
* IPv6;
* MD5;
* SHA1;
* SHA256;
* domains;
* file-like indicators;
* other indicators.

Domain classification is heuristic. It does not perform DNS resolution or public-suffix validation.

---

### Log Hunting

The bundled synthetic log format contains fields such as:

```text
TIMESTAMP
SRC
DST
USER
ACTION
FILE
```

Example:

```text
2026-08-07 10:01:15 SRC=192.168.1.5 DST=45.33.32.156 USER=admin ACTION=FAILED_LOGIN FILE=ssh.log
```

The log hunter applies deterministic detection rules to this format.

A key authentication detection is:

```text
3+ failed logins
       +
later successful login
       ↓
CRITICAL authentication anomaly
```

The resulting finding uses evidence from the actual event rather than fabricated user or file values.

---

### Timeline Analysis

Timeline reconstruction evaluates events associated with an IOC in chronological order.

The implementation checks whether a successful login occurs after at least three prior failed login events.

This prevents a simple presence-based check from incorrectly treating an unrelated success and earlier/later failures as the same authentication sequence.

---

### Sigma Detection

The Sigma detector supports a deliberately limited subset of Sigma semantics.

Example:

```yaml
title: Multiple Failed Login Attempts

detection:
  selection:
    ACTION: FAILED_LOGIN
  condition: selection
```

Supported:

* one `selection`;
* exact field-value equality;
* implicit AND semantics;
* `condition: selection`.

Unsupported functionality includes:

* multiple named selections;
* complex boolean expressions;
* `contains`;
* `startswith`;
* wildcard semantics;
* list-based matching;
* `1 of`;
* `all of`;
* advanced Sigma modifiers.

Unsupported condition values are rejected rather than silently approximated.

---

### YARA Detection

YARA scanning is provided through `yara-python`.

The Python wrapper performs:

```text
Rule validation
      ↓
YARA compilation
      ↓
File scanning
      ↓
Match reporting
```

The actual detection conditions are defined in the supplied `.yar` rule.

---

## Security Design

Security considerations were incorporated into the implementation and verification process.

### YAML Safety

Sigma rules are loaded with:

```python
yaml.safe_load()
```

to avoid unsafe YAML object deserialization.

### HTML Escaping

File-derived report content is HTML-escaped before being inserted into the generated dashboard:

```python
html.escape()
```

### Terminal Output Sanitization

Potential terminal control characters are removed from log content before console output.

This reduces the risk of attacker-controlled log content manipulating the analyst's terminal display.

### No Shell Execution

The toolkit does not execute file or log content through:

```text
eval()
exec()
subprocess
shell commands
```

### No Network Services

The toolkit does not expose a network listener or communicate with external threat-intelligence services.

---

## Threat Model

The toolkit assumes a trusted analyst operating locally against files they are authorized to analyze.

Input files may contain adversary-influenced content, including:

* attacker-generated log entries;
* suspicious filenames;
* malicious sample files;
* hostile strings intended to appear in reports or console output.

The application treats these inputs as data rather than executable instructions.

However, the project is **not intended to be an internet-facing malware-analysis service or anonymous file-upload scanner**.

It currently does not provide comprehensive:

* sandbox isolation;
* processing timeouts;
* resource quotas;
* multi-tenant protections.

---

## Configuration

The toolkit does not use a central configuration file.

Important detection data is currently defined in source code.

### Known-Malicious Hashes

`hunters/hash_analyzer.py` contains a small illustrative known-bad hash dictionary.

It is not a live threat-intelligence source.

### Suspicious Domains

`hunters/log_hunter.py` contains a small static set of example suspicious domains.

These values are intended for demonstration and controlled testing.

---

## Testing

The project contains a comprehensive automated test suite in:

```text
tests/test_toolkit.py
```

Run all tests:

```bash
python -m pytest -q
```

Run tests with coverage:

```bash
python -m pytest -q \
  --cov=. \
  --cov-report=term-missing \
  --cov-report=html
```

### Current Verification

```text
177 passed
99% total coverage
```

Coverage currently reports approximately:

```text
1,393 statements
13 missed
99% total coverage
```

The suite covers:

* IOC classification;
* IOC validation;
* IOC boundary matching;
* invalid IOC input;
* hash calculation;
* known-bad hash lookup;
* log parsing;
* authentication anomaly detection;
* temporal ordering;
* timeline reconstruction;
* Sigma matching;
* invalid Sigma rules;
* empty Sigma selections;
* YARA compilation;
* YARA scanning;
* invalid YARA rules;
* dashboard generation;
* malformed reports;
* CLI behavior;
* terminal-output sanitization;
* filesystem error handling;
* adversarial input scenarios.

Tests use controlled temporary filesystem locations where appropriate.

---

## Code Quality and Security Verification

The project has undergone multiple verification stages as part of the refactoring and final adversarial-audit workflow.

### Pytest

```text
177 passed
```

### Coverage

```text
99%
```

### Ruff

Static analysis was completed and identified findings were remediated.

### Bandit

Final security scan:

```text
HIGH:   0
MEDIUM: 0
```

The remaining low-severity results were expected test assertions rather than unresolved production security vulnerabilities.

### MyPy

Final result:

```text
Success: no issues found in 13 source files
```

### pip-audit

Final dependency audit:

```text
No known vulnerabilities found
```

These results represent the verified state of the project during the current development cycle. They are not a permanent guarantee against future vulnerabilities or dependency changes.

---

## Sample Data

The repository contains controlled demonstration data:

```text
samples/threat_hunting.log
samples/update.bin
```

These assets are intended for local testing and demonstrations.

Example detection rules are provided in:

```text
rules/sigma/failed_login.yml
rules/yara/suspicious_sample.yar
```

The sample data and rules are tracked in Git to support reproducible demonstrations.

---

## Dashboard

The project includes a static HTML dashboard for visualizing the log-hunting report.

```text
Log Hunting
     ↓
JSON Report
     ↓
Dashboard Generator
     ↓
dashboards/index.html
```

A dashboard screenshot is included at:

```text
screenshots/threat-hunting-dashboard.png
```

The dashboard is intentionally lightweight and static.

It does not provide:

* real-time monitoring;
* alert streaming;
* user authentication;
* SIEM ingestion;
* persistent event storage.

---

## Reports

Investigation results are written as JSON under:

```text
reports/generated/
```

Example report outputs are maintained separately under:

```text
reports/examples/
```

Generated reports are runtime artifacts and are excluded from normal Git tracking.

---

## Limitations

This project intentionally has a focused scope.

### Bespoke Log Format

The log-hunting functionality is designed around the project's synthetic:

```text
TIMESTAMP SRC=... DST=... USER=... ACTION=... FILE=...
```

format.

It does not currently provide native parsers for:

* Windows Event Logs;
* Sysmon;
* Linux syslog;
* CEF;
* JSON telemetry;
* other enterprise telemetry formats.

### Simplified Sigma Support

The Sigma detector implements only a small subset of Sigma semantics.

It should not be considered a complete Sigma engine.

### Static Threat Intelligence

The known-malicious hash database is a small hardcoded demonstration dataset.

There is currently no:

* VirusTotal integration;
* MISP integration;
* OpenCTI integration;
* commercial threat-intelligence feed;
* automatic IOC update mechanism.

### Static Suspicious-Domain Data

Suspicious-domain detection relies on a small hardcoded example set.

### Dashboard Scope

The dashboard currently focuses on the log-hunting report rather than aggregating every investigation report type.

### Resource Controls

The application is intended for local analyst use and does not currently provide comprehensive resource quotas, processing timeouts, or sandbox isolation for hostile large-scale inputs.

### Synchronous Processing

Each command processes its input synchronously.

There is currently no:

* live log tailing;
* distributed processing;
* multi-file worker pool;
* persistent event pipeline.

### IOC Classification

IOC/domain classification is heuristic rather than authoritative external validation.

### Detection Complexity

The detection mechanisms demonstrate core threat-hunting and detection concepts but are not equivalent to enterprise-grade SIEM, EDR, or detection-engineering platforms.

---

## Future Engineering Directions

Potential future improvements include:

* extracting a shared normalized event parser;
* supporting additional real-world log formats;
* expanding Sigma condition support;
* adding configurable IOC and hash datasets;
* integrating external threat-intelligence sources;
* aggregating all investigation reports in the dashboard;
* adding structured logging;
* introducing configurable resource controls;
* supporting batch analysis;
* adding more detection rules and investigation scenarios;
* expanding CI coverage across supported Python versions.

These are future engineering directions and are **not current capabilities**.

---

## Responsible Use

This toolkit is intended for:

* cybersecurity education;
* SOC analyst practice;
* threat-hunting demonstrations;
* defensive security research;
* controlled laboratory environments;
* analysis of files and logs the operator is authorized to inspect.

Do not use this project to analyze systems, files, or data without appropriate authorization.

---

## Project Status

**Status: Functional educational threat-hunting toolkit**

The current implementation provides a complete local investigation workflow:

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
YARA Scanning
       ↓
JSON Reporting
       ↓
Static Dashboard
```

The project has undergone:

* automated testing;
* coverage analysis;
* static code analysis;
* security scanning;
* dependency auditing;
* type checking;
* adversarial testing;
* final security-focused review.

### Current Verification

```text
Tests:          177 passed
Coverage:       99%
Bandit HIGH:    0
Bandit MEDIUM:  0
MyPy:           Clean
pip-audit:      No known vulnerabilities
```

---

## Author

**Ibrahim Mukhtar Saidu**

Cybersecurity Analyst & Security Researcher
Founder & Cybersecurity Project Developer at **CYBERNOVA AI**

### GitHub

**Profile:**
https://github.com/ibrahim-mukhtar-saidu

**Project Repository:**
https://github.com/ibrahim-mukhtar-saidu/cybernova-threat-hunting-toolkit

---

## License

This project is distributed under the license included in the repository.

See:

```text
LICENSE
```

for the complete license terms.

---

## CYBERNOVA AI

**CYBERNOVA AI — Defensive Security • Threat Hunting • Security Research**

Built by **Ibrahim Mukhtar Saidu**.
