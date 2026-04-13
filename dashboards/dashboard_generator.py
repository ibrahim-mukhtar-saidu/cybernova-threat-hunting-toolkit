import json
from pathlib import Path

REPORT_FILE = "reports/threat_hunting_report.json"
OUTPUT_FILE = "dashboards/index.html"

def generate_dashboard():
    with open(REPORT_FILE, "r", encoding="utf-8") as f:
        report = json.load(f)

    findings = report["findings"]
    summary = report["summary"]

    finding_rows = ""

    for finding in findings:
        finding_rows += f"""
        <tr>
            <td>{finding['severity']}</td>
            <td>{finding['type']}</td>
            <td>{finding['user']}</td>
            <td>{finding['destination']}</td>
            <td>{finding['file']}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>CyberNova Threat Hunting Dashboard</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #111;
            color: white;
            padding: 30px;
        }}

        h1 {{
            text-align: center;
        }}

        .cards {{
            display: flex;
            gap: 20px;
            margin-bottom: 30px;
        }}

        .card {{
            background: #222;
            padding: 20px;
            border-radius: 10px;
            width: 180px;
            text-align: center;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
            border: 1px solid #555;
            padding: 12px;
            text-align: left;
        }}

        th {{
            background: #333;
        }}
    </style>
</head>
<body>

<h1>CyberNova Threat Hunting Dashboard</h1>

<div class="cards">
    <div class="card">
        <h2>Total Findings</h2>
        <h1>{summary['total_findings']}</h1>
    </div>

    <div class="card">
        <h2>Critical</h2>
        <h1>{summary['critical']}</h1>
    </div>

    <div class="card">
        <h2>High</h2>
        <h1>{summary['high']}</h1>
    </div>

    <div class="card">
        <h2>Medium</h2>
        <h1>{summary['medium']}</h1>
    </div>

    <div class="card">
        <h2>Low</h2>
        <h1>{summary['low']}</h1>
    </div>
</div>

<h2>Threat Hunting Findings</h2>

<table>
    <tr>
        <th>Severity</th>
        <th>Type</th>
        <th>User</th>
        <th>Destination</th>
        <th>File</th>
    </tr>

    {finding_rows}

</table>

</body>
</html>
"""

    Path("dashboards").mkdir(exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    print("Dashboard created:")
    print(OUTPUT_FILE)

if __name__ == "__main__":
    generate_dashboard()
