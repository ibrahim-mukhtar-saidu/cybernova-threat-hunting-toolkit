import html
import json
from pathlib import Path


REPORT_FILE = Path("reports/generated/threat_hunting_report.json")
OUTPUT_FILE = Path("dashboards/index.html")


def generate_dashboard():
    if not REPORT_FILE.exists():
        raise FileNotFoundError(
            f"Threat hunting report not found: {REPORT_FILE}"
        )

    with REPORT_FILE.open("r", encoding="utf-8") as file:
        report = json.load(file)

    findings = report.get("findings", [])
    summary = report.get("summary", {})

    finding_rows = ""

    for finding in findings:
        severity = html.escape(str(finding.get("severity", "UNKNOWN")))
        finding_type = html.escape(str(finding.get("type", "UNKNOWN")))
        timestamp = html.escape(str(finding.get("timestamp", "UNKNOWN")))
        user = html.escape(str(finding.get("user", "UNKNOWN")))
        destination = html.escape(
            str(finding.get("destination", "UNKNOWN"))
        )
        file_name = html.escape(str(finding.get("file", "UNKNOWN")))
        description = html.escape(
            str(finding.get("description", "No description available."))
        )

        finding_rows += f"""
        <tr>
            <td>
                <span class="severity {severity.lower()}">
                    {severity}
                </span>
            </td>
            <td>{finding_type}</td>
            <td>{timestamp}</td>
            <td>{user}</td>
            <td>{destination}</td>
            <td>{file_name}</td>
            <td>{description}</td>
        </tr>
        """

    if not finding_rows:
        finding_rows = """
        <tr>
            <td colspan="7" class="no-findings">
                No suspicious activity detected.
            </td>
        </tr>
        """

    total_findings = summary.get("total_findings", len(findings))
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)

    generated_at = html.escape(
        str(report.get("generated_at", "Unknown"))
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>CYBERNOVA AI Threat Hunting Dashboard</title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 30px;
            background: #0b0f14;
            color: #e6edf3;
            font-family: Arial, Helvetica, sans-serif;
        }}

        .container {{
            max-width: 1500px;
            margin: 0 auto;
        }}

        header {{
            margin-bottom: 30px;
        }}

        h1 {{
            margin-bottom: 8px;
            color: #58a6ff;
        }}

        .subtitle {{
            color: #8b949e;
            margin: 0;
        }}

        .report-time {{
            margin-top: 10px;
            color: #8b949e;
            font-size: 14px;
        }}

        .cards {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 16px;
            margin-bottom: 30px;
        }}

        .card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}

        .card h2 {{
            margin: 0 0 10px;
            font-size: 15px;
            color: #8b949e;
            text-transform: uppercase;
        }}

        .card .number {{
            font-size: 32px;
            font-weight: bold;
        }}

        .total {{
            border-top: 3px solid #58a6ff;
        }}

        .critical {{
            border-top: 3px solid #f85149;
        }}

        .high {{
            border-top: 3px solid #ff7b72;
        }}

        .medium {{
            border-top: 3px solid #d29922;
        }}

        .low {{
            border-top: 3px solid #3fb950;
        }}

        .table-container {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            min-width: 1100px;
        }}

        th,
        td {{
            border-bottom: 1px solid #30363d;
            padding: 14px;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background: #21262d;
            color: #c9d1d9;
            font-size: 13px;
            text-transform: uppercase;
        }}

        td {{
            color: #c9d1d9;
            font-size: 14px;
        }}

        tr:hover {{
            background: #1c2128;
        }}

        .severity {{
            display: inline-block;
            padding: 5px 9px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: bold;
        }}

        .severity.critical {{
            background: #490202;
            color: #ff7b72;
        }}

        .severity.high {{
            background: #3d1e00;
            color: #ffa657;
        }}

        .severity.medium {{
            background: #3b2b00;
            color: #d29922;
        }}

        .severity.low {{
            background: #0d2f17;
            color: #3fb950;
        }}

        .no-findings {{
            text-align: center;
            padding: 40px;
            color: #8b949e;
        }}

        footer {{
            margin-top: 25px;
            color: #6e7681;
            font-size: 13px;
            text-align: center;
        }}

        @media (max-width: 900px) {{
            body {{
                padding: 15px;
            }}

            .cards {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}

        @media (max-width: 500px) {{
            .cards {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>

<body>
    <div class="container">

        <header>
            <h1>CYBERNOVA AI Threat Hunting Dashboard</h1>
            <p class="subtitle">
                Security Operations Center Investigation Overview
            </p>
            <p class="report-time">
                Report generated: {generated_at}
            </p>
        </header>

        <section class="cards">

            <div class="card total">
                <h2>Total Findings</h2>
                <div class="number">{total_findings}</div>
            </div>

            <div class="card critical">
                <h2>Critical</h2>
                <div class="number">{critical}</div>
            </div>

            <div class="card high">
                <h2>High</h2>
                <div class="number">{high}</div>
            </div>

            <div class="card medium">
                <h2>Medium</h2>
                <div class="number">{medium}</div>
            </div>

            <div class="card low">
                <h2>Low</h2>
                <div class="number">{low}</div>
            </div>

        </section>

        <section class="table-container">
            <table>

                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Timestamp</th>
                        <th>User</th>
                        <th>Destination</th>
                        <th>File</th>
                        <th>Description</th>
                    </tr>
                </thead>

                <tbody>
                    {finding_rows}
                </tbody>

            </table>
        </section>

        <footer>
            CYBERNOVA AI &mdash; Threat Hunting Toolkit
        </footer>

    </div>
</body>
</html>
"""

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        file.write(html_content)

    print("Dashboard created:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    generate_dashboard()
