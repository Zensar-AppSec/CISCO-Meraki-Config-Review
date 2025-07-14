import json
from pathlib import Path
from datetime import datetime

# Define paths to local JSON files
data_files = {
    "admins": "",
    "alerts": "",
    "content_filtering": "",
    "devices": "",
    "firewall": "",
    "ssids": "",
    "vpn": ""
}

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

# --- CHECK FUNCTIONS WITH EVIDENCE ---

def check_password_policy():
    return "⚠️ Not visible", "Password policy not defined in config files.", "No relevant fields in admins_Org.json or ssids_London.json"

def check_timeout_length():
    return "⚠️ Not visible", "Idle timeout settings not present.", "Session management fields not found."

def check_sso(admins):
    methods = [a['authenticationMethod'] for a in admins]
    evidence = "<br>".join(f"{a['name']}: {a['authenticationMethod']}" for a in admins)
    if all(m == "Email" for m in methods):
        return "❌ Not configured", "No SSO found.", evidence
    return "✅ Configured", "Some admins use SSO.", evidence

def check_2fa(admins):
    enabled = [a for a in admins if a['twoFactorAuthEnabled']]
    total = len(admins)
    evidence = "<br>".join(f"{a['name']}: 2FA {'✅' if a['twoFactorAuthEnabled'] else '❌'}" for a in admins)
    if len(enabled) == total:
        return "✅ Enforced", "All admins have 2FA.", evidence
    elif len(enabled) > 0:
        return "⚠️ Partial", f"{len(enabled)}/{total} have 2FA.", evidence
    return "❌ Not Enabled", "No 2FA configured.", evidence

def check_amp(alerts):
    types = [a for a in alerts if a["type"].startswith("amp")]
    enabled_types = [a["type"] for a in types if a["enabled"]]
    evidence = "<br>".join(enabled_types) if enabled_types else "None enabled"
    if enabled_types:
        return "✅ Enabled", "AMP malware alerts active.", evidence
    return "❌ Disabled", "AMP is not active.", evidence

def check_ids_ips():
    return "❌ Not configured", "intrusion_settings file is empty or missing.", "No IDS/IPS config data present."

def check_firmware(devices):
    versions = [f"{d['name']} ({d['model']}): {d['firmware']}" for d in devices]
    evidence = "<br>".join(versions)
    return "⚠️ Review", "Firmware info available, check if it's latest.", evidence

def check_syslog(firewall):
    matches = [r for r in firewall['rules'] if r.get('syslogEnabled') and r.get('destPort') == '514']
    if matches:
        rule = matches[0]
        evidence = f"Rule: {rule['comment']} → {rule['destCidr']}:{rule['destPort']}"
        return "✅ Yes", "Syslog forwarding is configured.", evidence
    return "❌ Not found", "No syslog forwarding rule found.", "No firewall rule forwarding syslog."

def check_web_filtering(cf):
    if not cf["blockedUrlCategories"] and not cf["blockedUrlPatterns"]:
        evidence = f"Allowed URLs: {', '.join(cf['allowedUrlPatterns'])}"
        return "⚠️ Not enforced", "Web filtering not actively blocking.", evidence
    return "✅ Active", "Web filtering configured.", str(cf)

def check_firewall_rule_owners(firewall):
    comments = [r['comment'] for r in firewall['rules'] if r.get('comment')]
    evidence = "<br>".join(comments) if comments else "No comments found"
    if comments:
        return "⚠️ Partial", f"{len(comments)} rules have comments, ownership unclear.", evidence
    return "❌ None", "Firewall rules lack comments/owners.", evidence

# --- HTML Report Builder ---

def render_html_table(rows):
    scan_time = datetime.now().strftime("%B %d, %Y at %H:%M:%S")
    html = f"""
    <html><head>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 40px;
            background: #f0f2f5;
            color: #333;
            line-height: 1.6;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #ccc;
            padding-bottom: 10px;
        }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        h3 {{ color: #2c3e50; margin-top: 25px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        th, td {{ border: 1px solid #ddd; padding: 10px; vertical-align: top; }}
        th {{ background: #34495e; color: white; }}
        .ok {{ background-color: #e6f9ef; color: #1e7e34; }}
        .warn {{ background-color: #fff3cd; color: #856404; }}
        .fail {{ background-color: #fcebea; color: #c0392b; }}
        .header-bar {{
            background: #2980b9;
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.1);
        }}
    </style>
    </head><body>
        <div class='header-bar'>
            <h1>📊 Additional Findings Meraki JSON Audit</h1>
            <p><strong>🕒 Scan Date:</strong> {scan_time}</p>
        </div>
        <table>
            <tr><th>Benchmark</th><th>Status</th><th>Observation</th><th>Evidence</th></tr>
    """
    for item, status, note, evidence in rows:
        css_class = "ok" if "✅" in status else "warn" if "⚠️" in status else "fail"
        html += f"<tr class='{css_class}'><td>{item}</td><td>{status}</td><td>{note}</td><td>{evidence}</td></tr>"
    html += f"""
    </table>
    <footer style=\"margin-top: 40px; text-align: center; color: #7f8c8d; font-size: 14px;\">
        <p><em>CISCO Meraki Config Review Tool - Developed by Zensar's AppSec Team. Contact us AppSec[at]zensar[dot]com</em></p>
    </footer>
</body></html>"""
    return html

# --- Main Execution ---

def main():
    # Load data
    admins = load_json(data_files["admins"])
    alerts = load_json(data_files["alerts"])['alerts']
    content_filtering = load_json(data_files["content_filtering"])
    devices = load_json(data_files["devices"])
    firewall = load_json(data_files["firewall"])

    # Checks
    rows = [
        ("Password Policy", *check_password_policy()),
        ("Timeout Length", *check_timeout_length()),
        ("SSO Configured", *check_sso(admins)),
        ("2FA Enabled", *check_2fa(admins)),
        ("AMP Enabled", *check_amp(alerts)),
        ("IDS/IPS Enabled", *check_ids_ips()),
        ("Firmware Updates", *check_firmware(devices)),
        ("Syslog Forwarding", *check_syslog(firewall)),
        ("Web Filtering", *check_web_filtering(content_filtering)),
        ("Firewall Rule Ownership", *check_firewall_rule_owners(firewall)),
    ]

    html = render_html_table(rows)
    out_path = "config_review_with_evidence.html"
    with open(out_path, "w") as f:
        f.write(html)
    print(f"[\u2713] HTML report generated: {out_path}")

if __name__ == "__main__":
    main()

