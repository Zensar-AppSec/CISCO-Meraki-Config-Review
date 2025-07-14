import json
import os
from datetime import datetime

CONFIG_DIR = "./"

BENCHMARKS = {
    "admins_Org.json": {
        "endpoint": "/organizations/<orgId>/admins",
        "checks": lambda data: [
            ("✅ Admin '{}' has role '{}'".format(a.get('name', 'unknown'), a.get('role')), "")
            if isinstance(a, dict) and a.get('role') in ['read-only', 'network admin'] else
            ("❌ Admin '{}' has excessive privileges (role: '{}')".format(a.get('name', 'unknown'), a.get('role')),
             "Restrict privileges as per least privilege principle.")
            for a in data if isinstance(a, dict)
        ]
    },
    "alerts_<location>Firewall.json": {
        "endpoint": "/networks/<networkId>/alerts/settings",
        "checks": lambda data: [
            ("✅ Alert '{}' is enabled.".format(alert.get('alertType', 'unknown')), "")
            if isinstance(alert, dict) and alert.get('enabled') else
            ("❌ Alert '{}' is disabled.".format(alert.get('alertType', 'unknown')), "Enable this alert.")
            for alert in data.get("alerts", []) if isinstance(alert, dict)
        ]
    },
    "content_filtering_<location>.json": {
        "endpoint": "/networks/<networkId>/contentFiltering",
        "checks": lambda data: [
            ("✅ Malware category is blocked.", "")
            if "Malware" in data.get("blockedUrlCategories", []) else
            ("❌ Malware category not blocked.", "Enable content filtering for Malware.")
        ]
    },
    "devices_<location>.json": {
        "endpoint": "/networks/<networkId>/devices",
        "checks": lambda data: [
            ("✅ Device '{}' has a name.".format(dev.get('serial', 'unknown')), "")
            if isinstance(dev, dict) and dev.get('name') else
            ("❌ Device '{}' has no name.".format(dev.get('serial', 'unknown')), "Assign device name.")
            for dev in data if isinstance(dev, dict)
        ]
    },
    "firewall_<location>.json": {
        "endpoint": "/networks/<networkId>/appliance/firewall/l3FirewallRules",
        "checks": lambda data: [
            ("❌ Insecure Allow All rule: '{}'".format(rule.get('comment', '')), "Avoid allow any-any.")
            if rule.get("policy") == "allow" and rule.get("srcCidr") == "any" and rule.get("destCidr") == "any"
            else ("✅ Rule '{}' is restricted.".format(rule.get("comment", "")), "")
            for rule in data if isinstance(rule, dict)
        ]
    },
    "intrusion_settings_<location>.json": {
        "endpoint": "/networks/<networkId>/appliance/security/intrusionSettings",
        "checks": lambda data: [
            ("✅ IDS/IPS is enabled in '{}' mode.".format(data.get("mode", "unknown")), "")
            if data.get("mode") == "prevention" else
            ("❌ IDS/IPS is not in prevention mode.", "Set mode to 'prevention'.")
        ]
    },
    "l7_firewall_<location>.json": {
        "endpoint": "/networks/<networkId>/appliance/firewall/l7FirewallRules",
        "checks": lambda data: [
            ("✅ L7 Rule blocks category: '{}'".format(rule.get('category', 'unknown')), "")
            if rule.get('policy') == 'deny' else
            ("❌ L7 Rule allows category: '{}'".format(rule.get('category', 'unknown')), "Set rule to deny.")
            for rule in data if isinstance(rule, dict)
        ]
    },
    "ssids_<location>.json": {
        "endpoint": "/networks/<networkId>/wireless/ssids",
        "checks": lambda data: [
            ("✅ SSID '{}' uses authentication.".format(ssid.get('name', 'unknown')), "")
            if ssid.get("authMode") != "open" else
            ("❌ SSID '{}' is open.".format(ssid.get('name', 'unknown')), "Use WPA2/WPA3.")
            for ssid in data if isinstance(ssid, dict)
        ]
    },
    "switchports_<device_id>.json": {
        "endpoint": "/devices/<serial>/switchPorts",
        "checks": lambda data: [
            ("✅ Port {} is access mode.".format(port.get('portId', 'unknown')), "")
            if port.get("type") == "access" else
            ("❌ Port {} is trunk.".format(port.get('portId', 'unknown')), "Set to access if not required.")
            for port in data if isinstance(port, dict)
        ]
    },
    "vlan_settings_<location>Firewall.json": {
        "endpoint": "/networks/<networkId>/appliance/vlans/settings",
        "checks": lambda data: [
            ("✅ VLANs enabled: {}.".format(data.get("vlansEnabled", False)), "")
        ]
    },
    "vlans_<location>Firewall.json": {
        "endpoint": "/networks/<networkId>/vlans",
        "checks": lambda data: [
            ("✅ VLAN '{}' has subnet.".format(v.get('name', 'unknown')), "")
            if v.get("subnet") else
            ("❌ VLAN '{}' missing subnet.".format(v.get('name', 'unknown')), "Define subnet.")
            for v in data if isinstance(v, dict)
        ]
    },
    "vpn_<location>.json": {
        "endpoint": "/networks/<networkId>/siteToSiteVpn",
        "checks": lambda data: [
            ("✅ VPN mode is '{}'".format(data.get("mode", "unknown")), "")
            if data.get("mode") == "hub" else
            ("❌ VPN mode is '{}'".format(data.get("mode", "unknown")), "Use 'hub' mode for central routing.")
        ]
    }
}

def audit_json_folder(config_dir):
    findings = []
    total_pass, total_fail = 0, 0
    evidence_blocks = []

    for filename, benchmark in BENCHMARKS.items():
        filepath = os.path.join(config_dir, filename)
        if not os.path.exists(filepath):
            continue

        with open(filepath) as f:
            data = json.load(f)

        result = benchmark["checks"](data)
        section_pass = sum(1 for x in result if x[0].startswith("✅"))
        section_fail = sum(1 for x in result if x[0].startswith("❌"))
        total_pass += section_pass
        total_fail += section_fail
        findings.append((filename, result, section_pass, section_fail, benchmark["endpoint"]))
        evidence_blocks.append((filename, data, benchmark["endpoint"]))

    return findings, total_pass, total_fail, evidence_blocks

def generate_json_audit_html(findings, total_pass, total_fail, evidence_blocks):
    now = datetime.now()
    scan_date = now.strftime("%B %d, %Y at %H:%M:%S")
    score_pct = round((total_pass / (total_pass + total_fail)) * 100) if total_pass + total_fail > 0 else 0
    timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"./meraki_json_audit_{timestamp}.html"

    html = f"""
    <html>
    <head>
        <title>FP: Meraki Configuration Audit</title>
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
            h2 {{
                color: #34495e;
                margin-top: 30px;
            }}
            h3 {{
                color: #2c3e50;
                margin-top: 25px;
            }}
            ul {{
                list-style-type: none;
                padding-left: 0;
            }}
            li {{
                padding: 8px 12px;
                margin: 6px 0;
                border-radius: 6px;
                font-size: 15px;
            }}
            li[style*='green'] {{
                background-color: #e6f9ef;
                color: #1e7e34;
                border-left: 5px solid #28a745;
            }}
            li[style*='red'] {{
                background-color: #fcebea;
                color: #c0392b;
                border-left: 5px solid #e74c3c;
            }}
            li[style*='gray'] {{
                background-color: #f2f2f2;
                color: #7f8c8d;
                border-left: 5px solid #bdc3c7;
            }}
            code, pre {{
                background-color: #fafafa;
                padding: 10px;
                border: 1px solid #e1e1e8;
                border-radius: 6px;
                display: block;
                overflow-x: auto;
                font-size: 13px;
                white-space: pre-wrap;
            }}
            summary {{
                font-weight: bold;
                font-size: 16px;
                margin: 10px 0;
                cursor: pointer;
            }}
            details {{
                margin-bottom: 20px;
            }}
            .score {{
                background: linear-gradient(to right, #1d976c, #93f9b9);
                color: white;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                box-shadow: 0 4px 10px rgba(0,0,0,0.1);
            }}
            .header-bar {{
                background: #2980b9;
                color: white;
                padding: 12px 20px;
                border-radius: 8px;
                margin-bottom: 30px;
                box-shadow: 0 2px 6px rgba(0,0,0,0.1);
            }}
        </style>
    </head>
    <body>
        <div class="header-bar">
            <h1>📊 FP: Network Configuration Review</h1>
            <p><strong>🕒 Scan Date:</strong> {scan_date}</p>
        </div>

        <div class="score">
            <h2>✅ Overall Score: {total_pass}/{total_pass + total_fail} ({score_pct}%)</h2>
        </div>
    """

    for section, results, sec_pass, sec_fail, endpoint in findings:
        html += f"<h3>📁 {section} <span class='status'>API: {endpoint}</span></h3>"
        html += f"<p><strong>✅ Passed:</strong> {sec_pass} | <strong>❌ Failed:</strong> {sec_fail}</p><ul>"
        for msg, reco in results:
            color = "green" if msg.startswith("✅") else "red" if msg.startswith("❌") else "gray"
            html += f"<li style='color:{color}'>{msg}"
            if reco:
                html += f"<ul><li><strong>👉 Recommendation:</strong> {reco}</li></ul>"
            html += "</li>"
        html += "</ul>"

    html += "<h2>📄 Evidence (Raw JSON):</h2>"
    for section, data, endpoint in evidence_blocks:
        masked = endpoint.replace(endpoint.split('/')[2], "<masked>")
        html += f"<details><summary><strong>{section}</strong> (API: {masked})</summary><pre>{json.dumps(data, indent=2)}</pre></details>"

    html += "<footer style='margin-top: 40px; text-align: center; color: #7f8c8d; font-size: 14px;'>CISCO Meraki Config Review Tool - Developed by Zensar's AppSec Team. Contact us @ AppSec[at]zensar[dot]com. </footer>"
    html += "</body></html>"

    with open(filename, "w") as f:
        f.write(html)

    print(f"✅ Report saved as: {filename}")

if __name__ == "__main__":
    findings, total_pass, total_fail, evidence_blocks = audit_json_folder(CONFIG_DIR)
    generate_json_audit_html(findings, total_pass, total_fail, evidence_blocks)

