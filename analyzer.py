import re
from collections import defaultdict
import webbrowser
import os


log_file = "big_auth.log"

failed_ssh_re = re.compile(
    r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE
)

success_ssh_re = re.compile(
    r"Accepted (password|publickey) for .* from (\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE
)

su_root_re = re.compile(
    r"session opened for user root by",
    re.IGNORECASE
)


failed_ssh_count = 0
success_ssh_count = 0
su_root_count = 0
ip_attempts = defaultdict(int)

with open(log_file, "r", errors="ignore") as f:
    for line in f:

        failed_match = failed_ssh_re.search(line)
        if failed_match:
            failed_ssh_count += 1
            ip = failed_match.group(1)
            ip_attempts[ip] += 1
            continue

        if success_ssh_re.search(line):
            success_ssh_count += 1
            continue

        if su_root_re.search(line):
            su_root_count += 1


bruteforce_ips = {
    ip: count for ip, count in ip_attempts.items() if count > 5
}


print("\nSecurity Log Analyzer\n")

print(f"Failed SSH attempts: {failed_ssh_count}")
print(f"Successful SSH logins: {success_ssh_count}")
print(f"su to root events: {su_root_count}")

print("\nPossible brute force sources:")
if bruteforce_ips:
    for ip, count in bruteforce_ips.items():
        print(f"{ip} -> {count} attempts")
else:
    print("No brute force activity detected")

print()
html = f"""
<html>
<head>
    <title>Security Log Analyzer Report</title>
    <style>
        body {{ font-family: Arial; margin: 40px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 50%; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>

<h1>Security Log Analyzer Report</h1>

<h2>Summary</h2>
<ul>
    <li>Failed SSH attempts: {failed_ssh_count}</li>
    <li>Successful SSH logins: {success_ssh_count}</li>
    <li>su to root events: {su_root_count}</li>
</ul>

<h2>Brute Force Detection</h2>
<table>
<tr>
    <th>IP Address</th>
    <th>Failed Attempts</th>
</tr>
"""

for ip, count in bruteforce_ips.items():
    html += f"<tr><td>{ip}</td><td>{count}</td></tr>"

html += """
</table>

</body>
</html>
"""


with open("report.html", "w") as f:
    f.write(html)

report_path = os.path.abspath("report.html")
webbrowser.open(f"file://{report_path}")
