Security Log Analyzer (Python)

A simple Python script that analyzes Linux authentication logs to identify suspicious security activities such as brute force attacks and privilege escalation attempts.
This project was built as a practical SOC Analyst exercise focusing on log analysis and detection logic rather than heavy tooling.

Features

- Parse Linux authentication logs (`auth.log`)
- Detect failed SSH login attempts
- Identify brute force attacks based on repeated failures per IP
- Detect successful SSH logins
- Detect privilege escalation events (su to root)
- Generate a simple HTML report automaticall

Log Source

- Real authentication logs were used
- Log entries were replayed to exceed 10,000 lines for performance testing

How to Run

-python3 security_log_analyzer.py

Notes

-The environment used systemd logging (journalctl).  
-Authentication-related events were extracted and saved as a snapshot into a text file (`big_auth.log`) for offline analysis and testing.
-This approach simulates real-world scenarios where logs are exported from centralized logging systems or SIEM platforms.
