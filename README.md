# Threat Intelligence Dashboard
# ThreatModeling – Live Threat Intelligence Dashboard

This project is a real-time threat intelligence dashboard built using Python, with guidance from AI to accelerate development and design decisions. It ingests live Indicators of Compromise (IOCs) from the AlienVault OTX API and parses them into a structured format using `pandas`. These indicators include malicious IP addresses, domains, and file hashes, often enriched with metadata such as ports, protocols, and descriptions from honeypot logs.

The goal of this project is to evolve into a lightweight, modular threat detection platform for both learning and practical use. In its current form, it serves as a clean proof of concept that demonstrates threat feed ingestion, IOC parsing, and security context extraction — all of which are foundational skills for a cybersecurity analyst or SOC role.

This dashboard is part of a larger effort to simulate and monitor real-world cyber threats in a home lab environment. Future enhancements include visualizing data in a Streamlit dashboard, mapping indicators to MITRE ATT&CK techniques, and correlating incoming IOCs with internal network activity captured from tools like Suricata, pfSense, or Pi-hole.

By integrating live threat data with local monitoring, this project aims to provide practical, hands-on exposure to cyber defense workflows such as detection engineering, threat hunting, and alerting — all driven by live, evolving adversary data.

