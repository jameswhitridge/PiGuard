# PiGuard

PiGuard is an always-on Raspberry Pi home network security monitoring system built with Python, Nmap, SQLite, Flask, JavaScript, and Linux systemd.

PiGuard automatically discovers devices on a local network, maintains a trusted-device baseline, monitors TCP ports and services, detects newly discovered devices and ports, stores historical network data, and provides an interactive web dashboard for reviewing security events.

## Features

- Automated network device discovery
- Trusted and untrusted device tracking
- New device detection and security alerts
- TCP port and service monitoring
- New port detection
- Historical scan storage with SQLite
- Flask REST API
- Web-based security dashboard
- Device renaming and trust management
- Security alert resolution
- Automated scans every 10 minutes
- Automatic startup using Linux systemd

## Technologies

- Raspberry Pi 3B
- Raspberry Pi OS / Linux
- Python
- Nmap
- SQLite
- Flask
- Gunicorn
- HTML
- CSS
- JavaScript
- REST APIs
- JSON
- systemd

## Security Notice

PiGuard is designed for monitoring networks that the user owns or is authorized to administer. The current dashboard is intended for local-network use and should not be exposed directly to the public internet.
