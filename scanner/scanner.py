import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import json
import sys
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from database.database import record_scan


def get_local_network():
    """Automatically determine the Pi's active IPv4 network."""

    route_output = subprocess.check_output(
        ["ip", "-4", "route", "show", "default"],
        text=True
    )

    parts = route_output.split()
    interface = parts[parts.index("dev") + 1]

    address_output = subprocess.check_output(
        ["ip", "-4", "-o", "addr", "show", "dev", interface],
        text=True
    )

    for part in address_output.split():
        if "/" in part:
            try:
                interface_address = ipaddress.ip_interface(part)
                return str(interface_address.network), interface
            except ValueError:
                pass

    raise RuntimeError("Could not determine local network.")


def scan_network(network):
    """Run an Nmap host-discovery scan and return discovered devices."""

    command = [
        "nmap",
	"--privileged",
        "-sn",
        "-oX",
        "-",
        network
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True
    )

    root = ET.fromstring(result.stdout)

    devices = []

    for host in root.findall("host"):
        status = host.find("status")

        if status is None or status.get("state") != "up":
            continue

        device = {
            "ip": None,
            "hostname": "Unknown",
            "mac": "Unknown",
            "vendor": "Unknown",
            "status": "online"
        }

        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                device["ip"] = address.get("addr")

            elif address.get("addrtype") == "mac":
                device["mac"] = address.get("addr")
                device["vendor"] = address.get("vendor", "Unknown")

        hostname = host.find("hostnames/hostname")

        if hostname is not None:
            device["hostname"] = hostname.get("name", "Unknown")

        if device["ip"]:
            devices.append(device)

    devices.sort(
        key=lambda device: ipaddress.ip_address(device["ip"])
    )

    return devices


def save_scan(network, interface, devices):
    """Save the most recent scan as JSON."""

    output = {
        "scan_time": datetime.now().isoformat(),
        "network": network,
        "interface": interface,
        "devices_found": len(devices),
        "devices": devices
    }

    project_root = Path(__file__).resolve().parents[1]
    data_directory = project_root / "data"
    data_directory.mkdir(exist_ok=True)

    output_file = data_directory / "latest_scan.json"

    with open(output_file, "w") as file:
        json.dump(output, file, indent=4)

    return output_file


def display_devices(devices):
    print()
    print("PiGuard Network Discovery")
    print("=" * 95)

    print(
        f"{'IP ADDRESS':<17}"
        f"{'HOSTNAME':<30}"
        f"{'MAC ADDRESS':<20}"
        f"{'VENDOR'}"
    )

    print("-" * 95)

    for device in devices:
        print(
            f"{device['ip']:<17}"
            f"{device['hostname'][:28]:<30}"
            f"{device['mac']:<20}"
            f"{device['vendor']}"
        )

    print("-" * 95)
    print(f"{len(devices)} devices discovered.")
    print()


def scan_ports(devices):
    """Scan common TCP ports on discovered devices."""

    if not devices:
        return {}

    ip_addresses = [device["ip"] for device in devices]

    command = [
        "nmap",
        "-sT",
        "--top-ports",
        "100",
        "--open",
        "-oX",
        "-"
    ] + ip_addresses

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True
    )

    root = ET.fromstring(result.stdout)

    port_results = {}

    for host in root.findall("host"):
        ip_address = None

        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                ip_address = address.get("addr")

        if not ip_address:
            continue

        port_results[ip_address] = []

        ports_element = host.find("ports")

        if ports_element is None:
            continue

        for port in ports_element.findall("port"):
            state = port.find("state")

            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")

            port_results[ip_address].append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": (
                    service.get("name", "unknown")
                    if service is not None
                    else "unknown"
                )
            })

    return port_results


def main():
    print()
    print("PiGuard")
    print("Home Network Security Monitor")
    print()

    print("[*] Detecting local network...")
    network, interface = get_local_network()

    print(f"[+] Interface: {interface}")
    print(f"[+] Network:   {network}")

    print()
    print("[*] Scanning network...")

    devices = scan_network(network)

    display_devices(devices)

    print("[*] Scanning common TCP ports...")

    port_results = scan_ports(devices)

    print()
    print("Open Ports")
    print("=" * 70)

    for device in devices:
        ip = device["ip"]
        ports = port_results.get(ip, [])

        if ports:
            print(f"\n{ip} ({device['hostname']})")

            for port in ports:
                print(
                    f"  {port['port']}/{port['protocol']} "
                    f"{port['service']}"
                )

    print()


    output_file = save_scan(network, interface, devices)

    print(f"[+] Scan saved to {output_file}")


    scan_id, new_devices, new_ports = record_scan(
    	network,
    	interface,
    	devices,
	port_results
    )

    print(f"[+] Database scan recorded with ID {scan_id}")

    if new_devices:
    	print()
    	print("!" * 60)
    	print("SECURITY ALERT")
    	print("!" * 60)

    	for device in new_devices:
        	print()
        	print("New untrusted device detected!")
        	print(f"IP:       {device['ip']}")
        	print(f"Hostname: {device['hostname']}")
        	print(f"MAC:      {device['mac']}")
        	print(f"Vendor:   {device['vendor']}")

    	print()
    	print("Review new devices before marking them trusted.")

    else:
    	print("[+] No new devices detected.")



    if new_ports:
        print()
        print("!" * 60)
        print("NEW PORT SECURITY ALERT")
        print("!" * 60)

        for event in new_ports:
            device = event["device"]
            port = event["port"]

            print()
            print(f"Device:   {device['hostname']}")
            print(f"IP:       {device['ip']}")
            print(
                f"Port:     "
                f"{port['port']}/{port['protocol']}"
            )
            print(f"Service:  {port['service']}")

    else:
        print("[+] No new ports detected.")


if __name__ == "__main__":
    main()
