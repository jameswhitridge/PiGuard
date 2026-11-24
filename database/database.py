import sqlite3
from pathlib import Path
from datetime import datetime


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_PATH = PROJECT_ROOT / "data" / "piguard.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_database():
    DB_PATH.parent.mkdir(exist_ok=True)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT NOT NULL,
            network TEXT NOT NULL,
            interface TEXT NOT NULL,
            device_count INTEGER NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_key TEXT UNIQUE NOT NULL,
            mac_address TEXT,
            hostname TEXT,
            vendor TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            trusted INTEGER NOT NULL DEFAULT 0
        )
    """)

    # Add port_baselined to older PiGuard databases.
    cursor.execute("PRAGMA table_info(devices)")
    device_columns = {
        row[1] for row in cursor.fetchall()
    }

    if "port_baselined" not in device_columns:
        cursor.execute("""
            ALTER TABLE devices
            ADD COLUMN port_baselined INTEGER NOT NULL DEFAULT 0
        """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id),
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            alert_type TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            resolved INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            port_number INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,

            UNIQUE (
                device_id,
                port_number,
                protocol
            ),

            FOREIGN KEY (device_id)
                REFERENCES devices(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS port_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            port_number INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service TEXT,
            observed_at TEXT NOT NULL,

            FOREIGN KEY (scan_id)
                REFERENCES scans(id),

            FOREIGN KEY (device_id)
                REFERENCES devices(id)
        )
    """)

    conn.commit()
    conn.close()


def create_device_key(device):
    mac = device.get("mac", "Unknown")

    if mac and mac != "Unknown":
        return f"mac:{mac.lower()}"

    return f"ip:{device['ip']}"


def record_scan(network, interface, devices, port_results):
    initialize_database()

    conn = get_connection()
    cursor = conn.cursor()

    scan_time = datetime.now().isoformat(timespec="seconds")

    cursor.execute(
        """
        INSERT INTO scans (
            scan_time,
            network,
            interface,
            device_count
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            scan_time,
            network,
            interface,
            len(devices)
        )
    )

    scan_id = cursor.lastrowid

    new_devices = []
    new_ports = []

    for device in devices:

        device_key = create_device_key(device)

        cursor.execute(
            """
            SELECT
                id,
                hostname,
                vendor,
                mac_address,
                trusted,
                port_baselined
            FROM devices
            WHERE device_key = ?
            """,
            (device_key,)
        )

        existing_device = cursor.fetchone()

        if existing_device:

            device_id = existing_device[0]
            old_hostname = existing_device[1]
            old_vendor = existing_device[2]
            old_mac = existing_device[3]
            trusted = bool(existing_device[4])
            port_baselined = bool(existing_device[5])

            hostname = device["hostname"]
            vendor = device["vendor"]
            mac = device["mac"]

            if hostname == "Unknown":
                hostname = old_hostname

            if vendor == "Unknown":
                vendor = old_vendor

            if mac == "Unknown":
                mac = old_mac

            cursor.execute(
                """
                UPDATE devices
                SET
                    mac_address = ?,
                    hostname = ?,
                    vendor = ?,
                    last_seen = ?
                WHERE id = ?
                """,
                (
                    mac,
                    hostname,
                    vendor,
                    scan_time,
                    device_id
                )
            )

        else:

            cursor.execute(
                """
                INSERT INTO devices (
                    device_key,
                    mac_address,
                    hostname,
                    vendor,
                    first_seen,
                    last_seen,
                    trusted,
                    port_baselined
                )
                VALUES (?, ?, ?, ?, ?, ?, 0, 0)
                """,
                (
                    device_key,
                    device["mac"],
                    device["hostname"],
                    device["vendor"],
                    scan_time,
                    scan_time
                )
            )

            device_id = cursor.lastrowid
            trusted = False
            port_baselined = False

            alert_message = (
                f"New device detected: "
                f"{device['hostname']} "
                f"({device['ip']}) - "
                f"{device['vendor']}"
            )

            cursor.execute(
                """
                INSERT INTO alerts (
                    device_id,
                    alert_type,
                    message,
                    created_at,
                    resolved
                )
                VALUES (?, ?, ?, ?, 0)
                """,
                (
                    device_id,
                    "NEW_DEVICE",
                    alert_message,
                    scan_time
                )
            )

            new_devices.append(device)

        cursor.execute(
            """
            INSERT INTO observations (
                scan_id,
                device_id,
                ip_address,
                status
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                scan_id,
                device_id,
                device["ip"],
                device["status"]
            )
        )

        # Only process ports if Nmap returned results
        # for this particular device.
        if device["ip"] in port_results:

            current_ports = port_results[device["ip"]]

            for port in current_ports:

                cursor.execute(
                    """
                    SELECT id, service
                    FROM ports
                    WHERE
                        device_id = ?
                        AND port_number = ?
                        AND protocol = ?
                    """,
                    (
                        device_id,
                        port["port"],
                        port["protocol"]
                    )
                )

                known_port = cursor.fetchone()

                if known_port:

                    cursor.execute(
                        """
                        UPDATE ports
                        SET
                            service = ?,
                            last_seen = ?
                        WHERE id = ?
                        """,
                        (
                            port["service"],
                            scan_time,
                            known_port[0]
                        )
                    )

                else:

                    cursor.execute(
                        """
                        INSERT INTO ports (
                            device_id,
                            port_number,
                            protocol,
                            service,
                            first_seen,
                            last_seen
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            device_id,
                            port["port"],
                            port["protocol"],
                            port["service"],
                            scan_time,
                            scan_time
                        )
                    )

                    # The first port scan establishes
                    # a baseline and does NOT generate alerts.
                    #
                    # After that, newly discovered ports
                    # generate alerts on trusted devices.
                    if port_baselined and trusted:

                        alert_message = (
                            f"New port detected on "
                            f"{device['hostname']} "
                            f"({device['ip']}): "
                            f"{port['port']}/"
                            f"{port['protocol']} "
                            f"({port['service']})"
                        )

                        cursor.execute(
                            """
                            INSERT INTO alerts (
                                device_id,
                                alert_type,
                                message,
                                created_at,
                                resolved
                            )
                            VALUES (?, ?, ?, ?, 0)
                            """,
                            (
                                device_id,
                                "NEW_PORT",
                                alert_message,
                                scan_time
                            )
                        )

                        new_ports.append({
                            "device": device,
                            "port": port
                        })

                cursor.execute(
                    """
                    INSERT INTO port_observations (
                        scan_id,
                        device_id,
                        port_number,
                        protocol,
                        service,
                        observed_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        device_id,
                        port["port"],
                        port["protocol"],
                        port["service"],
                        scan_time
                    )
                )

            if not port_baselined:
                cursor.execute(
                    """
                    UPDATE devices
                    SET port_baselined = 1
                    WHERE id = ?
                    """,
                    (device_id,)
                )

    conn.commit()
    conn.close()

    return scan_id, new_devices, new_ports


if __name__ == "__main__":
    initialize_database()
    print(f"PiGuard database initialized: {DB_PATH}")
