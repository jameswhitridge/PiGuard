from flask import Flask, jsonify, request, render_template
import sqlite3
from pathlib import Path

app = Flask(__name__)


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/devices/<int:device_id>/trust", methods=["POST"])
def trust_device(device_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE devices
        SET trusted = 1
        WHERE id = ?
        """,
        (device_id,)
    )

    if cursor.rowcount == 0:
        conn.close()
        return jsonify({
            "error": "Device not found"
        }), 404

    # If the device had a NEW_DEVICE alert,
    # resolve it automatically when trusted.
    cursor.execute(
        """
        UPDATE alerts
        SET resolved = 1
        WHERE device_id = ?
        AND alert_type = 'NEW_DEVICE'
        """,
        (device_id,)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "device_id": device_id,
        "trusted": True
    })


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
def resolve_alert(alert_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE alerts
        SET resolved = 1
        WHERE id = ?
        """,
        (alert_id,)
    )

    if cursor.rowcount == 0:
        conn.close()
        return jsonify({
            "error": "Alert not found"
        }), 404

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "alert_id": alert_id,
        "resolved": True
    })


@app.route("/api/devices/<int:device_id>/name", methods=["PATCH"])
def rename_device(device_id):
    data = request.get_json(silent=True)

    if not data or not data.get("hostname"):
        return jsonify({
            "error": "hostname is required"
        }), 400

    hostname = data["hostname"].strip()

    if not hostname:
        return jsonify({
            "error": "hostname cannot be empty"
        }), 400

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE devices
        SET hostname = ?
        WHERE id = ?
        """,
        (
            hostname,
            device_id
        )
    )

    if cursor.rowcount == 0:
        conn.close()
        return jsonify({
            "error": "Device not found"
        }), 404

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "device_id": device_id,
        "hostname": hostname
    })




PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_PATH = PROJECT_ROOT / "data" / "piguard.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/api/status")
def api_status():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS count FROM devices")
    total_devices = cursor.fetchone()["count"]

    cursor.execute(
        "SELECT COUNT(*) AS count FROM devices WHERE trusted = 1"
    )
    trusted_devices = cursor.fetchone()["count"]

    cursor.execute(
        "SELECT COUNT(*) AS count FROM devices WHERE trusted = 0"
    )
    untrusted_devices = cursor.fetchone()["count"]

    cursor.execute(
        """
        SELECT COUNT(*) AS count
        FROM alerts
        WHERE resolved = 0
        """
    )
    active_alerts = cursor.fetchone()["count"]

    cursor.execute(
        """
        SELECT *
        FROM scans
        ORDER BY id DESC
        LIMIT 1
        """
    )

    latest_scan = cursor.fetchone()

    conn.close()

    return jsonify({
        "status": "online",
        "total_devices": total_devices,
        "trusted_devices": trusted_devices,
        "untrusted_devices": untrusted_devices,
        "active_alerts": active_alerts,
        "latest_scan": dict(latest_scan) if latest_scan else None
    })


@app.route("/api/devices")
def api_devices():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            d.id,
            d.hostname,
            d.mac_address,
            d.vendor,
            d.first_seen,
            d.last_seen,
            d.trusted,
            d.port_baselined,

            (
                SELECT o.ip_address
                FROM observations o
                WHERE o.device_id = d.id
                ORDER BY o.id DESC
                LIMIT 1
            ) AS ip_address

        FROM devices d
        ORDER BY d.id
        """
    )

    devices = [
        dict(row)
        for row in cursor.fetchall()
    ]

    conn.close()

    return jsonify(devices)


@app.route("/api/alerts")
def api_alerts():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            a.id,
            a.device_id,
            a.alert_type,
            a.message,
            a.created_at,
            a.resolved,
            d.hostname

        FROM alerts a

        LEFT JOIN devices d
            ON a.device_id = d.id

        ORDER BY a.id DESC
        """
    )

    alerts = [
        dict(row)
        for row in cursor.fetchall()
    ]

    conn.close()

    return jsonify(alerts)


@app.route("/api/devices/<int:device_id>/ports")
def api_device_ports(device_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            port_number,
            protocol,
            service,
            first_seen,
            last_seen

        FROM ports

        WHERE device_id = ?

        ORDER BY port_number
        """,
        (device_id,)
    )

    ports = [
        dict(row)
        for row in cursor.fetchall()
    ]

    conn.close()

    return jsonify(ports)


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
