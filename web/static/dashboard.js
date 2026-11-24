let deviceMap = {};


function escapeHTML(value) {

    if (value === null || value === undefined) {
        return "Unknown";
    }

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function formatDate(value) {

    if (!value) {
        return "Unknown";
    }

    return new Date(value).toLocaleString();
}


async function loadDashboard() {

    try {

        const [
            statusResponse,
            deviceResponse,
            alertResponse
        ] = await Promise.all([
            fetch("/api/status"),
            fetch("/api/devices"),
            fetch("/api/alerts")
        ]);

        if (
            !statusResponse.ok ||
            !deviceResponse.ok ||
            !alertResponse.ok
        ) {
            throw new Error("API request failed");
        }

        const status = await statusResponse.json();
        const devices = await deviceResponse.json();
        const alerts = await alertResponse.json();

        updateStatus(status);
        updateDevices(devices);
        updateAlerts(alerts);

    } catch (error) {

        console.error(error);

        document.getElementById(
            "alertList"
        ).innerHTML =
            '<p class="muted">Unable to load PiGuard data.</p>';
    }
}


function updateStatus(status) {

    document.getElementById(
        "knownDevices"
    ).textContent = status.total_devices;

    document.getElementById(
        "untrustedDevices"
    ).textContent = status.untrusted_devices;

    document.getElementById(
        "activeAlerts"
    ).textContent = status.active_alerts;


    if (status.latest_scan) {

        document.getElementById(
            "lastScanDevices"
        ).textContent =
            status.latest_scan.device_count;

        document.getElementById(
            "lastScanTime"
        ).textContent =
            formatDate(status.latest_scan.scan_time);

    } else {

        document.getElementById(
            "lastScanDevices"
        ).textContent = "—";

        document.getElementById(
            "lastScanTime"
        ).textContent = "No scans recorded";
    }
}


function updateDevices(devices) {

    deviceMap = {};

    const table =
        document.getElementById("deviceTable");

    table.innerHTML = "";


    devices.forEach(device => {

        deviceMap[device.id] = device;

        const row =
            document.createElement("tr");


        const trustStatus = device.trusted
            ? '<span class="badge trusted">TRUSTED</span>'
            : '<span class="badge untrusted">UNTRUSTED</span>';


        const trustButton = device.trusted
            ? ""
            : `
                <button
                    class="action-button"
                    onclick="trustDevice(${device.id})"
                >
                    Trust
                </button>
            `;


        row.innerHTML = `
            <td>
                <strong>
                    ${escapeHTML(device.hostname)}
                </strong>
            </td>

            <td>
                ${escapeHTML(device.ip_address)}
            </td>

            <td>
                ${escapeHTML(device.vendor)}
            </td>

            <td>
                ${escapeHTML(device.mac_address)}
            </td>

            <td>
                ${trustStatus}
            </td>

            <td>
                <div class="actions">

                    ${trustButton}

                    <button
                        class="secondary-button"
                        onclick="renameDevice(${device.id})"
                    >
                        Rename
                    </button>

                    <button
                        class="secondary-button"
                        onclick="viewPorts(${device.id})"
                    >
                        Ports
                    </button>

                </div>
            </td>
        `;

        table.appendChild(row);
    });
}


function updateAlerts(alerts) {

    const container =
        document.getElementById("alertList");

    container.innerHTML = "";


    if (alerts.length === 0) {

        container.innerHTML =
            '<p class="muted">No security alerts recorded.</p>';

        return;
    }


    alerts.forEach(alert => {

        const element =
            document.createElement("div");

        element.className =
            alert.resolved
                ? "alert resolved"
                : "alert active";


        const button = alert.resolved
            ? ""
            : `
                <button
                    class="action-button"
                    onclick="resolveAlert(${alert.id})"
                >
                    Resolve
                </button>
            `;


        element.innerHTML = `
            <div>
                <h3>
                    ${escapeHTML(alert.alert_type)}
                </h3>

                <p>
                    ${escapeHTML(alert.message)}
                </p>

                <p>
                    ${escapeHTML(
                        formatDate(alert.created_at)
                    )}
                </p>
            </div>

            ${button}
        `;

        container.appendChild(element);
    });
}


async function trustDevice(deviceId) {

    const response = await fetch(
        `/api/devices/${deviceId}/trust`,
        {
            method: "POST"
        }
    );

    if (response.ok) {
        await loadDashboard();
    }
}


async function resolveAlert(alertId) {

    const response = await fetch(
        `/api/alerts/${alertId}/resolve`,
        {
            method: "POST"
        }
    );

    if (response.ok) {
        await loadDashboard();
    }
}


async function renameDevice(deviceId) {

    const device = deviceMap[deviceId];

    const hostname = prompt(
        "Enter a name for this device:",
        device.hostname
    );


    if (!hostname) {
        return;
    }


    const response = await fetch(
        `/api/devices/${deviceId}/name`,
        {
            method: "PATCH",

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({
                hostname: hostname
            })
        }
    );


    if (response.ok) {
        await loadDashboard();
    }
}


async function viewPorts(deviceId) {

    const response = await fetch(
        `/api/devices/${deviceId}/ports`
    );

    const ports = await response.json();

    const device = deviceMap[deviceId];


    document.getElementById(
        "portsTitle"
    ).textContent =
        `Open Ports — ${device.hostname}`;


    const container =
        document.getElementById("portsContent");


    if (ports.length === 0) {

        container.innerHTML =
            '<p class="muted">No known open ports.</p>';

    } else {

        container.innerHTML =
            ports.map(port => `

                <div class="port-row">

                    <span class="port-number">
                        ${escapeHTML(port.port_number)}
                        /
                        ${escapeHTML(port.protocol)}
                    </span>

                    <span>
                        ${escapeHTML(port.service)}
                    </span>

                </div>

            `).join("");
    }


    document.getElementById(
        "portsModal"
    ).classList.remove("hidden");
}


function closePorts() {

    document.getElementById(
        "portsModal"
    ).classList.add("hidden");
}


loadDashboard();
