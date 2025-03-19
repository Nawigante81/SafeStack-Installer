# SafeStack-Installer

**SafeStack-Installer** is a Bash script that automates the installation and configuration of essential security and monitoring services on Debian/Ubuntu systems. It enables rapid deployment of Pi-hole, Unbound, CrowdSec, Prometheus, and Grafana, integrating them into a cohesive ecosystem for security and data visualization.

## Project Description

**SafeStack-Installer** simplifies the setup of advanced security and monitoring tools on Debian or Ubuntu-based servers. The script automates installation and integration of the following services:

- **Pi-hole** – Network-level ad and tracking blocker.
- **Unbound** – Local DNS resolver enhancing privacy.
- **CrowdSec** – Local protection against network attacks (without registering to the central API).
- **Prometheus** – Monitoring system for collecting metrics.
- **Grafana** – Visualization tool for collected data.

The script installs these applications, automatically configures their interoperability, and adjusts UFW firewall rules (for TCP and UDP protocols), significantly enhancing system security.

## Features

- **Interactive Installation**: Users can select services to install, configure ports, and set passwords for Pi-hole, offering flexibility for various use-case scenarios.
- **Automated Configuration**: The script performs the following tasks:
  - Checks availability of required ports.
  - Installs and updates necessary packages.
  - Configures the UFW firewall for TCP and UDP protocols.
  - Integrates services, e.g., configuring Pi-hole to use Unbound as a DNS resolver, enhancing privacy.
- **Error Handling**: In case of issues, the script logs events to `/var/log/install_script.log` and offers options to skip problematic steps or abort installation, improving reliability.

## Requirements

- **Operating System**: Debian (recommended 11+) or Ubuntu (recommended 20.04+).
- **Privileges**: Requires root privileges (e.g., via `sudo`).
- **Internet Access**: Necessary for downloading packages and system updates.
- **Available Ports**: The script verifies port availability and warns about conflicts.

## Installation and Usage

1. **Clone the repository**:
   ```bash
   git clone https://github.com/<username>/SafeStack-Installer.git
   cd SafeStack-Installer
   ```

2. **Run the script**:
   ```bash
   chmod +x script.sh
   sudo ./script.sh
   ```

3. **Follow instructions**: The script guides you through installation, allowing selection of services and configurations.

4. **Verify installation**: After completion, verify services:
   - Pi-hole: `sudo systemctl status pihole-FTL`
   - Unbound: `sudo systemctl status unbound`
   - CrowdSec: `sudo cscli metrics`
   - Prometheus: `sudo systemctl status prometheus`
   - Grafana: `sudo systemctl status grafana-server`

## Configuration and Integration

After installation, services are preconfigured to work together. Use the links below for administrative panels and customization tips:

- **Pi-hole**: Admin panel: `http://<SERVER_IP>/admin/`. Customize blocklists or add your own rules.
- **Grafana**: Runs on port 3000: `http://<SERVER_IP>:3000`. Default login: admin/admin. Add Prometheus as a data source.
- **Prometheus**: Metrics available at: `http://<SERVER_IP>:9090`. Edit `/etc/prometheus/prometheus.yml` to add more services.
- **CrowdSec**: Check status: `sudo cscli metrics`. Add custom security scenarios.
- **Unbound**: Logs located at `/var/log/unbound.log`. Configure via `/etc/unbound/unbound.conf`.

## Logs and Debugging

All events are logged in:
```bash
cat /var/log/install_script.log
```

For debugging, use these commands:
- Pi-hole: `pihole -d`
- Unbound: `unbound -d`
- CrowdSec: `sudo cscli explain`

Report issues in the GitHub Issues section.

## Authors

- **Acid** – [GitHub](https://github.com/<username>)

