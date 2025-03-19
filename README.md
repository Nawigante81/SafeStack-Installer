# 🚀 SafeStack-Installer

**SafeStack-Installer** is a professional-grade Bash automation script engineered to streamline the installation and integration of essential security and monitoring tools on Debian and Ubuntu servers. Rapidly deploy Pi-hole, Unbound, CrowdSec, Prometheus, and Grafana into a unified and highly secure ecosystem optimized for performance, security, and insightful analytics.

---

## 🛡️ Project Overview

**SafeStack-Installer** transforms complex security setups into a simple, intuitive experience. With a single script, you gain access to:

- ✅ **Pi-hole** – Network-wide ad-blocking and privacy protection.
- ✅ **Unbound** – Secure local DNS resolver focused on privacy and performance.
- ✅ **CrowdSec** – Advanced threat detection and local attack mitigation (no external API registration needed).
- ✅ **Prometheus** – Industry-standard monitoring solution for comprehensive metrics collection.
- ✅ **Grafana** – Powerful, intuitive visualization platform for metrics and insights.

The installer ensures seamless interoperability among these applications and securely configures firewall rules via UFW, optimizing both security and usability.

---

## ⚙️ Cutting-edge Features

- **Interactive Setup**: User-friendly prompts allow precise selection and customization of services, ports, and credentials, ensuring flexibility tailored to your needs.
- **Full Automation**:
  - Comprehensive pre-installation checks to prevent port conflicts.
  - Automatic handling of package installations and system updates.
  - Dynamic firewall configuration (UFW) to secure TCP and UDP traffic.
  - Seamless service integration (e.g., linking Pi-hole and Unbound for improved DNS privacy).
- **Intelligent Error Management**:
  - Extensive logging capabilities in `/var/log/install_script.log`.
  - Graceful handling of installation interruptions, with clear guidance to skip or troubleshoot specific steps.

---

## 📋 Requirements

- **OS Compatibility**: Debian (11 or newer) or Ubuntu (20.04 LTS or newer).
- **Permissions**: Root privileges required (e.g., `sudo`).
- **Network Access**: Essential for package installation and updates.
- **Port Availability**: The installer proactively checks for and reports port conflicts.

---

## 🚦 Installation Guide

### 1. Clone Repository

```bash
git clone https://github.com/<username>/SafeStack-Installer.git
cd SafeStack-Installer
```

### 2. Execute the Installer

```bash
chmod +x script.sh
sudo ./script.sh
```

### 3. Follow On-screen Guidance

The interactive script will guide you through each step, allowing custom configuration tailored precisely to your environment.

### 4. Verify Your Setup

Confirm service statuses easily:

```bash
sudo systemctl status pihole-FTL unbound prometheus grafana-server
sudo cscli metrics
```

---

## 🎛️ Advanced Configuration & Integration

After deployment, the services are integrated and ready for use. Access and customize using these interfaces:

- 🛑 **Pi-hole**: Access your admin dashboard at `http://<SERVER_IP>/admin/`.
- 📊 **Grafana**: Explore dashboards at `http://<SERVER_IP>:3000` (Default credentials: `admin/admin`). Integrate Prometheus as your data source.
- 📈 **Prometheus**: Monitor metrics at `http://<SERVER_IP>:9090`. Extend service monitoring via `/etc/prometheus/prometheus.yml`.
- 🔐 **CrowdSec**: Validate security settings using `sudo cscli metrics`. Add custom defense scenarios.
- 🌀 **Unbound**: Review logs (`/var/log/unbound.log`) and modify settings (`/etc/unbound/unbound.conf`) for optimal DNS security.

---

## 🐞 Logging & Troubleshooting

Efficient debugging is facilitated by detailed logging and dedicated diagnostic commands:

- **Check Installation Logs**:

```bash
cat /var/log/install_script.log
```

- **Debugging Commands**:

```bash
pihole -d
unbound -d
sudo cscli explain
```

Issues or suggestions? Please use the GitHub Issues section—we appreciate your feedback!

---

## 👨‍💻 Maintainer

- **Acid** – [GitHub](https://github.com/<username>)

🌟 **Enjoyed SafeStack-Installer? Consider starring ⭐ the repository to support ongoing development!**

