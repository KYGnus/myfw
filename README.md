# FreeUTM - Enterprise-Grade Unified Threat Management Solution

![FreeUTM Logo](https://www.clipartmax.com/png/middle/326-3266663_gnu-linux-gnu-linux-logo-png.png)  
**Open-Source Network Security Platform for Modern Enterprises**

## Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Integration](#integration)
- [Security Features](#security-features)
- [Performance Considerations](#performance-considerations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Enterprise Support](#enterprise-support)

## Overview

FreeUTM is a comprehensive open-source Unified Threat Management solution designed for enterprise environments. It combines next-generation firewall capabilities, intrusion detection/prevention, advanced threat protection, network monitoring, and load balancing in a single integrated platform.

Built on proven open-source technologies like iptables, Snort, Zeek, ClamAV, and Netdata, FreeUTM provides enterprise-grade security for organizations of all sizes while maintaining complete transparency and customizability.

## Key Features

### Core Security Components
- **Next-Gen Firewall**: Stateful packet inspection with deep packet analysis
- **Intrusion Prevention System**: Real-time network attack prevention (Snort 3 + Zeek)
- **Advanced Threat Protection**: Multi-engine malware detection (ClamAV + YARA + Maldet)
- **Network Anomaly Detection**: Behavioral analysis with machine learning indicators

### Enterprise Capabilities
- **Centralized Monitoring**: Real-time dashboards with Netdata integration
- **Threat Intelligence**: Automated feed updates from 100+ sources
- **Load Balancing**: Nginx + HAProxy for high availability deployments
- **Compliance Ready**: Built-in hardening for PCI-DSS, HIPAA, GDPR

### Operational Features
- Automated security updates and signature management
- Custom rule engine for organization-specific policies
- Comprehensive logging and email alerting system


Here's an updated **Features** section that includes your requested benefits while staying accurate to the script's current capabilities:

---

## Benefits  

### **Core Security Tools**  
- Basic iptables firewall with threat feed blocking  
- IDS/IPS setup (Snort3 + Zeek + Maltrail)  
- Antivirus scanning (ClamAV + Maldet + Rkhunter)  
- System hardening & monitoring  

### **Key Advantages**  
✅ **Build Your Own UTM**  
   - Fully customizable script – modify rules, feeds, and tools to fit your needs  

✅ **No License Costs**  
   - 100% free and open-source (GPLv3) – no subscriptions or hidden fees  

✅ **Attack Vector Protection**  
   | Attack Vector       | Mitigation Strategy          |  
   |---------------------|------------------------------|  
   | Malware             | ClamAV + YARA + Maldet scans |  
   | Brute Force         | Fail2Ban + iptables rules    |  
   | Suspicious Traffic  | Snort3 + Zeek network monitoring |  
   | Known Threats       | 100+ automated threat feeds  |  

✅ **Zero Cost**  
   - Uses only free/open-source tools – no budget required  

✅ **Enterprise-Ready Foundation**  
   - Base for building advanced security (custom rules, SIEM integration, etc.)  

✅ **Web Interface (Future Roadmap)**  
   - Planned add-on for browser-based management (community contributions welcome)  



## System Architecture

```
FreeUTM Architecture
┌───────────────────────────────────────────────────────────────┐
│                        Management Layer                        │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │
│   │ Web Console │  │ CLI Toolkit │  │ REST API (Future)   │   │
│   └─────────────┘  └─────────────┘  └─────────────────────┘   │
└──────────────┬───────────────────────────────────────┬─────────┘
               │                                       │
┌──────────────▼───────┐                   ┌──────────▼──────────┐
│   Control Plane      │                   │    Data Plane        │
│                      │                   │                      │
│  • Configuration Mgmt│                   │  • Packet Processing │
│  • Rule Compilation  │◄──Secure IPC─────►│  • Traffic Analysis │
│  • Log Aggregation   │                   │  • Pattern Matching  │
│  • Alert Management  │                   │  • Flow Control      │
└──────────────────────┘                   └──────────────────────┘
               ▲                                       ▲
               │                                       │
┌──────────────┴───────┐                   ┌──────────┴──────────┐
│   Support Services   │                   │   Network Stack      │
│                      │                   │                      │
│  • Threat Intel Feeds│                   │  • Kernel Modules    │
│  • Signature Updates │                   │  • Network Drivers   │
│  • System Monitoring │                   │  • Hardware Offload  │
└──────────────────────┘                   └──────────────────────┘
```

## Installation

### System Requirements

| Component          | Minimum Requirements | Recommended for Production |
|--------------------|----------------------|----------------------------|
| CPU                | 2 cores              | 8+ cores with AES-NI       |
| RAM                | 4GB                  | 16GB+                      |
| Storage            | 50GB HDD             | 200GB SSD (RAID-1)         |
| Network Interfaces | 1x 1Gbps             | 2x 10Gbps (Bonded)         |
| OS                 | Ubuntu 22.04 LTS     | Ubuntu 22.04 LTS           |

### Installation Methods

**Option 1: DEB Package (Recommended)**
```bash
sudo apt install ./Installers/freeutm_2.0_all.deb
```

**Option 2: Manual Setup**
```bash
git https://github.com/KooshaYeganeh/freeutm.git
cd freeutm
chmod +x utm
sudo ./freeutm --configure --firewall
sudo ./freeutm --configure --ids/ips
```


## Usage
### Command Reference

**System Updates & Services**
```bash
# Update and upgrade all system packages
sudo freeutm --update

# Manage system services
sudo freeutm --service-manager --service <service_name> --start/--stop/--restart/--status
```

**Configuration**
```bash
# Configure system components
sudo freeutm --configure --firewall       # Configure firewall tools
sudo freeutm --configure --kernel        # Configure kernel parameters
sudo freeutm --configure --service-manager  # Configure Fail2Ban
sudo freeutm --configure --ids/ips        # Configure Zeek, Snort, and Maltrail
sudo freeutm --configure --av             # Configure ClamAV, Maldet, RKhunter, chkrootkit, and Yara
sudo freeutm --configure --monitoring     # Configure Netdata (access at IP:19999)
sudo freeutm --configure --hardening      # Harden system security
sudo freeutm --configure --vul            # Configure vulnerability check tools
sudo freeutm --configure --load-balancing # Configure load balancing (Nginx, HAProxy)
```

**IDS/IPS Management**
```bash
# Add custom rule for Snort
sudo freeutm --ids/ips --add-rule '<rule>'
```

**Antivirus Management**
```bash
# Run complete antivirus scan (ClamAV, Maldet, Rkhunter, chkrootkit, YARA)
sudo freeutm --av --scan

# Update antivirus databases
sudo freeutm --av --update
```

**Vulnerability Management**
```bash
# Scan for vulnerabilities with Lynis
sudo freeutm --vulcheck
```

**Load Balancing**
```bash
# Configure load balancing services
sudo freeutm --configure --load-balancing
```


## License

FreeUTM is released under the **GNU General Public License v3.0** (GPL-3.0). Commercial licensing options are available for enterprises requiring proprietary integration.

## Enterprise Support

For organizations requiring professional support, we offer:

- **Priority Security Updates**
- **24/7 Technical Support**
- **Custom Development**
- **Compliance Consulting**

Contact: [Mail](kooshakooshadv@gmail.com)
Contact: [website](kooshayeganeh.github.io)


