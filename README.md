# 🌐 Network Flow Monitor

**Professional Network Traffic Analysis & Visualization Tool**

---

## 🔹 Overview

**Network Flow Monitor** is a modern Python-based application with a sleek GUI that enables real-time network packet capture, flow reconstruction, and traffic visualization. Designed for security analysts, network engineers, and enthusiasts, it provides deep insights into your network while remaining user-friendly.

---

## ✨ Features

### 🎯 Interface Selection

* **Dynamic Discovery**: Automatically lists all network interfaces
* **Visual Status**: Shows connection and selection indicators
* **Easy Selection**: Click-to-select interface

### 📡 Real-Time Packet Capture

* Live packet streaming with timestamps and detailed info
* Multi-protocol support: TCP, UDP, ICMP, ARP, and more
* Configurable BPF filters for targeted monitoring
* Thread-safe architecture for smooth performance

### 🌊 Network Flow Analysis

* Automatic tracking of bidirectional flows
* Detailed flow metrics: packets, bytes, duration
* Top Talkers identification: most active hosts/connections
* Flow Details Panel: inspect each network conversation

### 📊 Visual Analytics

* **Real-Time Charts**: Line and bar graphs for traffic analysis
* **Protocol Distribution**: Pie chart breakdown by protocol
* **Traffic Timeline**: Historical packet/byte trends
* Interactive plots with zoom, pan, and explore features

### ⚙️ Advanced Settings

* Configurable capture filters (BPF)
* Memory and packet limits for high-traffic environments
* Adjustable GUI refresh/update intervals
* Export/Import configuration options
* Dark theme and tabbed interface for easy navigation

### 🛡️ Security & Privacy

* Local processing only, no external transmission
* Safe defaults for general use
* Monitor only networks you have permission for

---

## 🚀 Quick Start

### Prerequisites

* Python 3.7+
* Root/Administrator privileges for packet capture
* Operating System: Linux, macOS, Windows
* Dependencies: `scapy`, `matplotlib`, `numpy`, `tkinter`

### Installation

1. Clone or download the repository:

   ```bash
   git clone https://github.com/Dharan10/Network-Monitor
   cd network-monitor
   ```
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:

   ```bash
   sudo python3 app.py   # Linux/macOS
   # Or run Command Prompt as Administrator on Windows
   ```

---

## 📝 Usage Guide

1. **Select Interface**: Go to "Interface Selection" tab and pick your network interface.
2. **Start Monitoring**: Switch to "Live Monitor" tab and click ▶ Start Capture.
3. **Analyze Flows**: View bidirectional flows, packet count, bytes, and duration.
4. **Visual Analysis**: Explore traffic trends and protocol distribution in charts.
5. **Settings**: Configure filters, update intervals, max packets, and alert thresholds.

---

## 🔧 Common Issues

* **Permission Denied**: Ensure you run with elevated privileges
* **No Interfaces Found**: Check network interface status and availability
* **Capture Not Working**: Verify BPF filter syntax and interface support
* **High CPU Usage**: Increase update interval or restrict capture filter
* **GUI Freezing**: Restart application, reduce capture rate, or close charts

---

## 📄 License

This project is open-source for educational and professional network monitoring purposes. Use responsibly and comply with local laws.

---

## 🤝 Contributing

* Fork or clone the repository
* Install dependencies and set up Python environment
* Test changes thoroughly
* Follow PEP 8 guidelines and add docstrings
* Submit feature requests or bug fixes via pull requests

---

## 🏆 Acknowledgments

* **Scapy**: Packet manipulation
* **Matplotlib**: Visualization
* **Tkinter**: GUI framework
* Python community for support and guidance

---

**🚀 Network Flow Monitor – Professional Network Analysis Made Simple**
