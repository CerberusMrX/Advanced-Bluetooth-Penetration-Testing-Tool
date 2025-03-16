# Cerberus Blue v6.1 - Advanced Bluetooth Penetration Testing Tool

**Cerberus Blue** is a cutting-edge, open-source tool designed for Bluetooth security research and penetration testing. It offers a robust suite of attacks targeting Bluetooth Classic and BLE devices across Android, iOS, Windows, and Linux platforms. With real-world functionality at its core, Cerberus Blue includes exploits for known CVEs, device spoofing, packet manipulation, and Android-specific ADB-based attacks, all wrapped in a user-friendly interface.Still this is a Beta Version.

**Programmer**: Sudeepa Wanigarathna  
**Version**: 6.1 (March 2025)  
**License**: MIT

  ![tool1](https://github.com/user-attachments/assets/80d90a75-4869-4ed7-9b13-27601f3c65c7)

*Screenshot of the Cerberus Blue v6.1 menu in action.*

---

## Features

### General Bluetooth Attacks
- Device scanning, DoS, deauthentication, and fuzzing.
- Packet snooping, traffic injection, and reverse shell capabilities.
- Spoofing (MAC, BLE, device profiles) and reconnaissance.

### CVE-Based Exploits
- **BlueBorne Overflow** (CVE-2017-0785)
- **Pairing Exploit** (CVE-2018-5383)
- **Zero-Click RCE** (CVE-2020-0022)
- **KNOB Key Attack** (CVE-2019-9506)
- **BIAS Impersonation** (CVE-2021-0326, CVE-2023-45866)
- **BLE Spoofing & MITM** (CVE-2024-21306, CVE-2020-15802)
- **Bluetooth DoS** (CVE-2024-0230)
- Platform-specific: iOS Overflow (CVE-2021-31786), Windows BleedingTooth (CVE-2020-12351).

### Platform-Specific Attacks
- **Android**: Camera access, contact dumping, location tracking, screenshots, keystroke injection, and app launching via ADB.
- **iOS**: Bluetooth overflow and keystroke injection.
- **Windows**: RCE and enhanced DoS attacks.

### User Experience
- Rich CLI with progress bars, tables, and color-coded output.
- Grouped menu for easy navigation.
- Detailed logging (`cerberus_blue.log`) for debugging.

---

## Requirements

### System Dependencies
- **Operating System**: Linux (Ubuntu 20.04+ recommended) or Windows (limited support).
- **Bluetooth Adapter**: USB dongle supporting HCI commands (e.g., CSR 4.0).
- **Required Tools**:
  - `bluez`: Core Bluetooth stack.
  - `bluez-hcidump`: Packet capturing.
  - `rfkill`: Bluetooth state management.
  - `network-manager`: Optional network control.
  - `android-tools-adb`: For Android ADB exploits.
  - `figlet`: ASCII banner (optional).

Install on Ubuntu or Kali:
```bash
sudo apt update
sudo apt install bluez bluez-hcidump rfkill network-manager android-tools-adb figlet
pip3 install -r requirements.txt
python3 cerberusblue.py
