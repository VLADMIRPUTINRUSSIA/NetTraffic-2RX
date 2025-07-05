#!/bin/bash

# Extreme All-in-One Network & Wi-Fi Diagnostic Script
# Author: Gemini (based on initial script by Copilot)
# OS: Debian/Ubuntu Based Systems
# Usage: chmod +x extreme_network_diagnostic.sh && sudo ./extreme_network_diagnostic.sh
# Note: Running with sudo is required for many network commands and package installations.

# --- Configuration ---
OUTPUT_DIR="scan_results_$(date +%Y%m%d_%H%M%S)"
REPORT_FILENAME="network_diagnostic_report_$(date +%Y%m%d_%H%M%S).pdf"
TARGET_HOST="google.com"
TARGET_IP="8.8.8.8"

# --- Colors for better output ---
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Trap to clean up on exit ---
cleanup() {
    echo -e "${YELLOW}[*] Cleaning up temporary files...${NC}"
    # Remove Python temporary files if any
    find . -name "*.pyc" -delete
    echo -e "${GREEN}[✓] Cleanup complete.${NC}"
}
trap cleanup EXIT

# --- Set to exit immediately if any command fails ---
set -e

echo -e "${GREEN}[*] Starting Extreme Network & Wi-Fi Diagnostic...${NC}"
echo -e "${YELLOW}[*] Output will be saved in: ${OUTPUT_DIR}${NC}"

# --- 1. Auto-Update & Upgrade ---
echo -e "\n${YELLOW}--- 1. Updating and upgrading system ---${NC}"
sudo apt update -y && sudo apt upgrade -y || echo -e "${RED}[!] System update/upgrade failed. Continuing with existing packages.${NC}"

# --- 2. Install Dependencies ---
echo -e "\n${YELLOW}--- 2. Installing required packages ---${NC}"
REQUIRED_PACKAGES="mtr traceroute nmap tcpdump iftop dnsutils curl python3-pip net-tools iputils-ping iw net-tools wireless-tools network-manager"
for pkg in $REQUIRED_PACKAGES; do
    if ! dpkg -s "$pkg" &> /dev/null; then
        echo -e "${YELLOW}Installing $pkg...${NC}"
        sudo apt install -y "$pkg" || echo -e "${RED}[!] Failed to install $pkg. Some features might be limited.${NC}"
    else
        echo -e "${GREEN}$pkg is already installed.${NC}"
    fi
done

# Install fpdf for PDF report generation
if ! python3 -c "import fpdf" &> /dev/null; then
    echo -e "${YELLOW}Installing fpdf Python library...${NC}"
    pip3 install fpdf || echo -e "${RED}[!] Failed to install fpdf. PDF report generation might fail.${NC}"
else
    echo -e "${GREEN}fpdf is already installed.${NC}"
fi

# --- 3. Create Output Directory ---
echo -e "\n${YELLOW}--- 3. Creating output directory ---${NC}"
mkdir -p "$OUTPUT_DIR"
echo -e "${GREEN}[✓] Directory created: ${OUTPUT_DIR}${NC}"

# --- 4. Network Diagnostics Functions ---

run_command() {
    local cmd_description="$1"
    local command="$2"
    local output_file="$3"
    echo -e "\n${YELLOW}[*] Running: ${cmd_description}${NC}"
    echo "### ${cmd_description} ###" > "$output_file"
    if eval "$command" >> "$output_file" 2>&1; then
        echo -e "${GREEN}[✓] ${cmd_description} completed.${NC}"
    else
        echo -e "${RED}[!] ${cmd_description} failed. Check ${output_file} for details.${NC}"
    fi
}

# General Network Information
run_command "IP Address Configuration" "ip a" "$OUTPUT_DIR/ip_address.txt"
run_command "IP Routing Table" "ip route" "$OUTPUT_DIR/ip_route.txt"
run_command "Network Statistics (detailed)" "netstat -s" "$OUTPUT_DIR/netstat_summary.txt"
run_command "Socket Status (listening ports, connections)" "ss -tulnp" "$OUTPUT_DIR/socket_status.txt"

# Connectivity Checks
run_command "Ping to ${TARGET_IP} (100 packets)" "ping -c 100 ${TARGET_IP}" "$OUTPUT_DIR/ping_target_ip.txt"
run_command "Ping to ${TARGET_HOST} (100 packets)" "ping -c 100 ${TARGET_HOST}" "$OUTPUT_DIR/ping_target_host.txt"
run_command "MTR to ${TARGET_HOST} (100 cycles)" "mtr -r -c 100 ${TARGET_HOST}" "$OUTPUT_DIR/mtr_target_host.txt"
run_command "Traceroute to ${TARGET_HOST}" "traceroute ${TARGET_HOST}" "$OUTPUT_DIR/traceroute_target_host.txt"
run_command "DNS Resolution for ${TARGET_HOST} (dig)" "dig ${TARGET_HOST}" "$OUTPUT_DIR/dig_target_host.txt"
run_command "DNS Trace for ${TARGET_HOST} (dig +trace)" "dig +trace ${TARGET_HOST}" "$OUTPUT_DIR/dig_trace_target_host.txt"
run_command "Curl Check for https://www.roblox.com (header only)" "curl -I https://www.roblox.com" "$OUTPUT_DIR/curl_roblox.txt"

# Port Scanning (Localhost)
run_command "Nmap Scan of Localhost (common ports)" "nmap -p 1-1000 -T4 127.0.0.1" "$OUTPUT_DIR/nmap_localhost_common_ports.txt"

# Network Interface Traffic (snapshot)
echo -e "\n${YELLOW}[*] Running: iftop (snapshot of top bandwidth usage for 10 seconds)${NC}"
echo "### iftop Top Bandwidth Usage (10 seconds) ###" > "$OUTPUT_DIR/iftop_snapshot.txt"
sudo iftop -t -s 10 -L 10 >> "$OUTPUT_DIR/iftop_snapshot.txt" 2>&1 || echo -e "${RED}[!] iftop failed. It might require interaction or specific permissions.${NC}"
echo -e "${GREEN}[✓] iftop snapshot completed.${NC}"

# TCPDUMP (Packet Capture Snapshot)
echo -e "\n${YELLOW}[*] Running: tcpdump (capture first 50 packets on default interface)${NC}"
echo "### tcpdump Packet Capture Snapshot (first 50 packets) ###" > "$OUTPUT_DIR/tcpdump_snapshot.txt"
sudo tcpdump -i any -c 50 >> "$OUTPUT_DIR/tcpdump_snapshot.txt" 2>&1 || echo -e "${RED}[!] tcpdump failed. It might require specific permissions or no packets were captured.${NC}"
echo -e "${GREEN}[✓] tcpdump snapshot completed.${NC}"

# --- 5. Wi-Fi Specific Diagnostics (requires 'iw' and 'nmcli') ---
echo -e "\n${YELLOW}--- 5. Wi-Fi Specific Diagnostics ---${NC}"

# Find all Wi-Fi interfaces
WIFI_INTERFACES=$(iw dev | awk '/Interface/ {print $2}')

if [ -z "$WIFI_INTERFACES" ]; then
    echo -e "${RED}[!] No Wi-Fi interfaces found. Skipping Wi-Fi specific diagnostics.${NC}"
else
    echo "### Wi-Fi Interface Details ###" > "$OUTPUT_DIR/wifi_interface_details.txt"
    echo "### Wi-Fi Scan Results ###" > "$OUTPUT_DIR/wifi_scan_results.txt"
    echo "### Wi-Fi Connection Status ###" > "$OUTPUT_DIR/wifi_connection_status.txt"
    echo "### Wi-Fi NetworkManager Details ###" > "$OUTPUT_DIR/wifi_network_manager_details.txt"
    echo "### Supported Wi-Fi Frequencies and Modes ###" > "$OUTPUT_DIR/wifi_supported_freqs_modes.txt"


    for IFACE in $WIFI_INTERFACES; do
        echo -e "${YELLOW}Processing Wi-Fi interface: ${IFACE}${NC}"

        # Interface details (including mode, transmit power)
        echo "--- Interface: ${IFACE} (ip link show) ---" >> "$OUTPUT_DIR/wifi_interface_details.txt"
        ip link show "$IFACE" >> "$OUTPUT_DIR/wifi_interface_details.txt" 2>&1

        echo "--- Interface: ${IFACE} (iw dev ${IFACE} info) ---" >> "$OUTPUT_DIR/wifi_interface_details.txt"
        iw dev "$IFACE" info >> "$OUTPUT_DIR/wifi_interface_details.txt" 2>&1

        # Currently connected Wi-Fi network details
        echo "--- Current Wi-Fi Connection Status for ${IFACE} (iw dev ${IFACE} link) ---" >> "$OUTPUT_DIR/wifi_connection_status.txt"
        if iw dev "$IFACE" link >> "$OUTPUT_DIR/wifi_connection_status.txt" 2>&1; then
            # Extract signal strength if connected
            SIGNAL_STRENGTH=$(grep "signal:" "$OUTPUT_DIR/wifi_connection_status.txt" | awk '{print $2}')
            if [ -n "$SIGNAL_STRENGTH" ]; then
                echo -e "${GREEN}[✓] Signal Strength for ${IFACE}: ${SIGNAL_STRENGTH} dBm${NC}"
            fi
        else
            echo -e "${YELLOW}[!] ${IFACE} not connected to an AP or failed to get link info.${NC}"
        fi

        # Wi-Fi Scan for nearby networks (including SSIDs, BSSIDs, frequencies, signal strength)
        # This can help identify if Wi-Fi 4, 5, 6, 6E, 7 networks are present based on their advertised capabilities.
        # Note: iw scan output can be very verbose.
        echo "--- Wi-Fi Scan Results for ${IFACE} (iw dev ${IFACE} scan) ---" >> "$OUTPUT_DIR/wifi_scan_results.txt"
        sudo iw dev "$IFACE" scan >> "$OUTPUT_DIR/wifi_scan_results.txt" 2>&1 || echo -e "${RED}[!] Failed to scan with ${IFACE}. Permissions or hardware limitations.${NC}"

        # NetworkManager details (if running)
        echo "--- NetworkManager Device Details for ${IFACE} (nmcli dev show ${IFACE}) ---" >> "$OUTPUT_DIR/wifi_network_manager_details.txt"
        nmcli dev show "$IFACE" >> "$OUTPUT_DIR/wifi_network_manager_details.txt" 2>&1 || echo -e "${YELLOW}[!] NetworkManager not managing ${IFACE} or nmcli not available.${NC}"

        # Supported frequencies and modes for the Wi-Fi card (iw list)
        # This helps understand the capabilities of the installed Wi-Fi hardware
        echo "--- Supported Frequencies and Modes for ${IFACE} (iw list | grep -A 20 \"${IFACE}\") ---" >> "$OUTPUT_DIR/wifi_supported_freqs_modes.txt"
        iw list | grep -A 20 "phy" | grep -B 10 "$IFACE" | grep -A 20 "Frequencies:" >> "$OUTPUT_DIR/wifi_supported_freqs_modes.txt" 2>&1 || echo -e "${YELLOW}[!] Failed to get supported frequencies for ${IFACE}.${NC}"

        # Note on Wi-Fi Standards (4, 5, 6, 6E, 7):
        # Directly detecting these standards requires analyzing 802.11 management frames (e.g., Beacon frames).
        # Standard shell tools can show if the AP supports certain channels/frequencies (2.4GHz, 5GHz, 6GHz for 6E/7),
        # but full capability detection usually needs tools like Wireshark or specialized Python libraries with monitor mode.
        echo -e "${YELLOW}Note: Detailed Wi-Fi standard detection (Wi-Fi 4, 5, 6, 6E, 7) requires advanced packet analysis often beyond simple shell commands.${NC}"
        echo -e "${YELLOW}The 'iw dev [interface] scan' output contains information like 802.11n, 802.11ac, 802.11ax capabilities which indicate Wi-Fi 4, 5, 6 respectively.${NC}"
        echo -e "${YELLOW}Wi-Fi 6E operates in the 6GHz band, and Wi-Fi 7 (802.11be) adds new features like MLO. Look for these indicators in scan results.${NC}"
    done
fi

# --- 6. System Resource Diagnostics (context for network issues) ---
echo -e "\n${YELLOW}--- 6. System Resource Diagnostics ---${NC}"
run_command "Memory Usage" "free -h" "$OUTPUT_DIR/system_memory.txt"
run_command "Disk Usage" "df -h" "$OUTPUT_DIR/system_disk_usage.txt"
run_command "Top Processes by CPU/Memory (snapshot)" "top -bn1 | head -n 20" "$OUTPUT_DIR/system_top_processes.txt"

# --- 7. Generate PDF Report ---
echo -e "\n${YELLOW}--- 7. Generating PDF report...${NC}"

python3 - <<EOF
import os
from fpdf import FPDF
import datetime

class PDFReport(FPDF):
    def header(self):
        self.set_font("Arial", "B", 14)
        self.cell(0, 10, "Extreme Network & Wi-Fi Diagnostic Report", ln=True, align="C")
        self.set_font("Arial", "", 10)
        self.cell(0, 7, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, 'Page %s' % self.page_no(), 0, 0, 'C')

    def add_section(self, title, content):
        self.add_page()
        self.set_font("Arial", "B", 12)
        self.multi_cell(0, 8, title, 0, 'L')
        self.ln(2)
        self.set_font("Arial", "", 9)
        # Ensure content is string and replace problematic characters
        content = str(content).replace('\x00', '').replace('\x1b', '') # Remove null and escape characters
        try:
            self.multi_cell(0, 4, content)
        except Exception as e:
            self.multi_cell(0, 4, f"Error rendering content for {title}: {e}\nContent snippet:\n{content[:500]}...")
        self.ln(5)

pdf = PDFReport()
pdf.set_auto_page_break(auto_page_break=True, margin=15)
pdf.set_title("Extreme Network & Wi-Fi Diagnostic Report")

# Order the files for better report structure
sections_order = [
    "ip_address.txt",
    "ip_route.txt",
    "netstat_summary.txt",
    "socket_status.txt",
    "ping_target_ip.txt",
    "ping_target_host.txt",
    "mtr_target_host.txt",
    "traceroute_target_host.txt",
    "dig_target_host.txt",
    "dig_trace_target_host.txt",
    "curl_roblox.txt",
    "nmap_localhost_common_ports.txt",
    "iftop_snapshot.txt",
    "tcpdump_snapshot.txt",
    "wifi_interface_details.txt",
    "wifi_connection_status.txt",
    "wifi_scan_results.txt",
    "wifi_network_manager_details.txt",
    "wifi_supported_freqs_modes.txt",
    "system_memory.txt",
    "system_disk_usage.txt",
    "system_top_processes.txt"
]

processed_files = []
for filename in sections_order:
    filepath = os.path.join("$OUTPUT_DIR", filename)
    if os.path.exists(filepath):
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
        pdf.add_section(f"Report for: {filename}", content)
        processed_files.append(filename)

# Add any other files not explicitly ordered
for filename in sorted(os.listdir("$OUTPUT_DIR")):
    if filename.endswith(".txt") and filename not in processed_files:
        filepath = os.path.join("$OUTPUT_DIR", filename)
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
        pdf.add_section(f"Report for: {filename}", content)

report_filepath = os.path.join("$OUTPUT_DIR", "$REPORT_FILENAME")
pdf.output(report_filepath)
print(f"[+] Report saved as {report_filepath}")
EOF

echo -e "\n${GREEN}[✓] All tasks completed. Report saved as ${OUTPUT_DIR}/${REPORT_FILENAME}${NC}"
echo -e "${GREEN}To view the report, open ${OUTPUT_DIR}/${REPORT_FILENAME}${NC}"
