# TTGO T-Display WiFi Security Tool

A multi-functional WiFi assessment and analysis tool built for the ESP32 (TTGO T-Display). Inspired by the Marauder firmware, this tool features a clean, double-buffered UI on the ST7789 TFT display and provides several capabilities for studying wireless networks.

## Features
- **AP Scanning:** Discover active Access Points, their signal strength (RSSI), channel, and encryption.
- **Station Scanning:** Sniff for clients (STAs) transmitting probe requests and data packets.
- **Deauth Attack:** Target specific APs to broadcast deauthentication frames (Educational purposes only).
- **Handshake Sniffing:** Passively capture WPA/WPA2 4-way handshakes (EAPOL) and PMKIDs.
- **Deauth + Capture (Combo):** Actively deauthenticate clients to force handshakes for capture.
- **PCAP Dump:** Stream captured packets via Serial to be analyzed in Wireshark (via a Python serial-to-pcap script).
- **Web Dashboard:** Host an mDNS-enabled local web interface (`http://wifitool.local`) to download captured PCAP files and view status.
- **Evil Portal:** Create a captive portal clone (Google Sign-In mocking) to intercept credentials.

## Hardware Requirements
- **TTGO T-Display (ESP32):** Includes a 1.14" ST7789V TFT Display and built-in buttons.

## Software Dependencies
- **PlatformIO** (VS Code recommended)
- **TFT_eSPI** Library (Configured for ST7789V, 135x240)
- Built-in ESP32 libraries (WiFi, WebServer, DNSServer, LittleFS)

## Setup & Compilation
1. Clone the repository.
2. Open the project folder in **PlatformIO**.
3. All dependencies are automatically resolved via `platformio.ini`.
4. Compile the project using `pio run` or using the UI checkmark.
5. Upload to your TTGO T-Display via USB (`pio run -t upload`).
6. Build and upload LittleFS filesystem using `pio run -t buildfs` and `pio run -t uploadfs` (required to serve PCAP files to the Web Dashboard).

## Disclaimer
This project is for educational and research purposes only. Only test on networks you own or have explicit permission to audit.
