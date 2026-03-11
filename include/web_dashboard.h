#pragma once

#include "pcap_serial.h" // For access to the PCAP buffer
#include <ESPmDNS.h>
#include <WebServer.h>
#include <WiFi.h>


WebServer server(80);

const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WiFi Marauder Dashboard</title>
  <style>
    body { background-color: #050f05; color: #00ff00; font-family: monospace; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    h1 { margin-bottom: 5px; color: #00ff00; text-shadow: 0 0 5px #00ff00; }
    .subtitle { color: #009600; margin-bottom: 30px; font-size: 0.9em; }
    .card { background: #001e00; padding: 20px; border: 1px solid #00ff00; border-radius: 8px; text-align: center; width: 80%; max-width: 400px; box-shadow: 0 0 15px rgba(0, 255, 0, 0.2); }
    .stat { margin: 10px 0; font-size: 1.2em; color: #fff; }
    .stat span { color: #00ff00; font-weight: bold; }
    a.btn { display: inline-block; margin-top: 20px; background-color: #00ff00; color: #000; padding: 15px 25px; text-decoration: none; font-size: 1.2em; font-weight: bold; border-radius: 5px; border: 2px solid #00ff00; transition: all 0.3s ease; text-transform: uppercase; }
    a.btn:hover { background-color: #000; color: #00ff00; box-shadow: 0 0 10px #00ff00; }
    .danger { color: #ff3232; margin-top: 30px; font-size: 0.8em; }
  </style>
</head>
<body>
  <h1>WIFI TOOL</h1>
  <div class="subtitle">T-Display Edition - Dashboard</div>
  <div class="card">
    <div class="stat">PCAP Size: <span>%SIZE% bytes</span></div>
    <div class="stat">Packets: <span>%COUNT%</span></div>
    <a href="/pcap" class="btn">Download PCAP</a>
  </div>
  <div class="danger">⚠ FOR AUTHORIZED TESTING ONLY ⚠</div>
</body>
</html>
)rawliteral";

String processor(const String &var) {
  if (var == "SIZE") {
    return String(pcapGetSize());
  } else if (var == "COUNT") {
    return String(pcapGetCount());
  }
  return String();
}

void handleRoot() {
  String html = String(index_html);
  html.replace("%SIZE%", processor("SIZE"));
  html.replace("%COUNT%", processor("COUNT"));
  server.send(200, "text/html", html);
}

void handlePcapDownload() {
  if (pcapGetSize() == 0) {
    server.send(404, "text/plain", "No packets captured yet.");
    return;
  }

  // Stream the buffer directly to the client as an attachment
  server.sendHeader("Content-Disposition",
                    "attachment; filename=\"capture.pcap\"");
  server.sendHeader("Connection", "close");
  server.setContentLength(pcapGetSize());
  server.send(200, "application/vnd.tcpdump.pcap",
              ""); // Send headers only first

  // Now write the data
  WiFiClient client = server.client();
  if (client) {
    size_t sent = client.write(pcapGetBuffer(), pcapGetSize());
    Serial.printf("[WEB] Sent PCAP file: %d bytes\n", sent);
  }
}

void startWebDashboard() {
  Serial.println("\n[WEB] Starting Web Dashboard...");

  // 1. Ensure any promiscuous/monitor stuff is completely off
  esp_wifi_set_promiscuous(false);

  // 2. Start AP mode
  WiFi.mode(WIFI_AP);
  WiFi.softAP("WiFiTool_MGT",
              "marauder123"); // Password to keep it relatively safe

  delay(100);

  IPAddress IP = WiFi.softAPIP();
  Serial.print("[WEB] AP IP address: ");
  Serial.println(IP);

  // 3. Start mDNS
  if (!MDNS.begin("wifitool")) {
    Serial.println("[WEB] Error setting up MDNS responder!");
  } else {
    Serial.println("[WEB] mDNS responder started at http://wifitool.local");
  }

  // 4. Setup server routes
  server.on("/", handleRoot);
  server.on("/pcap", handlePcapDownload);

  server.begin();
  Serial.println("[WEB] HTTP server started");
}

void stopWebDashboard() {
  server.close();
  WiFi.softAPdisconnect(true);
  MDNS.end();
  WiFi.mode(WIFI_STA);
  Serial.println("[WEB] Stopped Web Dashboard, returned to STA mode");
}
