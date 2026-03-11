/*
 * ui.h — TFT Display UI for WiFi Security Tool
 * Marauder-inspired green/dark theme on ST7789V 135×240
 *
 * Uses TFT_eSprite for double-buffered rendering (no flicker!)
 * Full-screen sprite: 240×135×2 = 64,800 bytes in SRAM
 */
#pragma once

#include "wifi_scan.h"
#include <Arduino.h>
#include <TFT_eSPI.h>

extern TFT_eSPI tft;

// ── Sprite (double buffer) ─────────────────────
static TFT_eSprite spr = TFT_eSprite(&tft);
static bool spriteCreated = false;

// Create sprite once — call in setup()
inline void initSprite() {
  if (!spriteCreated) {
    spr.createSprite(240, 135); // landscape resolution
    spr.setColorDepth(16);
    spriteCreated = true;
  }
}

// Push sprite to display (the only moment pixels change on screen)
inline void pushFrame() { spr.pushSprite(0, 0); }

// ── Color palette (Marauder-inspired) ──────────
// Use spr. instead of tft. for color565 since we draw to sprite
#define C_BG spr.color565(0, 0, 0)
#define C_HEADER_BG spr.color565(0, 30, 0)
#define C_HEADER_RED spr.color565(50, 0, 0)
#define C_HEADER_CYAN spr.color565(0, 30, 30)
#define C_GREEN spr.color565(0, 255, 0)
#define C_GREEN_DIM spr.color565(0, 150, 0)
#define C_GREEN_DARK spr.color565(0, 80, 0)
#define C_CYAN spr.color565(0, 200, 200)
#define C_RED spr.color565(255, 50, 50)
#define C_ORANGE spr.color565(255, 180, 0)
#define C_YELLOW spr.color565(255, 255, 50)
#define C_WHITE spr.color565(200, 200, 200)
#define C_GRAY spr.color565(120, 120, 120) // Improved contrast
#define C_DARK_ROW spr.color565(5, 15, 5)
#define C_SEL_BG spr.color565(0, 50, 0)

// ── Menu items ─────────────────────────────────
enum MenuItem {
  MENU_SCAN_AP,
  MENU_SCAN_STA,
  MENU_DEAUTH,
  MENU_SNIFF,
  MENU_PMKID_COMBO,
  MENU_PCAP_DUMP,
  MENU_WEB_DASHBOARD,
  MENU_EVIL_PORTAL,
  MENU_COUNT
};

const char *menuLabels[] = {
    "Scan APs",         "Scan Stations", "Deauth Attack", "Sniff Handshake",
    "Deauth + Capture", "PCAP Dump",     "Web Dashboard", "Evil Portal"};

const char *menuIcons[] = {
    "[>]", // scan
    "[*]", // stations
    "[!]", // deauth
    "[~]", // sniff
    "[#]", // combo
    "[=]", // pcap
    "[@]", // web
    "[$]"  // evil portal
};

// ── Layout Helpers ─────────────────────────────
void drawHeader(String title, String rightText, uint16_t bgColor,
                uint16_t textColor = C_WHITE) {
  spr.fillRect(0, 0, 240, 18, bgColor);
  spr.setTextFont(1);
  spr.setTextColor(textColor);
  spr.setTextDatum(ML_DATUM);
  spr.drawString(title, 5, 8);
  spr.setTextDatum(MR_DATUM);
  spr.drawString(rightText, 235, 8);
}

void drawFooter(String text, uint16_t bgColor, uint16_t textColor = C_CYAN) {
  spr.fillRect(0, 125, 240, 10, bgColor);
  spr.setTextFont(1);
  spr.setTextColor(textColor);
  spr.setTextDatum(MC_DATUM);
  spr.drawString(text, 120, 130);
}

// ── Web Dashboard View ────────────────────────
inline void drawWebDashboardStatus() {
  spr.fillSprite(C_BG);

  drawHeader("WEB DASHBOARD", "RUNNING", C_HEADER_BG, C_GREEN);

  int y = 35;
  spr.setTextFont(2);
  spr.setTextDatum(MC_DATUM);

  spr.setTextColor(C_WHITE);
  spr.drawString("Connect to WiFi:", 120, y);
  y += 18;

  spr.setTextColor(C_CYAN);
  spr.drawString("WiFiTool_MGT", 120, y);
  y += 22;

  spr.setTextColor(C_WHITE);
  spr.drawString("Go to browser:", 120, y);
  y += 18;

  spr.setTextColor(C_GREEN);
  spr.drawString("http://wifitool.local", 120, y);

  drawFooter("BTN=Stop & Return", C_HEADER_BG, C_WHITE);
  pushFrame();
}

// ── Evil Portal View ────────────────────────────
inline void drawEvilPortalStatus(bool hasPassword, String email = "",
                                 String pwd = "") {
  spr.fillSprite(C_BG);

  drawHeader("EVIL PORTAL", "RUNNING", C_HEADER_BG, C_GREEN);

  int y = 35;
  spr.setTextFont(2);
  spr.setTextDatum(MC_DATUM);

  if (hasPassword) {
    // Credentials Captured! Big red/green alert
    spr.fillRect(0, 30, 240, 90, spr.color565(50, 0, 0)); // Dark red bg

    spr.setTextColor(C_WHITE);
    spr.drawString("CREDENCIAIS CAPTURADAS!", 120, y);
    y += 20;

    spr.setTextColor(C_GREEN);
    spr.setTextFont(2);
    spr.drawString(email, 120, y); // Draw the email
    y += 20;

    spr.setTextColor(C_CYAN);
    spr.setTextFont(4);
    spr.drawString(pwd, 120, y); // Draw the password big
  } else {
    // Waiting state
    spr.setTextColor(C_WHITE);
    spr.drawString("Aguardando vitima...", 120, y);
    y += 20;

    spr.setTextColor(C_GRAY);
    spr.drawString("SoftAP ativa.", 120, y);
    y += 20;
    spr.drawString("Servindo Google Login.", 120, y);
  }

  drawFooter("BTN=Stop & Return", C_HEADER_BG, C_WHITE);
  pushFrame();
}

// ── Splash screen ──────────────────────────────
inline void drawSplash() {
  spr.fillSprite(C_BG);

  spr.setTextColor(C_GREEN, C_BG);
  spr.setTextFont(4);
  spr.setTextDatum(MC_DATUM);
  spr.drawString("> WIFI TOOL <", 120, 50);

  spr.setTextFont(2);
  spr.setTextColor(C_WHITE, C_BG);
  spr.drawString("T-Display Edition", 120, 80);

  spr.setTextFont(1);
  spr.setTextColor(C_GRAY, C_BG);
  spr.drawString("Press any button", 120, 110);

  pushFrame();
}

// ── Main menu ──────────────────────────────────
inline void drawMenu(int selected, int targetApIdx = -1) {
  spr.fillSprite(C_BG);

  String headerTitle = "WIFI TOOL";
  if (targetApIdx >= 0 && targetApIdx < apCount) {
    headerTitle = "TRGT: " + apList[targetApIdx].ssid;
    if (headerTitle.length() > 16) {
      headerTitle = headerTitle.substring(0, 14) + "..";
    }
  }

  drawHeader(headerTitle, String(ESP.getFreeHeap() / 1024) + "KB", C_HEADER_BG);

  // Menu items - using small font (1) to fit 8 items
  int startY = 18;
  int rowH = 13;

  spr.setTextFont(1); // Force font 1 for smaller rows
  for (int i = 0; i < MENU_COUNT; i++) {
    int y = startY + i * rowH;
    if (y + rowH > 125)
      break;

    if (i == selected) {
      spr.fillRect(0, y, 240, rowH, C_SEL_BG);
      spr.setTextColor(C_GREEN);
    } else {
      if (i % 2 == 0)
        spr.fillRect(0, y, 240, rowH, C_DARK_ROW);
      spr.setTextColor(C_GREEN_DIM);
    }

    spr.setTextDatum(ML_DATUM);
    spr.setTextFont(2);
    spr.drawString(String(menuIcons[i]) + " " + String(menuLabels[i]), 5,
                   y + rowH / 2);

    if (i == selected) {
      spr.setTextColor(C_GREEN);
      spr.setTextDatum(MR_DATUM);
      spr.drawString("<", 235, y + rowH / 2);
    }
  }

  drawFooter("TOP=Next   BTN=Select", C_HEADER_BG);
  pushFrame();
}

// ── AP List screen ─────────────────────────────
inline void drawAPList(int scrollPos, int selectedIdx) {
  spr.fillSprite(C_BG);

  drawHeader("ACCESS POINTS", String(apCount), C_HEADER_BG);

  if (apCount == 0) {
    spr.setTextDatum(MC_DATUM);
    spr.setTextColor(C_GREEN_DIM);
    spr.setTextFont(2);
    spr.drawString("Scanning...", 120, 67);
    drawFooter("TOP=Scroll   BTN=Select", C_HEADER_BG);
    pushFrame();
    return;
  }

  int visibleRows = 6;
  int rowH = 17;
  int startY = 20;

  for (int i = 0; i < visibleRows; i++) {
    int idx = scrollPos + i;
    if (idx >= apCount)
      break;

    int y = startY + i * rowH;

    if (idx == selectedIdx) {
      spr.fillRect(0, y, 240, rowH, C_SEL_BG);
      spr.setTextColor(C_GREEN);
    } else {
      if (i % 2 == 0)
        spr.fillRect(0, y, 240, rowH, C_DARK_ROW);
      bool isOpen = (apList[idx].encryption == WIFI_AUTH_OPEN);
      spr.setTextColor(isOpen ? C_ORANGE : C_GREEN_DIM);
    }

    String ssid = apList[idx].ssid;
    if (ssid.length() > 18)
      ssid = ssid.substring(0, 16) + "..";

    spr.setTextDatum(ML_DATUM);
    spr.setTextFont(2);
    spr.drawString(ssid, 5, y + rowH / 2);

    spr.setTextFont(1);
    spr.setTextDatum(MR_DATUM);
    spr.setTextColor(C_GRAY);
    spr.drawString(String(apList[idx].rssi) + " Ch" +
                       String(apList[idx].channel),
                   235, y + rowH / 2);
  }

  drawFooter("TOP=Scroll   BTN=Select", C_HEADER_BG);
  pushFrame();
}

// ── Station list screen ────────────────────────
inline void drawSTAList(int scrollPos) {
  spr.fillSprite(C_BG);

  drawHeader("STATIONS", String(staCount), C_HEADER_BG);

  if (staCount == 0) {
    spr.setTextDatum(MC_DATUM);
    spr.setTextColor(C_GREEN_DIM);
    spr.setTextFont(2);
    spr.drawString("Sniffing...", 120, 67);
    drawFooter("BTN=Stop", C_HEADER_BG);
    pushFrame();
    return;
  }

  int rowH = 15;
  int startY = 20;
  int visibleRows = 7;

  for (int i = 0; i < visibleRows; i++) {
    int idx = scrollPos + i;
    if (idx >= staCount)
      break;

    int y = startY + i * rowH;
    if (i % 2 == 0)
      spr.fillRect(0, y, 240, rowH, C_DARK_ROW);

    spr.setTextFont(1);
    spr.setTextDatum(ML_DATUM);
    spr.setTextColor(C_CYAN);
    spr.drawString(macToString(staList[idx].mac), 5, y + rowH / 2);

    spr.setTextDatum(MR_DATUM);
    spr.setTextColor(C_GRAY);
    spr.drawString(String(staList[idx].rssi) + " dBm", 235, y + rowH / 2);
  }

  drawFooter("TOP=Scroll   BTN=Stop", C_HEADER_BG);
  pushFrame();
}

// ── Deauth status screen ──────────────────────
inline void drawDeauthStatus(const char *targetSSID, uint32_t sent,
                             bool running) {
  spr.fillSprite(C_BG);

  drawHeader("DEAUTH ATTACK", running ? "RUNNING" : "STOPPED", C_HEADER_RED,
             C_RED);

  int y = 35;
  spr.setTextFont(2);
  spr.setTextDatum(ML_DATUM);

  spr.setTextColor(C_WHITE);
  spr.drawString("Target:", 10, y);
  y += 18;

  String ssid = String(targetSSID);
  if (ssid.length() > 20)
    ssid = ssid.substring(0, 18) + "..";
  spr.setTextColor(C_GREEN);
  spr.drawString(ssid, 10, y);
  y += 24;

  spr.setTextColor(C_WHITE);
  spr.drawString("Packets sent:", 10, y);
  y += 20;

  spr.setTextColor(C_RED);
  spr.setTextFont(4);
  spr.drawString(String(sent), 10, y);

  drawFooter("BTN=Stop", C_HEADER_RED, C_WHITE);
  pushFrame();
}

// ── Sniffer status screen ─────────────────────
inline void drawSnifferStatus(const char *targetSSID, uint32_t eapol,
                              uint32_t pmkid, uint32_t total,
                              bool handshakeCaptured, bool running) {
  spr.fillSprite(C_BG);

  drawHeader("SNIFFER", running ? "LISTENING" : "IDLE", C_HEADER_CYAN, C_CYAN);

  int y = 30;
  spr.setTextFont(2);
  spr.setTextDatum(ML_DATUM);

  String ssid = String(targetSSID);
  if (ssid.length() > 15)
    ssid = ssid.substring(0, 13) + "..";

  spr.setTextColor(C_WHITE);
  spr.drawString("Target: " + ssid, 10, y);
  y += 20;

  spr.setTextColor(C_CYAN);
  spr.drawString("EAPOL: " + String(eapol), 10, y);
  spr.setTextDatum(MR_DATUM);
  spr.drawString("PMKID: " + String(pmkid), 230, y);
  y += 20;

  spr.setTextDatum(ML_DATUM);
  spr.setTextColor(C_GRAY);
  spr.drawString("Total pkts: " + String(total), 10, y);
  y += 24;

  // Handshake status
  spr.setTextFont(4);
  spr.setTextDatum(MC_DATUM);
  if (handshakeCaptured) {
    spr.setTextColor(C_GREEN);
    spr.drawString("CAPTURED!", 120, y);
  } else {
    spr.setTextColor(running ? C_ORANGE : C_GRAY);
    spr.setTextFont(2);
    spr.drawString(running ? "Waiting for Handshake..." : "Idle", 120, y);
  }

  drawFooter("TOP=PCAP   BTN=Stop", C_HEADER_CYAN, C_CYAN);
  pushFrame();
}

// ── Simple message screen (for confirmations) ──
inline void drawMessage(const char *line1, const char *line2, const char *line3,
                        uint16_t color) {
  spr.fillSprite(C_BG);

  // Create a minimal header for consistency
  drawHeader("SYSTEM", "", C_HEADER_BG);

  spr.setTextDatum(MC_DATUM);
  spr.setTextColor(color);
  spr.setTextFont(2);
  spr.drawString(line1, 120, 50);

  spr.setTextColor(C_CYAN);
  spr.drawString(line2, 120, 75);

  spr.setTextColor(C_GRAY);
  spr.setTextFont(1);
  spr.drawString(line3, 120, 100);

  // Footer
  drawFooter("Please wait...", C_HEADER_BG);

  pushFrame();
}
