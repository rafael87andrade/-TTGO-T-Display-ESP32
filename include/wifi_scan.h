/*
 * wifi_scan.h — AP and Station scanner
 * Uses WiFi.scanNetworks() for APs and promiscuous mode for stations
 */
#pragma once

#include "esp_wifi.h"
#include <Arduino.h>
#include <WiFi.h>


// ── Structures ─────────────────────────────────
struct AccessPoint {
  String ssid;
  uint8_t bssid[6];
  int32_t rssi;
  uint8_t channel;
  wifi_auth_mode_t encryption;
  bool selected;
};

struct Station {
  uint8_t mac[6];
  uint8_t bssid[6]; // AP it's associated to
  int32_t rssi;
};

// ── Limits ─────────────────────────────────────
#define MAX_APS 32
#define MAX_STATIONS 64

extern AccessPoint apList[MAX_APS];
extern int apCount;
extern Station staList[MAX_STATIONS];
extern int staCount;
extern int selectedAP;

// ── MAC string helper ──────────────────────────
inline String macToString(const uint8_t *mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1],
           mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

inline bool macEquals(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 6) == 0;
}

// ── AP Scan ────────────────────────────────────
inline void scanAccessPoints() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  int n = WiFi.scanNetworks(false, true); // async=false, show_hidden=true
  apCount = min(n, MAX_APS);

  for (int i = 0; i < apCount; i++) {
    apList[i].ssid = WiFi.SSID(i);
    if (apList[i].ssid.length() == 0)
      apList[i].ssid = "(hidden)";
    memcpy(apList[i].bssid, WiFi.BSSID(i), 6);
    apList[i].rssi = WiFi.RSSI(i);
    apList[i].channel = WiFi.channel(i);
    apList[i].encryption = WiFi.encryptionType(i);
    apList[i].selected = false;
  }

  WiFi.scanDelete();
  Serial.printf("[SCAN] Found %d APs\n", apCount);
}

// ── Station Scan (promiscuous sniff) ───────────
// Sniff data frames to discover stations
typedef struct {
  unsigned frame_ctrl : 16;
  unsigned duration_id : 16;
  uint8_t addr1[6]; // receiver
  uint8_t addr2[6]; // transmitter
  uint8_t addr3[6]; // bssid
  unsigned sequence_ctrl : 16;
} __attribute__((packed)) wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0];
} __attribute__((packed)) wifi_ieee80211_packet_t;

static void stationSnifferCb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT)
    return;

  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  const wifi_ieee80211_packet_t *frame =
      (wifi_ieee80211_packet_t *)pkt->payload;

  // Only data frames (type = 0x02)
  uint8_t frameType = (frame->hdr.frame_ctrl & 0x0C) >> 2;
  if (frameType != 2)
    return; // not a data frame

  const uint8_t *src = frame->hdr.addr2;
  const uint8_t *bssid = frame->hdr.addr3;

  // Skip broadcast/multicast
  if (src[0] & 0x01)
    return;

  // Check if already in list
  for (int i = 0; i < staCount; i++) {
    if (macEquals(staList[i].mac, src))
      return;
  }

  if (staCount >= MAX_STATIONS)
    return;

  memcpy(staList[staCount].mac, src, 6);
  memcpy(staList[staCount].bssid, bssid, 6);
  staList[staCount].rssi = pkt->rx_ctrl.rssi;
  staCount++;
}

inline void startStationScan(uint8_t channel = 0) {
  staCount = 0;
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(stationSnifferCb);
  esp_wifi_set_promiscuous(true);

  if (channel > 0 && channel <= 14) {
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  }

  Serial.printf("[SCAN] Station scan started on ch %d\n", channel);
}

inline void stopStationScan() {
  esp_wifi_set_promiscuous(false);
  Serial.printf("[SCAN] Station scan stopped. Found %d stations\n", staCount);
}
