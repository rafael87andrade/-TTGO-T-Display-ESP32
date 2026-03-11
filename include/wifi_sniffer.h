/*
 * wifi_sniffer.h — EAPOL / PMKID handshake capture
 * Promiscuous mode sniffer with EAPOL detection
 */
#pragma once

#include "esp_wifi.h"
#include "pcap_serial.h"
#include "wifi_scan.h"
#include <Arduino.h>


// ── Sniffer state ──────────────────────────────
struct SnifferStats {
  uint32_t totalPackets;
  uint32_t eapolPackets;
  uint32_t pmkidPackets;
  uint32_t deauthDetected;
  bool running;
  bool handshakeCaptured; // got at least 2 EAPOL frames
  uint8_t targetBSSID[6];
  uint8_t targetChannel;
  unsigned long startTime;
};

extern SnifferStats snifferStats;

// ── EAPOL detection ────────────────────────────
// EAPOL ethertype: 0x888E
// LLC/SNAP header pattern in 802.11 data frames:
// AA AA 03 00 00 00 88 8E
static const uint8_t EAPOL_SNAP[] = {0xAA, 0xAA, 0x03, 0x00,
                                     0x00, 0x00, 0x88, 0x8E};

// PMKID is in RSN IE of Message 1 (key info = 0x008A)
// OUI: 00-0F-AC, Type: 04 (PMKID)
static const uint8_t PMKID_OUI[] = {0x00, 0x0F, 0xAC, 0x04};

// ── Sniffer callback ───────────────────────────
static void handshakeSnifferCb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!snifferStats.running)
    return;

  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *payload = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;

  snifferStats.totalPackets++;

  // Minimum viable frame
  if (len < 28)
    return;

  uint16_t frameCtrl = payload[0] | (payload[1] << 8);
  uint8_t frameType = (frameCtrl & 0x0C) >> 2;
  uint8_t frameSubType = (frameCtrl >> 4) & 0x0F;

  // Detect deauth frames (type=0, subtype=0x0C)
  if (frameType == 0 && frameSubType == 0x0C) {
    snifferStats.deauthDetected++;
    return;
  }

  // Only process data frames (type=2)
  if (frameType != 2)
    return;

  // Check if this frame matches our target BSSID
  const uint8_t *addr1 = &payload[4];
  const uint8_t *addr2 = &payload[10];
  const uint8_t *addr3 = &payload[16];

  bool matchesBSSID = false;
  if (snifferStats.targetBSSID[0] != 0 || snifferStats.targetBSSID[1] != 0) {
    matchesBSSID = macEquals(addr1, snifferStats.targetBSSID) ||
                   macEquals(addr2, snifferStats.targetBSSID) ||
                   macEquals(addr3, snifferStats.targetBSSID);
    if (!matchesBSSID)
      return;
  }

  // Look for LLC/SNAP EAPOL header in payload
  // Data frame header is at least 24 bytes, QoS adds 2
  int headerLen = 24;
  if (frameSubType & 0x08)
    headerLen += 2; // QoS flag

  if ((int)len < headerLen + 8)
    return;

  // Search for EAPOL SNAP pattern
  bool isEAPOL = false;
  for (int i = headerLen; i < (int)len - 8; i++) {
    if (memcmp(&payload[i], EAPOL_SNAP, sizeof(EAPOL_SNAP)) == 0) {
      isEAPOL = true;
      break;
    }
  }

  if (!isEAPOL)
    return;

  snifferStats.eapolPackets++;
  Serial.printf("[EAPOL] Captured! (%d total) len=%d\n",
                snifferStats.eapolPackets, len);

  // Check for PMKID in EAPOL message
  for (int i = headerLen; i < (int)len - 20; i++) {
    if (memcmp(&payload[i], PMKID_OUI, sizeof(PMKID_OUI)) == 0) {
      snifferStats.pmkidPackets++;
      Serial.printf("[PMKID] Captured PMKID! offset=%d\n", i);
      break;
    }
  }

  // Save to PCAP buffer
  pcapWritePacket(payload, len);

  // Mark handshake as captured if we have 2+ EAPOL frames
  if (snifferStats.eapolPackets >= 2) {
    snifferStats.handshakeCaptured = true;
  }
}

// ── Start sniffer on target ────────────────────
inline void startSniffer(const uint8_t *bssid, uint8_t channel) {
  memset(&snifferStats, 0, sizeof(snifferStats));
  memcpy(snifferStats.targetBSSID, bssid, 6);
  snifferStats.targetChannel = channel;
  snifferStats.running = true;
  snifferStats.startTime = millis();

  pcapReset();

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(handshakeSnifferCb);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

  Serial.printf("[SNIFF] Started on ch %d, target %s\n", channel,
                macToString(bssid).c_str());
}

// ── Stop sniffer ───────────────────────────────
inline void stopSniffer() {
  snifferStats.running = false;
  esp_wifi_set_promiscuous(false);
  Serial.printf("[SNIFF] Stopped. EAPOL=%d PMKID=%d Total=%d\n",
                snifferStats.eapolPackets, snifferStats.pmkidPackets,
                snifferStats.totalPackets);
}
