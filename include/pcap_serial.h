/*
 * pcap_serial.h — PCAP format export via Serial
 * Outputs PCAP global header + packet records for Wireshark
 */
#pragma once

#include <Arduino.h>

// ── PCAP structures ────────────────────────────
// Global header: magic, version, snaplen, link type
struct __attribute__((packed)) PcapGlobalHeader {
  uint32_t magic_number;  // 0xA1B2C3D4
  uint16_t version_major; // 2
  uint16_t version_minor; // 4
  int32_t thiszone;       // 0
  uint32_t sigfigs;       // 0
  uint32_t snaplen;       // 65535
  uint32_t network;       // 105 = IEEE 802.11
};

// Per-packet header
struct __attribute__((packed)) PcapPacketHeader {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
};

// ── PCAP buffer ────────────────────────────────
#define PCAP_BUFFER_SIZE 8192
static uint8_t pcapBuffer[PCAP_BUFFER_SIZE];
static uint32_t pcapOffset = 0;
static uint32_t pcapPacketCount = 0;
static bool pcapHeaderWritten = false;

// ── Reset buffer ───────────────────────────────
inline void pcapReset() {
  pcapOffset = 0;
  pcapPacketCount = 0;
  pcapHeaderWritten = false;
}

// ── Write PCAP global header to buffer ─────────
inline void pcapWriteGlobalHeader() {
  if (pcapHeaderWritten)
    return;
  if (pcapOffset + sizeof(PcapGlobalHeader) > PCAP_BUFFER_SIZE)
    return;

  PcapGlobalHeader gh;
  gh.magic_number = 0xA1B2C3D4;
  gh.version_major = 2;
  gh.version_minor = 4;
  gh.thiszone = 0;
  gh.sigfigs = 0;
  gh.snaplen = 65535;
  gh.network = 105; // LINKTYPE_IEEE802_11

  memcpy(&pcapBuffer[pcapOffset], &gh, sizeof(gh));
  pcapOffset += sizeof(gh);
  pcapHeaderWritten = true;
}

// ── Write a packet to buffer ───────────────────
inline bool pcapWritePacket(const uint8_t *data, uint16_t len) {
  if (!pcapHeaderWritten)
    pcapWriteGlobalHeader();

  uint32_t needed = sizeof(PcapPacketHeader) + len;
  if (pcapOffset + needed > PCAP_BUFFER_SIZE) {
    Serial.println("[PCAP] Buffer full!");
    return false;
  }

  unsigned long now = millis();
  PcapPacketHeader ph;
  ph.ts_sec = now / 1000;
  ph.ts_usec = (now % 1000) * 1000;
  ph.incl_len = len;
  ph.orig_len = len;

  memcpy(&pcapBuffer[pcapOffset], &ph, sizeof(ph));
  pcapOffset += sizeof(ph);

  memcpy(&pcapBuffer[pcapOffset], data, len);
  pcapOffset += len;

  pcapPacketCount++;
  return true;
}

// ── Dump buffer to Serial (binary) ─────────────
// Use with: python -c "import serial; s=serial.Serial('COM3',115200);
// open('capture.pcap','wb').write(s.read(SIZE))"
inline void pcapDumpToSerial() {
  if (pcapOffset == 0) {
    Serial.println("[PCAP] No data to dump");
    return;
  }

  Serial.printf("\n[PCAP] Dumping %d bytes (%d packets)...\n", pcapOffset,
                pcapPacketCount);
  Serial.println("[PCAP] === START PCAP BINARY ===");
  delay(100);

  // Output as hex for safe serial transfer
  for (uint32_t i = 0; i < pcapOffset; i++) {
    Serial.printf("%02X", pcapBuffer[i]);
    if ((i + 1) % 40 == 0)
      Serial.println();
  }

  Serial.println();
  Serial.println("[PCAP] === END PCAP BINARY ===");
  Serial.printf("[PCAP] Done. %d bytes dumped.\n", pcapOffset);
}

// ── Get stats ──────────────────────────────────
inline uint32_t pcapGetSize() { return pcapOffset; }
inline uint32_t pcapGetCount() { return pcapPacketCount; }
inline uint8_t *pcapGetBuffer() { return pcapBuffer; }
