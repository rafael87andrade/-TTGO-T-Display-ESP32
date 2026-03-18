/*
 * test_pcap.cpp — Unit tests for PCAP buffer logic
 * Run with: pio test -e native
 *
 * These tests validate the core PCAP buffer management
 * functions that are platform-independent (no ESP32 HW needed).
 */
#include <cstdint>
#include <cstring>
#include <unity.h>


// ───────────────────────────────────────────────
// Minimal stubs to make pcap_serial.h compilable
// on native (non-ESP32) targets
// ───────────────────────────────────────────────
unsigned long _millis_val = 0;
unsigned long millis() { return _millis_val; }

// Stub Serial
struct FakeSerial {
  void println(const char *) {}
  void printf(const char *, ...) {}
} Serial;

// Include the real PCAP module (header-only)
#include "pcap_serial.h"

// ═══════════════════════════════════════════════
// PCAP RESET
// ═══════════════════════════════════════════════
void test_pcap_reset_zeros_state() {
  // Write something first
  uint8_t dummy[4] = {0xDE, 0xAD, 0xBE, 0xEF};
  pcapReset();
  pcapWritePacket(dummy, sizeof(dummy));
  TEST_ASSERT_GREATER_THAN(0, pcapGetSize());
  TEST_ASSERT_EQUAL(1, pcapGetCount());

  // Now reset and verify
  pcapReset();
  TEST_ASSERT_EQUAL(0, pcapGetSize());
  TEST_ASSERT_EQUAL(0, pcapGetCount());
}

// ═══════════════════════════════════════════════
// PCAP GLOBAL HEADER
// ═══════════════════════════════════════════════
void test_pcap_global_header_valid() {
  pcapReset();
  pcapWriteGlobalHeader();

  // Global header is 24 bytes
  TEST_ASSERT_EQUAL(sizeof(PcapGlobalHeader), pcapGetSize());

  // Verify magic number at offset 0
  uint8_t *buf = pcapGetBuffer();
  uint32_t magic;
  memcpy(&magic, buf, 4);
  TEST_ASSERT_EQUAL_UINT32(0xA1B2C3D4, magic);

  // Verify version (major=2 at offset 4, minor=4 at offset 6)
  uint16_t ver_major, ver_minor;
  memcpy(&ver_major, buf + 4, 2);
  memcpy(&ver_minor, buf + 6, 2);
  TEST_ASSERT_EQUAL_UINT16(2, ver_major);
  TEST_ASSERT_EQUAL_UINT16(4, ver_minor);

  // Verify link type = 105 (IEEE 802.11) at offset 20
  uint32_t network;
  memcpy(&network, buf + 20, 4);
  TEST_ASSERT_EQUAL_UINT32(105, network);
}

void test_pcap_global_header_written_only_once() {
  pcapReset();
  pcapWriteGlobalHeader();
  uint32_t size_after_first = pcapGetSize();
  pcapWriteGlobalHeader();
  pcapWriteGlobalHeader();
  // Size should not change — header written only once
  TEST_ASSERT_EQUAL(size_after_first, pcapGetSize());
}

// ═══════════════════════════════════════════════
// PCAP WRITE PACKET
// ═══════════════════════════════════════════════
void test_pcap_write_packet_creates_header_automatically() {
  pcapReset();
  uint8_t data[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  bool ok = pcapWritePacket(data, sizeof(data));
  TEST_ASSERT_TRUE(ok);

  // Should have: global header (24) + packet header (16) + data (10) = 50
  TEST_ASSERT_EQUAL(sizeof(PcapGlobalHeader) + sizeof(PcapPacketHeader) + 10,
                    pcapGetSize());
  TEST_ASSERT_EQUAL(1, pcapGetCount());
}

void test_pcap_write_multiple_packets() {
  pcapReset();
  uint8_t data[8] = {0};

  for (int i = 0; i < 5; i++) {
    data[0] = i;
    TEST_ASSERT_TRUE(pcapWritePacket(data, sizeof(data)));
  }

  TEST_ASSERT_EQUAL(5, pcapGetCount());

  // Total = 24 (global) + 5 * (16 + 8) = 24 + 120 = 144
  TEST_ASSERT_EQUAL(24 + 5 * (sizeof(PcapPacketHeader) + 8), pcapGetSize());
}

void test_pcap_write_packet_timestamp_from_millis() {
  pcapReset();
  _millis_val = 5500; // 5.5 seconds
  uint8_t data[4] = {0xAA, 0xBB, 0xCC, 0xDD};
  pcapWritePacket(data, sizeof(data));

  // Packet header starts after global header (24 bytes)
  uint8_t *buf = pcapGetBuffer();
  PcapPacketHeader ph;
  memcpy(&ph, buf + sizeof(PcapGlobalHeader), sizeof(ph));

  TEST_ASSERT_EQUAL_UINT32(5, ph.ts_sec);       // 5500 / 1000
  TEST_ASSERT_EQUAL_UINT32(500000, ph.ts_usec); // (5500 % 1000) * 1000
  TEST_ASSERT_EQUAL_UINT32(4, ph.incl_len);
  TEST_ASSERT_EQUAL_UINT32(4, ph.orig_len);
}

void test_pcap_write_packet_data_integrity() {
  pcapReset();
  uint8_t data[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  pcapWritePacket(data, sizeof(data));

  // Data starts after global header (24) + packet header (16) = offset 40
  uint8_t *buf = pcapGetBuffer();
  uint32_t dataOffset = sizeof(PcapGlobalHeader) + sizeof(PcapPacketHeader);
  TEST_ASSERT_EQUAL_MEMORY(data, buf + dataOffset, sizeof(data));
}

// ═══════════════════════════════════════════════
// PCAP BUFFER OVERFLOW PROTECTION
// ═══════════════════════════════════════════════
void test_pcap_buffer_overflow_returns_false() {
  pcapReset();
  // Fill buffer to near-capacity
  // Buffer is 8192 bytes. Each write = 16 (pkt hdr) + data.
  // Global header = 24 bytes. Available = 8168 bytes.
  // With 100-byte packets: 8168 / (16+100) = 70 packets max

  uint8_t bulk[100];
  memset(bulk, 0xAA, sizeof(bulk));

  int written = 0;
  for (int i = 0; i < 200; i++) { // Try to write way more than fits
    if (pcapWritePacket(bulk, sizeof(bulk))) {
      written++;
    }
  }

  // Should have written some but not all 200
  TEST_ASSERT_GREATER_THAN(0, written);
  TEST_ASSERT_LESS_THAN(200, written);
  // Buffer should not exceed PCAP_BUFFER_SIZE
  TEST_ASSERT_LESS_OR_EQUAL(PCAP_BUFFER_SIZE, pcapGetSize());
}

// ═══════════════════════════════════════════════
// PCAP GET STATS
// ═══════════════════════════════════════════════
void test_pcap_get_size_empty() {
  pcapReset();
  TEST_ASSERT_EQUAL(0, pcapGetSize());
}

void test_pcap_get_count_empty() {
  pcapReset();
  TEST_ASSERT_EQUAL(0, pcapGetCount());
}

void test_pcap_get_buffer_not_null() { TEST_ASSERT_NOT_NULL(pcapGetBuffer()); }

// ═══════════════════════════════════════════════
// RUN ALL TESTS
// ═══════════════════════════════════════════════
int main(int argc, char **argv) {
  UNITY_BEGIN();

  // Reset
  RUN_TEST(test_pcap_reset_zeros_state);

  // Global Header
  RUN_TEST(test_pcap_global_header_valid);
  RUN_TEST(test_pcap_global_header_written_only_once);

  // Write Packet
  RUN_TEST(test_pcap_write_packet_creates_header_automatically);
  RUN_TEST(test_pcap_write_multiple_packets);
  RUN_TEST(test_pcap_write_packet_timestamp_from_millis);
  RUN_TEST(test_pcap_write_packet_data_integrity);

  // Overflow
  RUN_TEST(test_pcap_buffer_overflow_returns_false);

  // Stats
  RUN_TEST(test_pcap_get_size_empty);
  RUN_TEST(test_pcap_get_count_empty);
  RUN_TEST(test_pcap_get_buffer_not_null);

  return UNITY_END();
}
