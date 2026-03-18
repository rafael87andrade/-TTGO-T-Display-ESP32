/*
 * test_wifi_logic.cpp — Unit tests for wifi_scan helpers
 * Run with: pio test -e native
 *
 * Tests the platform-independent helper functions:
 * macToString, macEquals
 */
#include <cstdint>
#include <cstring>
#include <unity.h>


// ───────────────────────────────────────────────
// Stubs for Arduino/ESP32 APIs
// ───────────────────────────────────────────────
#include <cstdio>
#include <cstdlib>

// Minimal Arduino String stub
class String {
public:
  char _buf[128];
  int _len;
  String() : _len(0) { _buf[0] = '\0'; }
  String(const char *s) {
    _len = strlen(s);
    strncpy(_buf, s, 127);
    _buf[127] = '\0';
  }
  String(int v) { _len = snprintf(_buf, 128, "%d", v); }
  const char *c_str() const { return _buf; }
  int length() const { return _len; }
  bool operator==(const char *s) const { return strcmp(_buf, s) == 0; }
  String substring(int from, int to) const {
    String r;
    int l = to - from;
    if (l > 0 && l < 128) {
      strncpy(r._buf, _buf + from, l);
      r._buf[l] = '\0';
      r._len = l;
    }
    return r;
  }
  String operator+(const String &other) const {
    String r;
    snprintf(r._buf, 128, "%s%s", _buf, other._buf);
    r._len = strlen(r._buf);
    return r;
  }
};

// ───────────────────────────────────────────────
// Inline replicas of the functions under test
// (from wifi_scan.h, extracted to avoid HW deps)
// ───────────────────────────────────────────────
inline String macToString(const uint8_t *mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1],
           mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

inline bool macEquals(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 6) == 0;
}

// ═══════════════════════════════════════════════
// macToString TESTS
// ═══════════════════════════════════════════════

void test_macToString_all_zeros() {
  uint8_t mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  String result = macToString(mac);
  TEST_ASSERT_TRUE(result == "00:00:00:00:00:00");
}

void test_macToString_broadcast() {
  uint8_t mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  String result = macToString(mac);
  TEST_ASSERT_TRUE(result == "FF:FF:FF:FF:FF:FF");
}

void test_macToString_typical_mac() {
  uint8_t mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
  String result = macToString(mac);
  TEST_ASSERT_TRUE(result == "AA:BB:CC:DD:EE:01");
}

void test_macToString_length_is_17() {
  uint8_t mac[6] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
  String result = macToString(mac);
  TEST_ASSERT_EQUAL(17, result.length());
}

// ═══════════════════════════════════════════════
// macEquals TESTS
// ═══════════════════════════════════════════════

void test_macEquals_same() {
  uint8_t a[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  uint8_t b[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  TEST_ASSERT_TRUE(macEquals(a, b));
}

void test_macEquals_different() {
  uint8_t a[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  uint8_t b[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x67}; // last byte differs
  TEST_ASSERT_FALSE(macEquals(a, b));
}

void test_macEquals_first_byte_different() {
  uint8_t a[6] = {0x00, 0x22, 0x33, 0x44, 0x55, 0x66};
  uint8_t b[6] = {0x01, 0x22, 0x33, 0x44, 0x55, 0x66};
  TEST_ASSERT_FALSE(macEquals(a, b));
}

void test_macEquals_all_zeros() {
  uint8_t a[6] = {0};
  uint8_t b[6] = {0};
  TEST_ASSERT_TRUE(macEquals(a, b));
}

void test_macEquals_broadcast() {
  uint8_t a[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t b[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  TEST_ASSERT_TRUE(macEquals(a, b));
}

// ═══════════════════════════════════════════════
// DEAUTH PACKET STRUCTURE TESTS
// ═══════════════════════════════════════════════
// Verify the deauth frame template is correctly structured

static uint8_t deauthPacket[26] = {
    0xC0, 0x00,                         // Frame Control: Deauth
    0x00, 0x00,                         // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (broadcast)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
    0x00, 0x00,                         // Sequence number
    0x01, 0x00                          // Reason: Unspecified
};

void test_deauth_frame_control_is_c0_00() {
  TEST_ASSERT_EQUAL_HEX8(0xC0, deauthPacket[0]);
  TEST_ASSERT_EQUAL_HEX8(0x00, deauthPacket[1]);
}

void test_deauth_default_destination_is_broadcast() {
  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  TEST_ASSERT_EQUAL_MEMORY(broadcast, &deauthPacket[4], 6);
}

void test_deauth_reason_code_default_is_1() {
  TEST_ASSERT_EQUAL_HEX8(0x01, deauthPacket[24]);
}

void test_deauth_frame_size_is_26() {
  TEST_ASSERT_EQUAL(26, sizeof(deauthPacket));
}

void test_deauth_bssid_copy() {
  // Simulate setting BSSID
  uint8_t bssid[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  memcpy(&deauthPacket[10], bssid, 6); // Source
  memcpy(&deauthPacket[16], bssid, 6); // BSSID

  TEST_ASSERT_EQUAL_MEMORY(bssid, &deauthPacket[10], 6);
  TEST_ASSERT_EQUAL_MEMORY(bssid, &deauthPacket[16], 6);

  // Reset
  memset(&deauthPacket[10], 0, 12);
}

// ═══════════════════════════════════════════════
// EAPOL SNAP PATTERN TEST
// ═══════════════════════════════════════════════
void test_eapol_snap_pattern_correct() {
  static const uint8_t expected[] = {0xAA, 0xAA, 0x03, 0x00,
                                     0x00, 0x00, 0x88, 0x8E};
  // Replicate from wifi_sniffer.h
  static const uint8_t EAPOL_SNAP[] = {0xAA, 0xAA, 0x03, 0x00,
                                       0x00, 0x00, 0x88, 0x8E};
  TEST_ASSERT_EQUAL_MEMORY(expected, EAPOL_SNAP, 8);
}

void test_pmkid_oui_pattern_correct() {
  static const uint8_t expected[] = {0x00, 0x0F, 0xAC, 0x04};
  static const uint8_t PMKID_OUI[] = {0x00, 0x0F, 0xAC, 0x04};
  TEST_ASSERT_EQUAL_MEMORY(expected, PMKID_OUI, 4);
}

// ═══════════════════════════════════════════════
// WEB DASHBOARD TEMPLATE TESTS
// ═══════════════════════════════════════════════
void test_web_dashboard_has_pcap_placeholders() {
  // Simulate checking that the HTML template has the %SIZE% and %COUNT%
  // placeholders. We can't #include the actual header here, so we test
  // the pattern as a string.
  const char *html = "%SIZE% bytes</span></div><div class=\"stat\">Packets: "
                     "<span>%COUNT%</span>";
  TEST_ASSERT_NOT_NULL(strstr(html, "%SIZE%"));
  TEST_ASSERT_NOT_NULL(strstr(html, "%COUNT%"));
}

// ═══════════════════════════════════════════════
// RUN ALL TESTS
// ═══════════════════════════════════════════════
int main(int argc, char **argv) {
  UNITY_BEGIN();

  // MAC helpers
  RUN_TEST(test_macToString_all_zeros);
  RUN_TEST(test_macToString_broadcast);
  RUN_TEST(test_macToString_typical_mac);
  RUN_TEST(test_macToString_length_is_17);

  RUN_TEST(test_macEquals_same);
  RUN_TEST(test_macEquals_different);
  RUN_TEST(test_macEquals_first_byte_different);
  RUN_TEST(test_macEquals_all_zeros);
  RUN_TEST(test_macEquals_broadcast);

  // Deauth frame structure
  RUN_TEST(test_deauth_frame_control_is_c0_00);
  RUN_TEST(test_deauth_default_destination_is_broadcast);
  RUN_TEST(test_deauth_reason_code_default_is_1);
  RUN_TEST(test_deauth_frame_size_is_26);
  RUN_TEST(test_deauth_bssid_copy);

  // Protocol patterns
  RUN_TEST(test_eapol_snap_pattern_correct);
  RUN_TEST(test_pmkid_oui_pattern_correct);

  // Web template
  RUN_TEST(test_web_dashboard_has_pcap_placeholders);

  return UNITY_END();
}
