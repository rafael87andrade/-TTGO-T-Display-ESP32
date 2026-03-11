/*
 * wifi_bypass.c — ESP32 raw frame sanity check bypass
 *
 * Uses the GCC --wrap linker feature to intercept calls to
 * ieee80211_raw_frame_sanity_check. The linker flag
 * -Wl,--wrap=ieee80211_raw_frame_sanity_check redirects all
 * calls from __real_ to __wrap_.
 */

#include <stdint.h>

// The --wrap linker flag renames:
//   calls to X → __wrap_X
//   original X → __real_X
// So we define __wrap_ version that returns 0 (allow all frames)

int __wrap_ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2,
                                            int32_t arg3) {
  (void)arg;
  (void)arg2;
  (void)arg3;
  return 0; // Allow all frame types including deauth
}
