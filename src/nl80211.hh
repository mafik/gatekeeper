#pragma once

#include <linux/nl80211.h>
#include <set>

#include "arr.hh"
#include "genetlink.hh"
#include "int.hh"
#include "optional.hh"
#include "str.hh"

namespace maf::nl80211 {

struct Bitrate {
  U32 bitrate;         // Bitrate in units of 100 kbps.
  bool short_preamble; // Short preamble supported in 2.4 GHz band.
  Str ToStr() const;
};

// DFS = Dynamic Frequency Selection
struct DFS {
  using State = nl80211_dfs_state;
  State state = NL80211_DFS_USABLE;
  U32 time_ms = 0;
  U32 cac_time_ms = 0; // Channel Availability Check
  Str ToStr() const;
};

struct WMMRule {
  U16 cw_min = 0; // Minimum contention window slot.
  U16 cw_max = 0; // Maximum contention window slot.
  U8 aifsn = 0;   // Arbitration Inter-Frame Space
  U16 txop = 0;   // Maximum duration of a TXOP.
};

struct Frequency {
  U32 frequency = 0;     // Frequency in MHz.
  bool disabled = false; // Channel is disabled in current regulatory domain.
  bool no_ir = false; // No mechanisms that initiate radiation are permitted on
                      // this channel, this includes sending probe requests, or
                      // modes of operation that require beaconing.
  bool radar = false; // Radar detection is mandatory on this channel in current
                      // regulatory domain.
  U32 max_tx_power_100dbm = 0; // Maximum transmission power in mBm (100 * dBm).
  Optional<DFS> dfs = std::nullopt; // Dynamic Frequency Selection.
  U32 offset = 0;
  bool indoor_only = false;
  bool no_ht40_minus = false;
  bool no_ht40_plus = false;
  bool no_80mhz = false;
  bool no_160mhz = false;
  Vec<WMMRule> wmm_rules;
  Str Describe() const;
};

struct Band {
  nl80211_band nl80211_band;
  Vec<Bitrate> bitrates;
  Vec<Frequency> frequencies;
  struct HighThroughput {
    Arr<U8, 16> mcs_set; // 16-byte attribute containing the MCS set as defined
                         // in 802.11n
    U16 capa;            // HT capabilities, as in the HT information IE
    U8 ampdu_factor;     // A-MPDU factor, as in 11n
    U8 ampdu_density;    // A-MPDU density, as in 11n
  };
  Optional<HighThroughput> ht = std::nullopt;
  struct VeryHighThroughput {
    Arr<U8, 8> mcs_set; // struct ieee80211_vht_mcs_info (nl80211.h sems to have
                        // wrong info about this)
    U32 capa;           // VHT capabilities, as in the HT information IE
  };
  Optional<VeryHighThroughput> vht = std::nullopt;
  Str Describe() const;
};

enum class CipherSuite : U32 {
  FallbackToGroup = 0x000FAC00,
  WEP40 = 0x000FAC01,
  TKIP = 0x000FAC02,
  CCMP = 0x000FAC04,
  WEP104 = 0x000FAC05,
  BIP = 0x00FAC06,
};

struct InterfaceLimit {
  U32 max;
  Vec<nl80211_iftype> iftypes;
};

struct InterfaceCombination {
  Vec<InterfaceLimit> limits;
  U32 num_channels;
  U32 maxnum; // Maximum number of interfaces
  U32 radar_detect_widths;
  U32 radar_detect_regions;
  bool sta_ap_bi_match = false;
  U32 beacon_interval_min_gcd;

  Str Describe() const;
};

struct Wiphy {
  int index;
  Str name;
  Vec<Band> bands;
  U8 retry_short_limit; // TX retry limit for frames whose length is less than
                        // or equal to the RTS threshold; allowed range: 1..255;
  U8 retry_long_limit;  // TX retry limit for frames whose length is greater
                        // than the RTS threshold; allowed range: 1..255;
  Optional<U16> fragmentation_threshold = std::nullopt; // Allowed range:
                                                        // 256..8000;
  Optional<U32> rts_threshold = std::nullopt; // Allowed range: 0..65536;
  U8 coverage_class = 0;
  U8 max_scan_ssids = 0; // Number of SSIDs you can scan with a single scan
                         // request.
  U8 max_sched_scan_ssids = 0;   // Number of SSIDs you can scan with a single
                                 // scheduled scan request.
  U16 max_scan_ie_len = 0;       // Maximum length of information elements that
                                 // can be added to scan requests.
  U16 max_sched_scan_ie_len = 0; // Maximum length of information elements that
                                 // can be added to scheduled scan requests.
  U8 max_sched_scan_match_sets =
      0; // Maximum number of sets that can be used with scheduled scan.
  bool roam_support =
      false; // Indicates whether the firmware is capable of roaming to another
             // AP in the same ESS if the signal lever is low.
  std::set<CipherSuite> cipher_suites;
  U8 max_num_pmkids = 0;    // Maximum number of PMKIDs a firmware can cache
  U32 antenna_avail_tx = 0; // Bitmask of available TX antennas
  U32 antenna_avail_rx = 0; // Bitmask of available RX antennas
  std::set<nl80211_iftype> iftypes;
  std::set<nl80211_iftype> software_iftypes;
  std::set<nl80211_commands> supported_commands;
  U32 max_remain_on_channel_duration =
      0; // Maximum duration for remain-on-channel
         // requests in milliseconds.
  bool offchannel_tx_ok = false;
  std::set<nl80211_wowlan_triggers> wowlan_triggers;
  Optional<nl80211_pattern_support> wowlan_pattern_support = std::nullopt;
  Vec<InterfaceCombination> interface_combinations;
  bool ap_sme = false; // Built-in AP Station Management Entity
  U32 feature_flags;   // See nl80211_feature_flags
  std::set<U16> tx_frame_types;
  std::set<U16> rx_frame_types;
  U32 nan_bands_bitmask = 0;               // See NL80211_ATTR_BANDS
  Vec<nl80211_bss_select_attr> bss_select; // See NL80211_ATTR_BSS_SELECT

  Str Describe() const;
};

struct Netlink {
  GenericNetlink nl;

  Netlink(Status &status);

  Vec<Wiphy> GetWiphys(Status &status);
};

Str WoWLANTriggerToStr(nl80211_wowlan_triggers);
Str IftypeToStr(nl80211_iftype);
Str CipherSuiteToStr(CipherSuite);
Str CmdToStr(U8 cmd);
Str AttrToStr(U16 attr);
Str BandAttrToStr(nl80211_band_attr);
Str BitrateAttrToStr(nl80211_bitrate_attr);
Str FrequencyAttrToStr(nl80211_frequency_attr);
Str BssSelectAttrToStr(nl80211_bss_select_attr);
Str WmmRuleToStr(nl80211_wmm_rule);
Str DfsStateToStr(DFS::State);
Str BandToStr(nl80211_band);

} // namespace maf::nl80211