#pragma once

#include <bitset>
#include <linux/nl80211.h>
#include <set>

#include "arr.hh"
#include "genetlink.hh"
#include "int.hh"
#include "mac.hh"
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
    U16 capa;            // See table 9-162 of IEEE 802.11-2016
    U8 ampdu_factor;     // A-MPDU factor, as in 11n
    U8 ampdu_density;    // A-MPDU density, as in 11n
  };
  Optional<HighThroughput> ht = std::nullopt;
  struct VeryHighThroughput {
    Arr<U8, 8> mcs_set; // See 9.4.2.158.3 of IEEE 802.11-2016
    U32 capa;           // See 9.4.2.158.2 of IEEE 802.11-2016
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

enum class AuthenticationKeyManagement : U32 {
  PSK = 0x000FAC02,
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

struct VendorCommand {
  U32 vendor_id;
  U32 subcommand;
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
  std::bitset<NUM_NL80211_EXT_FEATURES>
      ext_feature_flags; // See nl80211_ext_feature_index
  std::array<U16, NUM_NL80211_IFTYPES> tx_frame_types;
  std::array<U16, NUM_NL80211_IFTYPES> rx_frame_types;
  U32 max_num_sched_scan_plans = 0;
  U32 max_scan_plan_interval = 0; // seconds
  U32 max_scan_plan_iterations = 0;
  MAC mac;
  Vec<MAC> macs;
  Vec<VendorCommand> vendor_commands;
  U32 nan_bands_bitmask = 0;               // See NL80211_ATTR_BANDS
  Vec<nl80211_bss_select_attr> bss_select; // See NL80211_ATTR_BSS_SELECT

  Str Describe() const;
};

struct Interface {
  using Index = U32;
  using Type = nl80211_iftype;
  Index index;
  Str name;
  Type type;
  U32 wiphy_index;
  U64 wireless_device_id;
  MAC mac;
  bool use_4addr;
  U32 frequency_MHz;
  nl80211_channel_type channel_type;
  U32 frequency_offset;
  U32 center_frequency1;
  U32 center_frequency2;
  nl80211_chan_width chan_width;
  Optional<I32> tx_power_level_mbm;

  Str Describe() const;
};

struct Regulation {
  Arr<char, 2> alpha2 = {'X', 'X'};
  nl80211_dfs_regions dfs_region = NL80211_DFS_UNSET;

  struct Rule {
    std::bitset<32> flags;
    U32 start_kHz;
    U32 end_kHz;
    U32 max_bandwidth_kHz;
    U32 max_antenna_gain_mBi; // 100 * dBi
    U32 max_eirp_mBm;         // 100 * dBm; Effective Isotropic Radiated Power
    U32 dfs_cac_time_ms;      // Channel Availability Check time
    Str Describe() const;
  };

  Vec<Rule> rules;

  Str Describe() const;
};

struct DisconnectReason {
  enum {
    DISASSOCIATION = 0,
    DEAUTHENTICATION = 1,
  } type;
  enum {
    UNSPECIFIED_REASON = 1,
    INVALID_AUTHENTICATION = 2,
    LEAVING_NETWORK_DEAUTH = 3,
    REASON_INACTIVITY = 4,
    NO_MORE_STAS = 5,
    INVALID_CLASS2_FRAME = 6,
    INVALID_CLASS3_FRAME = 7,
    LEAVING_NETWORK_DISASSOC = 8,
    NOT_AUTHENTICATED = 9,
    UNACCEPTABLE_POWER_CAPABILITY = 10,
    UNACCEPTABLE_SUPPORTED_CHANNELS = 11,
    BSS_TRANSITION_DISASSOC = 12,
    REASON_INVALID_ELEMENT = 13,
    MIC_FAILURE = 14,
    FOURWAY_HANDSHAKE_TIMEOUT = 15,
    GK_HANDSHAKE_TIMEOUT = 16,
    HANDSHAKE_ELEMENT_MISMATCH = 17,
  } reason_code;
};

// See section 9.4.1.4 of IEEE 802.11-2016
struct CapabilitiesInformation {
  bool ess : 1 = true;
  bool ibss : 1 = false;
  bool cf_pollable : 1 = false;
  bool cf_poll_request : 1 = false;
  bool privacy : 1 = true;
  bool short_preamble : 1 = false;
  bool reserved1 : 1 = false;
  bool reserved2 : 1 = false;
  bool spectrum_management : 1 = false;
  bool qos : 1 = false;
  bool short_slot_time : 1 = false;
  bool apsd : 1 = false;
  bool radio_measurement : 1 = false;
  bool reserved3 : 1 = false;
  bool delayed_block_ack : 1 = false;
  bool immediate_block_ack : 1 = false;
};

enum class ReplayCountersUsage : U8 {
  ONE = 0,
  TWO = 1,
  FOUR = 2,
  SIXTEEN = 3,
};

// See section 9.4.2.25.4 of IEEE 802.11-2016
struct RSNCapabilities {
  // First octet
  bool management_frame_protection_capable : 1 = false;
  bool management_frame_protection_required : 1 = false;
  ReplayCountersUsage gtksa_replay_counter_usage : 2 = ReplayCountersUsage::ONE;
  ReplayCountersUsage ptksa_replay_counter_usage : 2 = ReplayCountersUsage::ONE;
  bool no_pairwise : 1 = false;
  bool preauthentication : 1 = false;

  // Second octet
  bool extended_key_id : 1 = false;
  bool pbac : 1 = false;
  bool spp_a_msdu_required : 1 = false;
  bool spp_a_msdu_capable : 1 = false;
  bool peerkey_enabled : 1 = false;
  bool joint_multi_band_rsna : 1 = false;
};

struct BeaconHeader {
  U16 type_subtype = 0x0080;
  U16 duration = 0;
  MAC destination_address = MAC::Broadcast();
  MAC source_address;
  MAC bssid;
  U16 sequence_control = 0;
  U64 timestamp = 0;
  U16 beacon_interval = 100;
  CapabilitiesInformation capabilities_information;
  BeaconHeader(MAC mac) : source_address(mac), bssid(mac) {}
} __attribute__((packed));

enum class ElementID : U8 {
  SSID = 0,                      // See section 9.4.2.2 of IEEE 802.11-2016
  SUPPORTED_RATES = 1,           // See section 9.4.2.3 of IEEE 802.11-2016
                                 // Can be also used to require HT or VHT
  DSSS_PARAMETER_SET = 3,        // See section 9.4.2.4 of IEEE 802.11-2016
  CF_PARAMETER_SET = 4,          // See section 9.4.2.5 of IEEE 802.11-2016
  TIM = 5,                       // See section 9.4.2.6 of IEEE 802.11-2016
  IBSS_PARAMETER_SET = 6,        // See section 9.4.2.7 of IEEE 802.11-2016
  HT_CAPABILITIES = 45,          // See section  9.4.2.56 of IEEE 802.11-2016
  RSN = 48,                      // See section 9.4.2.25 of IEEE 802.11-2016
  HT_OPERATION = 61,             // See section 9.4.2.57 of IEEE 802.11-2016
  EXTENDED_CAPABILITIES = 127,   // See section 9.4.2.27 of IEEE 802.11-2016
  VHT_CAPABILITIES = 191,        // See section 9.4.2.158 of IEEE 802.11-2016
  VHT_OPERATION = 192,           // See section 9.4.2.159 of IEEE 802.11-2016
  TRANSMIT_POWER_ENVELOPE = 195, // See section 9.4.2.162 of IEEE 802.11-2016
  VENDOR_SPECIFIC = 221,         // See section 9.4.2.26 of IEEE 802.11-2016
};

struct VHTOperationInformation {
  enum ChannelWidth : U8 {
    CHANNEL_WIDTH_20MHZ_40MHZ = 0,
    CHANNEL_WIDTH_80MHZ_160MHZ_80_80MHZ = 1,
    CHANNEL_WIDTH_160MHZ = 2,   // deprecated
    CHANNEL_WIDTH_80_80MHZ = 3, // deprecated
  };
  ChannelWidth channel_width;
  U8 channel_center_frequency_segment_0; // See Table 9-253 of IEEE 802.11-2016
  U8 channel_center_frequency_segment_1;
};

struct VHT_MCS_NSS_Map {
  enum Support : U8 {
    MCS_0_7 = 0,
    MCS_0_8 = 1,
    MCS_0_9 = 2,
    NOT_SUPPORTED = 3,
  };
  Support spatial_streams_1 : 2;
  Support spatial_streams_2 : 2;
  Support spatial_streams_3 : 2;
  Support spatial_streams_4 : 2;
  Support spatial_streams_5 : 2;
  Support spatial_streams_6 : 2;
  Support spatial_streams_7 : 2;
  Support spatial_streams_8 : 2;
};

namespace wmm {

// See section 9.4.1.17 of IEEE 802.11-2016
struct QoS_Info_AP {
  U8 edca_parameter_set_count : 4;
  bool q_ack : 1;
  bool queue_request : 1;
  bool txop_request : 1;
  bool uapsd : 1;
};

enum class AC {
  BE = 0, // Best Effort
  BK = 1, // Background
  VI = 2, // Video
  VO = 3, // Voice
};

struct AC_Parameter {
  U8 aifsn : 4; // Number of slots to defer after a SIFS
  bool acm : 1; // Admission Control Mandatory
  AC aci : 2;
  U8 reserved : 1;
  U8 ecw_min : 4; // CW = 2^ECW - 1
  U8 ecw_max : 4;
  U16 txop_limit; // In units of 32 microseconds. See section 10.22.2.8.
} __attribute__((packed));

} // namespace wmm

using KeyIndex = U8;

struct Netlink {
  GenericNetlink gn;

  Netlink(Status &);

  Vec<Wiphy> GetWiphys(Status &);
  Vec<Interface> GetInterfaces(Status &);
  Regulation GetRegulation(Status &);

  void SetInterfaceType(Interface::Index, Interface::Type, Status &);
  void RegisterFrame(Interface::Index, U16 frame_type, Status &);
  void DelStation(Interface::Index, MAC *, DisconnectReason *, Status &);
  void SetChannel(Interface::Index, U32 frequency_MHz, nl80211_chan_width,
                  U32 center_frequency1_MHz, Status &);
  void StartAP(Interface::Index, Span<> beacon_head, Span<> beacon_tail,
               U32 beacon_interval, U32 dtim_period, StrView ssid,
               nl80211_hidden_ssid, bool privacy, nl80211_auth_type,
               U32 wpa_versions, Span<AuthenticationKeyManagement> akm_suites,
               Span<CipherSuite> pairwise_ciphers, CipherSuite group_cipher,
               Span<> ie, Span<> ie_probe_resp, Span<> ie_assoc_resp,
               bool socket_owner, Status &);
  // Configure BSS parameters.
  //
  // `ht_opmode` is the second and third octet from `HT Operation Information`
  // from 9.4.2.57 of IEEE 802.11-2016.
  //
  // `basic_rates` is a list of BSSBasicRateSet from 9.4.2.3 of IEEE
  // 802.11-2016. For example 0x0c, 0x18, 0x30 for 6, 12, 24 Mbps.
  void SetBSS(Interface::Index, bool cts_protection, bool short_preamble,
              U16 ht_opmode, bool ap_isolate, Span<> basic_rates, Status &);

  void SetMulticastToUnicast(Interface::Index, bool enable, Status &);

  void NewKey(Interface::Index, MAC *, Span<> key_data, CipherSuite, KeyIndex,
              Status &);

  void SetKey(Interface::Index, KeyIndex, bool key_default,
              bool key_default_unicast, bool key_default_multicast, Status &);

  void SetStation(Interface::Index, MAC, Span<nl80211_sta_flags> set_flags,
                  Span<nl80211_sta_flags> clear_flags, Status &);
};

Str ChanWidthToStr(nl80211_chan_width);
Str ExtFeatureToStr(nl80211_ext_feature_index);
Str WoWLANTriggerToStr(nl80211_wowlan_triggers);
Str IftypeToStr(nl80211_iftype);
Str ChannelTypeToStr(nl80211_channel_type);
Str IfaceLimitAttrToStr(nl80211_iface_limit_attrs);
Str IfaceCombinationAttrToStr(nl80211_if_combination_attrs);
Str CipherSuiteToStr(CipherSuite);
Str CmdToStr(U8 cmd);
Str AttrToStr(nl80211_attrs);
Str BandAttrToStr(nl80211_band_attr);
Str BitrateAttrToStr(nl80211_bitrate_attr);
Str FrequencyAttrToStr(nl80211_frequency_attr);
Str BssSelectAttrToStr(nl80211_bss_select_attr);
Str RegRuleAttrToStr(nl80211_reg_rule_attr);
Str WmmRuleToStr(nl80211_wmm_rule);
Str DfsStateToStr(DFS::State);
Str BandToStr(nl80211_band);
Str DFSRegionToStr(nl80211_dfs_regions);

} // namespace maf::nl80211