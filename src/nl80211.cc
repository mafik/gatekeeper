#include "nl80211.hh"

#include "hex.hh"
#include "linux/nl80211.h"

#include "format.hh"
#include "log.hh"
#include "netlink.hh"
#include <string>

namespace maf::nl80211 {

#ifndef NDEBUG
#define NL80211_WARN
#endif

// #define NL80211_DEBUG

Netlink::Netlink(Status &status) : nl("nl80211"sv, NL80211_CMD_MAX, status) {
  if (!OK(status)) {
    return;
  }
}

using Attr = ::maf::Netlink::Attr;
using Attrs = ::maf::Netlink::Attrs;

Str Bitrate::ToStr() const {
  Str ret;
  if (bitrate % 10) {
    ret += f("%d.%d Mbps", bitrate / 10, bitrate % 10);
  } else {
    ret += f("%d Mbps", bitrate / 10);
  }
  if (short_preamble) {
    ret += " (short preamble)";
  }
  return ret;
}

static void ParseBitrate(Bitrate &bitrate, Attr &attr4) {
  for (auto &attr5 : attr4.Unnest()) {
    nl80211_bitrate_attr bitrate_attr = (nl80211_bitrate_attr)attr5.type;
    switch (bitrate_attr) {
    case NL80211_BITRATE_ATTR_RATE:
      bitrate.bitrate = attr5.As<U32>();
      break;
    case NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE:
      bitrate.short_preamble = true;
      break;
    default:
      // Ignore unknown attributes
      break;
    }
  }
}

static void ParseWMMRule(WMMRule &rule, Attr &rule_attrs) {
  for (auto &rule_attr : rule_attrs.Unnest()) {
    nl80211_wmm_rule rule_type = (nl80211_wmm_rule)rule_attr.type;
    switch (rule_type) {
    case NL80211_WMMR_CW_MIN:
      rule.cw_min = rule_attr.As<U16>();
      break;
    case NL80211_WMMR_CW_MAX:
      rule.cw_max = rule_attr.As<U16>();
      break;
    case NL80211_WMMR_AIFSN:
      rule.aifsn = rule_attr.As<U8>();
      break;
    case NL80211_WMMR_TXOP:
      rule.txop = rule_attr.As<U16>();
      break;
    default:
      // Ignore unknown attributes
      break;
    }
  }
}

static void ParseFrequency(Frequency &f, Attr &freq_attrs) {
  for (auto &attr5 : freq_attrs.Unnest()) {
    nl80211_frequency_attr freq_attr = (nl80211_frequency_attr)attr5.type;
    switch (freq_attr) {
    case NL80211_FREQUENCY_ATTR_FREQ:
      f.frequency = attr5.As<U32>();
      break;
    case NL80211_FREQUENCY_ATTR_OFFSET:
      f.offset = attr5.As<U32>();
      break;
    case NL80211_FREQUENCY_ATTR_RADAR:
      f.radar = true;
      break;
    case NL80211_FREQUENCY_ATTR_INDOOR_ONLY:
      f.indoor_only = true;
      break;
    case NL80211_FREQUENCY_ATTR_MAX_TX_POWER:
      f.max_tx_power_100dbm = attr5.As<U32>();
      break;
    case NL80211_FREQUENCY_ATTR_NO_HT40_MINUS:
      f.no_ht40_minus = true;
      break;
    case NL80211_FREQUENCY_ATTR_NO_HT40_PLUS:
      f.no_ht40_plus = true;
      break;
    case NL80211_FREQUENCY_ATTR_DISABLED:
      f.disabled = true;
      break;
    case NL80211_FREQUENCY_ATTR_NO_80MHZ:
      f.no_80mhz = true;
      break;
    case NL80211_FREQUENCY_ATTR_NO_160MHZ:
      f.no_160mhz = true;
      break;
    case NL80211_FREQUENCY_ATTR_DFS_STATE:
      if (!f.dfs.has_value()) {
        f.dfs.emplace();
      }
      f.dfs->state = attr5.As<nl80211_dfs_state>();
      break;
    case NL80211_FREQUENCY_ATTR_DFS_TIME:
      if (!f.dfs.has_value()) {
        f.dfs.emplace();
      }
      f.dfs->time_ms = attr5.As<U32>();
      break;
    case NL80211_FREQUENCY_ATTR_DFS_CAC_TIME:
      if (!f.dfs.has_value()) {
        f.dfs.emplace();
      }
      f.dfs->cac_time_ms = attr5.As<U32>();
      break;
    case NL80211_FREQUENCY_ATTR_WMM:
      for (auto &attr_rule : attr5.Unnest()) {
        WMMRule &rule = f.wmm_rules.emplace_back();
        ParseWMMRule(rule, attr_rule);
      }
      break;
    default:
      // Ignore unknown attributes
      break;
    }
  }
}

static void ParseWiphyBand(Band &band, Attr &band_attrs) {
  for (auto &attr2 : band_attrs.Unnest()) {
    nl80211_band_attr band_attr = (nl80211_band_attr)attr2.type;
    switch (band_attr) {
    case NL80211_BAND_ATTR_RATES:
      band.bitrates.clear();
      for (auto &bitrate_attrs : attr2.Unnest()) {
        Bitrate &bitrate = band.bitrates.emplace_back();
        ParseBitrate(bitrate, bitrate_attrs);
      }
      break;
    case NL80211_BAND_ATTR_FREQS:
      for (auto &attr4 : attr2.Unnest()) {
        if (band.frequencies.size() <= attr4.type) {
          band.frequencies.resize(attr4.type + 1);
        }
        Frequency &freq = band.frequencies[attr4.type];
        ParseFrequency(freq, attr4);
      }
      break;
    case NL80211_BAND_ATTR_HT_MCS_SET:
    case NL80211_BAND_ATTR_HT_CAPA:
    case NL80211_BAND_ATTR_HT_AMPDU_FACTOR:
    case NL80211_BAND_ATTR_HT_AMPDU_DENSITY:
      if (!band.ht.has_value()) {
        band.ht.emplace();
      }
      switch (band_attr) {
      case NL80211_BAND_ATTR_HT_MCS_SET:
        band.ht->mcs_set = attr2.As<Arr<U8, 16>>();
        break;
      case NL80211_BAND_ATTR_HT_CAPA:
        band.ht->capa = attr2.As<U16>();
        break;
      case NL80211_BAND_ATTR_HT_AMPDU_FACTOR:
        band.ht->ampdu_factor = attr2.As<U8>();
        break;
      case NL80211_BAND_ATTR_HT_AMPDU_DENSITY:
        band.ht->ampdu_density = attr2.As<U8>();
        break;
      default:
        break;
      }
      break;
    case NL80211_BAND_ATTR_VHT_MCS_SET:
    case NL80211_BAND_ATTR_VHT_CAPA:
      if (!band.vht.has_value()) {
        band.vht.emplace();
      }
      switch (band_attr) {
      case NL80211_BAND_ATTR_VHT_MCS_SET:
        band.vht->mcs_set = attr2.As<Arr<U8, 8>>();
        break;
      case NL80211_BAND_ATTR_VHT_CAPA:
        band.vht->capa = attr2.As<U32>();
        break;
      default:
        break;
      }
      break;
    default:
      // Ignore unknown attributes
      break;
    }
  }
}

static void ParseWiphyBands(Wiphy &wiphy, Attr &attr) {
  // For each band:
  // - one message with every supported rate for this band
  // - N messages - one for each supported channel (frequency)
  for (auto &attr2 : attr.Unnest()) {
    Band *band = nullptr;
    for (auto &known : wiphy.bands) {
      if (known.nl80211_band == attr2.type) {
        band = &known;
        break;
      }
    }
    if (band == nullptr) {
      band = &wiphy.bands.emplace_back();
      band->nl80211_band = (nl80211_band)attr2.type;
    }
    ParseWiphyBand(*band, attr2);
  }
}

static void ParseInterfaceCombination(InterfaceCombination &ic, Attr &attr) {
  for (auto &attr2 : attr.Unnest()) {
    nl80211_if_combination_attrs attr_type =
        (nl80211_if_combination_attrs)attr2.type;
    switch (attr_type) {
    case NL80211_IFACE_COMB_LIMITS:
      for (auto &attr3 : attr2.Unnest()) {
        InterfaceLimit &limit = ic.limits.emplace_back();
        for (auto &attr4 : attr3.Unnest()) {
          nl80211_iface_limit_attrs limit_attr =
              (nl80211_iface_limit_attrs)attr4.type;
          switch (limit_attr) {
          case NL80211_IFACE_LIMIT_MAX:
            limit.max = attr4.As<U32>();
            break;
          case NL80211_IFACE_LIMIT_TYPES:
            for (auto &attr5 : attr4.Unnest()) {
              limit.iftypes.push_back((nl80211_iftype)attr5.type);
            }
            break;
          default:
            // Ignore unknown attributes
            break;
          }
        }
      }
      break;
    case NL80211_IFACE_COMB_MAXNUM:
      ic.maxnum = attr2.As<U32>();
      break;
    case NL80211_IFACE_COMB_STA_AP_BI_MATCH:
      ic.sta_ap_bi_match = true;
      break;
    case NL80211_IFACE_COMB_NUM_CHANNELS:
      ic.num_channels = attr2.As<U32>();
      break;
    case NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS:
      ic.radar_detect_widths = attr2.As<U32>();
      break;
    case NL80211_IFACE_COMB_RADAR_DETECT_REGIONS:
      ic.radar_detect_regions = attr2.As<U32>();
      break;
    case NL80211_IFACE_COMB_BI_MIN_GCD:
      ic.beacon_interval_min_gcd = attr2.As<U32>();
      break;
    default:
      // Ignore unknown attributes
      break;
    }
  }
}

static void ParseWiphyDump(Vec<Wiphy> &wiphys, Attrs attrs) {
  Wiphy *wiphy = nullptr;
  for (auto &attr : attrs) {
    switch (attr.type) {
    case NL80211_ATTR_WIPHY: {
      int index = attr.As<int>();
      for (auto &known : wiphys) {
        if (known.index == index) {
          wiphy = &known;
          break;
        }
      }
      if (wiphy == nullptr) {
        wiphy = &wiphys.emplace_back();
        wiphy->index = index;
      }
      break;
    }
    case NL80211_ATTR_WIPHY_NAME:
      wiphy->name = attr.Span().ToStr();
      if (wiphy->name.ends_with('\0')) {
        wiphy->name.pop_back();
      }
      break;
    case NL80211_ATTR_GENERATION:
      // Could be used to detect changes in the wiphy dump.
      // We don't seem to need it.
      break;
    case NL80211_ATTR_WIPHY_RETRY_SHORT:
      wiphy->retry_short_limit = attr.As<U8>();
      break;
    case NL80211_ATTR_WIPHY_RETRY_LONG:
      wiphy->retry_long_limit = attr.As<U8>();
      break;
    case NL80211_ATTR_WIPHY_FRAG_THRESHOLD: {
      U32 frag_threshold = attr.As<U32>();
      if (frag_threshold != 0xffffffff) {
        wiphy->fragmentation_threshold = frag_threshold;
      }
      break;
    }
    case NL80211_ATTR_WIPHY_RTS_THRESHOLD: {
      U32 rts_threshold = attr.As<U32>();
      if (rts_threshold != 0xffffffff) {
        wiphy->rts_threshold = rts_threshold;
      }
      break;
    }
    case NL80211_ATTR_WIPHY_COVERAGE_CLASS:
      wiphy->coverage_class = attr.As<U8>();
      break;
    case NL80211_ATTR_MAX_NUM_SCAN_SSIDS:
      wiphy->max_scan_ssids = attr.As<U8>();
      break;
    case NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS:
      wiphy->max_sched_scan_ssids = attr.As<U8>();
      break;
    case NL80211_ATTR_MAX_SCAN_IE_LEN:
      wiphy->max_scan_ie_len = attr.As<U16>();
      break;
    case NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN:
      wiphy->max_sched_scan_ie_len = attr.As<U16>();
      break;
    case NL80211_ATTR_MAX_MATCH_SETS:
      wiphy->max_sched_scan_match_sets = attr.As<U8>();
      break;
    case NL80211_ATTR_ROAM_SUPPORT:
      wiphy->roam_support = true;
      break;
    case NL80211_ATTR_CIPHER_SUITES: {
      Span<> byte_span = attr.Span();
      Span<CipherSuite> ciphers_span((CipherSuite *)byte_span.data(),
                                     byte_span.size() / sizeof(U32));
      wiphy->cipher_suites = std::set(ciphers_span.begin(), ciphers_span.end());
      break;
    }
    case NL80211_ATTR_MAX_NUM_PMKIDS:
      wiphy->max_num_pmkids = attr.As<U8>();
      break;
    case NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX:
      wiphy->antenna_avail_tx = attr.As<U32>();
      break;
    case NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX:
      wiphy->antenna_avail_rx = attr.As<U32>();
      break;
    case NL80211_ATTR_SUPPORTED_IFTYPES:
      for (auto &attr2 : attr.Unnest()) {
        wiphy->iftypes.insert((nl80211_iftype)attr2.type);
      }
      break;
    case NL80211_ATTR_SOFTWARE_IFTYPES:
      for (auto &attr2 : attr.Unnest()) {
        wiphy->software_iftypes.insert((nl80211_iftype)attr2.type);
      }
      break;
    case NL80211_ATTR_SUPPORTED_COMMANDS:
      for (auto &attr2 : attr.Unnest()) {
        wiphy->supported_commands.insert(attr2.As<nl80211_commands>());
      }
      break;
    case NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION:
      wiphy->max_remain_on_channel_duration = attr.As<U32>();
      break;
    case NL80211_ATTR_OFFCHANNEL_TX_OK:
      wiphy->offchannel_tx_ok = true;
      break;
    case NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED:
      for (auto &attr2 : attr.Unnest()) {
        wiphy->wowlan_triggers.insert((nl80211_wowlan_triggers)attr2.type);
        if (attr2.type == NL80211_WOWLAN_TRIG_PKT_PATTERN) {
          wiphy->wowlan_pattern_support = attr2.As<nl80211_pattern_support>();
        }
      }
      break;
    case NL80211_ATTR_INTERFACE_COMBINATIONS:
      for (auto &attr2 : attr.Unnest()) {
        InterfaceCombination &ic = wiphy->interface_combinations.emplace_back();
        ParseInterfaceCombination(ic, attr2);
      }
      break;
    case NL80211_ATTR_DEVICE_AP_SME:
      wiphy->ap_sme = true;
      break;
    case NL80211_ATTR_FEATURE_FLAGS:
      wiphy->feature_flags = attr.As<U32>();
      break;
    case NL80211_ATTR_TX_FRAME_TYPES:
      LOG << "    NL80211_ATTR_TX_FRAME_TYPES:";
      for (auto &attr2 : attr.Unnest()) {
        wiphy->tx_frame_types.insert(attr2.type);
        LOG << "      " << attr2.type << ": " << BytesToHex(attr2.Span());
      }
      break;
    case NL80211_ATTR_RX_FRAME_TYPES:
      LOG << "    NL80211_ATTR_RX_FRAME_TYPES:";
      for (auto &attr2 : attr.Unnest()) {
        wiphy->rx_frame_types.insert(attr2.type);
        LOG << "      " << attr2.type << ": " << BytesToHex(attr2.Span());
      }
      break;
    case NL80211_ATTR_WIPHY_BANDS:
      ParseWiphyBands(*wiphy, attr);
      break;
    case NL80211_ATTR_BSS_SELECT:
      for (auto &attr2 : attr.Unnest()) {
        wiphy->bss_select.push_back((nl80211_bss_select_attr)attr2.type);
      }
      break;
    case NL80211_ATTR_BANDS:
      wiphy->nan_bands_bitmask = attr.As<U32>();
      break;
    default:
      LOG << "  " << nl80211::AttrToStr(attr.type) << "(" << attr.Span().size()
          << " bytes): " << BytesToHex(attr.Span());
      break;
    }
  }
}

Vec<Wiphy> Netlink::GetWiphys(Status &status) {
  Vec<Wiphy> ret;

  // Required to get full wiphy description.
  Attr attr_split_wiphy_dump(sizeof(Attr), NL80211_ATTR_SPLIT_WIPHY_DUMP);
  nl.Dump(
      NL80211_CMD_GET_WIPHY, &attr_split_wiphy_dump,
      [&](Span<>, Attrs attrs) { ParseWiphyDump(ret, attrs); }, status);
  if (!OK(status)) {
    return {};
  }
  return ret;
}

Str DfsStateToStrShort(DFS::State state) {
  switch (state) {
  case NL80211_DFS_USABLE:
    return "CAC required";
  case NL80211_DFS_UNAVAILABLE:
    return "CAC failed";
  case NL80211_DFS_AVAILABLE:
    return "available";
  default:
    return "??";
  }
}

static Str CipherSuiteToStrShort(CipherSuite cipher) {
  switch (cipher) {
  case CipherSuite::FallbackToGroup:
    return "group cipher";
  case CipherSuite::WEP40:
    return "WEP-40";
  case CipherSuite::TKIP:
    return "TKIP";
  case CipherSuite::CCMP:
    return "CCMP";
  case CipherSuite::WEP104:
    return "WEP-104";
  case CipherSuite::BIP:
    return "BIP";
  default:
    return f("%08x", (U32)cipher);
  }
}

static Str IftypeToStrShort(nl80211_iftype iftype) {
  switch (iftype) {
  case NL80211_IFTYPE_UNSPECIFIED:
    return "unspecified";
  case NL80211_IFTYPE_ADHOC:
    return "Ad-hoc";
  case NL80211_IFTYPE_STATION:
    return "Station";
  case NL80211_IFTYPE_AP:
    return "AP";
  case NL80211_IFTYPE_AP_VLAN:
    return "AP VLAN";
  case NL80211_IFTYPE_WDS:
    return "WDS";
  case NL80211_IFTYPE_MONITOR:
    return "Monitor";
  case NL80211_IFTYPE_MESH_POINT:
    return "Mesh point";
  case NL80211_IFTYPE_P2P_CLIENT:
    return "P2P client";
  case NL80211_IFTYPE_P2P_GO:
    return "P2P group owner";
  case NL80211_IFTYPE_P2P_DEVICE:
    return "P2P device";
  case NL80211_IFTYPE_OCB:
    return "OCB";
  case NL80211_IFTYPE_NAN:
    return "NAN";
  default:
    return IftypeToStr(iftype);
  }
}

Str Frequency::Describe() const {
  Str ret;
  ret += std::to_string(frequency) + " MHz";
  if (offset) {
    ret += f(" (+%d kHz)", offset);
  }
  ret += f(" %.0f", max_tx_power_100dbm / 100.0) + " dBm";
  if (disabled) {
    ret += " [disabled]";
  }
  if (no_ir) {
    ret += " [no radiation]";
  }
  if (radar) {
    if (dfs.has_value()) {
      ret += f(" [%s, scan time = %d s]",
               DfsStateToStrShort(dfs->state).c_str(), dfs->cac_time_ms / 1000);
    } else {
      ret += " [radar]";
    }
  }
  if (indoor_only) {
    ret += " [indoor]";
  }
  if (no_ht40_minus) {
    ret += " [no HT40-]";
  }
  if (no_ht40_plus) {
    ret += " [no HT40+]";
  }
  if (no_80mhz) {
    ret += " [no 80 MHz]";
  }
  if (no_160mhz) {
    ret += " [no 160 MHz]";
  }
  if (!wmm_rules.empty()) {
    ret += " [WMM]";
  }
  ret += '\n';
  return ret;
}

Str Band::Describe() const {
  Str ret;
  ret += "Band ";
  switch (nl80211_band) {
  case NL80211_BAND_2GHZ:
    ret += "2.4 GHz";
    break;
  case NL80211_BAND_5GHZ:
    ret += "5 GHz";
    break;
  case NL80211_BAND_60GHZ:
    ret += "60 GHz";
    break;
  case NL80211_BAND_6GHZ:
    ret += "6 GHz";
    break;
  case NL80211_BAND_S1GHZ:
    ret += "900 MHz";
    break;
  default:
    ret += BandToStr(nl80211_band);
    break;
  }
  ret += ":\n";
  Str body;
  body += "Bitrates: ";
  bool first = false;
  for (auto &bitrate : bitrates) {
    if (!first) {
      first = true;
    } else {
      body += ", ";
    }
    body += bitrate.ToStr();
  }
  body += "\n";
  body += "Frequencies:\n";
  for (auto &freq : frequencies) {
    body += Indent(freq.Describe());
  }
  // TODO...
  ret += Indent(body);
  return ret;
}

Str InterfaceCombination::Describe() const {
  Str ret = f("%d interfaces on %d channel", maxnum, num_channels);
  if (num_channels > 1) {
    ret += "s";
  }
  for (auto &limit : limits) {
    ret += ", (";
    ret += std::to_string(limit.max);
    ret += " ";
    bool first = false;
    for (auto iftype : limit.iftypes) {
      if (!first) {
        first = true;
      } else {
        ret += " / ";
      }
      ret += IftypeToStrShort(iftype);
    }
    ret += ")";
  }
  return ret;
}

Str Wiphy::Describe() const {
  Str ret;
  ret += f("Wiphy %d \"%s\":\n", index, name.c_str());
  Str body;
  body += "Bands:\n";
  for (auto &band : bands) {
    auto band_desc = band.Describe();
    body += Indent(band_desc);
  }
  body += "Retry limits: " + std::to_string(retry_short_limit) + " short, " +
          std::to_string(retry_long_limit) + " long\n";
  if (fragmentation_threshold.has_value()) {
    body +=
        "Fragmentation threshold: " + std::to_string(*fragmentation_threshold) +
        "\n";
  }
  if (rts_threshold.has_value()) {
    body += "RTS threshold: " + std::to_string(*rts_threshold) + "\n";
  }
  body += "Coverage class: " + std::to_string(coverage_class) + "\n";
  body += "Scan limits: max " + std::to_string(max_scan_ssids) + " SSIDs, " +
          std::to_string(max_scan_ie_len) + " bytes max IEs length\n";
  if (max_sched_scan_ssids) {
    body += "Scheduled scans: max " + std::to_string(max_sched_scan_ssids) +
            " SSIDs, " + std::to_string(max_sched_scan_ie_len) +
            " bytes max IEs length, " +
            std::to_string(max_sched_scan_match_sets) + " match sets\n";
  }
  if (roam_support) {
    body += "Roaming supported\n";
  }
  body += "Cipher suites:";
  {
    bool first = true;
    for (auto cipher : cipher_suites) {
      if (first) {
        first = false;
      } else {
        body += ",";
      }
      body += " " + CipherSuiteToStrShort(cipher);
    }
  }
  body += "\n";
  body += "Max PMKIDs: " + std::to_string(max_num_pmkids) + "\n";
  if (antenna_avail_tx) {
    body += "Configurable TX antennas:";
    for (int i = 0; i < 32; ++i) {
      if (antenna_avail_tx & (1 << i)) {
        body += " " + std::to_string(i);
      }
    }
    body += "\n";
  }
  if (antenna_avail_rx) {
    body += "Configurable RX antennas:";
    for (int i = 0; i < 32; ++i) {
      if (antenna_avail_rx & (1 << i)) {
        body += " " + std::to_string(i);
      }
    }
    body += "\n";
  }
  {
    body += "Supported interface types:";
    bool first = false;
    for (auto iftype : iftypes) {
      if (!first) {
        first = true;
      } else {
        body += ",";
      }
      body += " " + IftypeToStrShort(iftype);
    }
    body += "\n";
  }
  {
    body += "Supported software interface types:";
    bool first = false;
    for (auto iftype : software_iftypes) {
      if (!first) {
        first = true;
      } else {
        body += ",";
      }
      body += " " + IftypeToStrShort(iftype);
    }
    body += "\n";
  }
  {
    body += "Supported commands:";
    bool first = false;
    for (auto cmd : supported_commands) {
      if (!first) {
        first = true;
      } else {
        body += ",";
      }
      body += " " + CmdToStr(cmd);
    }
    body += "\n";
  }
  body += "Max remain-on-channel duration: " +
          std::to_string(max_remain_on_channel_duration) + " ms\n";
  body += "Off-channel TX ok: " + std::to_string(offchannel_tx_ok) + "\n";
  if (!wowlan_triggers.empty()) {
    body += "WoWLAN triggers:";
    for (auto trigger : wowlan_triggers) {
      body += " " + WoWLANTriggerToStr(trigger);
    }
    body += "\n";
    if (wowlan_pattern_support.has_value()) {
      body += "WoWLAN pattern support: max " +
              std::to_string(wowlan_pattern_support->max_patterns) +
              " patterns, length " +
              std::to_string(wowlan_pattern_support->min_pattern_len) + ".." +
              std::to_string(wowlan_pattern_support->max_pattern_len) +
              ", max pkt offset " +
              std::to_string(wowlan_pattern_support->max_pkt_offset) + "\n";
    }
  }
  body += "Interface combinations:\n";
  for (auto &ic : interface_combinations) {
    body += Indent(ic.Describe()) + "\n";
  }
  body += "AP Station Management Entity: ";
  body += (ap_sme ? "yes" : "no");
  body += "\n";
  body += "Features:";
  if (feature_flags & NL80211_FEATURE_SK_TX_STATUS) {
    body += " SK_TX_STATUS";
  }
  if (feature_flags & NL80211_FEATURE_HT_IBSS) {
    body += " HT_IBSS";
  }
  if (feature_flags & NL80211_FEATURE_INACTIVITY_TIMER) {
    body += " INACTIVITY_TIMER";
  }
  if (feature_flags & NL80211_FEATURE_CELL_BASE_REG_HINTS) {
    body += " CELL_BASE_REG_HINTS";
  }
  if (feature_flags & NL80211_FEATURE_P2P_DEVICE_NEEDS_CHANNEL) {
    body += " P2P_DEVICE_NEEDS_CHANNEL";
  }
  if (feature_flags & NL80211_FEATURE_SAE) {
    body += " SAE";
  }
  if (feature_flags & NL80211_FEATURE_LOW_PRIORITY_SCAN) {
    body += " LOW_PRIORITY_SCAN";
  }
  if (feature_flags & NL80211_FEATURE_SCAN_FLUSH) {
    body += " SCAN_FLUSH";
  }
  if (feature_flags & NL80211_FEATURE_AP_SCAN) {
    body += " AP_SCAN";
  }
  if (feature_flags & NL80211_FEATURE_VIF_TXPOWER) {
    body += " VIF_TXPOWER";
  }
  if (feature_flags & NL80211_FEATURE_NEED_OBSS_SCAN) {
    body += " NEED_OBSS_SCAN";
  }
  if (feature_flags & NL80211_FEATURE_P2P_GO_CTWIN) {
    body += " P2P_GO_CTWIN";
  }
  if (feature_flags & NL80211_FEATURE_P2P_GO_OPPPS) {
    body += " P2P_GO_OPPPS";
  }
  if (feature_flags & NL80211_FEATURE_ADVERTISE_CHAN_LIMITS) {
    body += " ADVERTISE_CHAN_LIMITS";
  }
  if (feature_flags & NL80211_FEATURE_FULL_AP_CLIENT_STATE) {
    body += " FULL_AP_CLIENT_STATE";
  }
  if (feature_flags & NL80211_FEATURE_USERSPACE_MPM) {
    body += " USERSPACE_MPM";
  }
  if (feature_flags & NL80211_FEATURE_ACTIVE_MONITOR) {
    body += " ACTIVE_MONITOR";
  }
  if (feature_flags & NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE) {
    body += " AP_MODE_CHAN_WIDTH_CHANGE";
  }
  if (feature_flags & NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES) {
    body += " DS_PARAM_SET_IE_IN_PROBES";
  }
  if (feature_flags & NL80211_FEATURE_WFA_TPC_IE_IN_PROBES) {
    body += " WFA_TPC_IE_IN_PROBES";
  }
  if (feature_flags & NL80211_FEATURE_QUIET) {
    body += " QUIET";
  }
  if (feature_flags & NL80211_FEATURE_TX_POWER_INSERTION) {
    body += " TX_POWER_INSERTION";
  }
  if (feature_flags & NL80211_FEATURE_ACKTO_ESTIMATION) {
    body += " ACKTO_ESTIMATION";
  }
  if (feature_flags & NL80211_FEATURE_STATIC_SMPS) {
    body += " STATIC_SMPS";
  }
  if (feature_flags & NL80211_FEATURE_DYNAMIC_SMPS) {
    body += " DYNAMIC_SMPS";
  }
  if (feature_flags & NL80211_FEATURE_SUPPORTS_WMM_ADMISSION) {
    body += " SUPPORTS_WMM_ADMISSION";
  }
  if (feature_flags & NL80211_FEATURE_MAC_ON_CREATE) {
    body += " MAC_ON_CREATE";
  }
  if (feature_flags & NL80211_FEATURE_TDLS_CHANNEL_SWITCH) {
    body += " TDLS_CHANNEL_SWITCH";
  }
  if (feature_flags & NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR) {
    body += " SCAN_RANDOM_MAC_ADDR";
  }
  if (feature_flags & NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR) {
    body += " SCHED_SCAN_RANDOM_MAC_ADDR";
  }
  if (feature_flags & NL80211_FEATURE_ND_RANDOM_MAC_ADDR) {
    body += " ND_RANDOM_MAC_ADDR";
  }
  body += "\n";

  body += "TX frame types:";
  for (auto tx : tx_frame_types) {
    body += f(" %04hx", tx);
  }
  body += "\n";
  body += "RX frame types:";
  for (auto rx : rx_frame_types) {
    body += f(" %04hx", rx);
  }
  body += "\n";

  body += "BSS select strategies:";
  if (bss_select.empty()) {
    body += " none";
  } else {
    bool first;
    for (auto strategy : bss_select) {
      if (!first) {
        first = true;
        body += " ";
      } else {
        body += ", ";
      }
      switch (strategy) {
      case NL80211_BSS_SELECT_ATTR_RSSI:
        body += "best RSSI";
        break;
      case NL80211_BSS_SELECT_ATTR_BAND_PREF:
        body += "band preference";
        break;
      case NL80211_BSS_SELECT_ATTR_RSSI_ADJUST:
        body += "best band-adjusted RSSI";
        break;
      default:
        body += BssSelectAttrToStr(strategy);
        break;
      }
    }
  }
  body += "\n";
  body += "NAN bands:";
  if (nan_bands_bitmask) {
    for (int band_i = 0; band_i < NUM_NL80211_BANDS; ++band_i) {
      nl80211_band band = (nl80211_band)band_i;
      if (nan_bands_bitmask & (1 << band_i)) {
        body += " " + BandToStr(band);
      }
    }
  } else {
    body += " any";
  }
  body += "\n";

  ret += Indent(body);
  return ret;
}

#define CASE(name)                                                             \
  case name:                                                                   \
    return #name

Str WoWLANTriggerToStr(nl80211_wowlan_triggers trigger) {
  switch (trigger) {
    CASE(NL80211_WOWLAN_TRIG_ANY);
    CASE(NL80211_WOWLAN_TRIG_DISCONNECT);
    CASE(NL80211_WOWLAN_TRIG_MAGIC_PKT);
    CASE(NL80211_WOWLAN_TRIG_PKT_PATTERN);
    CASE(NL80211_WOWLAN_TRIG_GTK_REKEY_SUPPORTED);
    CASE(NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE);
    CASE(NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST);
    CASE(NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE);
    CASE(NL80211_WOWLAN_TRIG_RFKILL_RELEASE);
    CASE(NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211);
    CASE(NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211_LEN);
    CASE(NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023);
    CASE(NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023_LEN);
    CASE(NL80211_WOWLAN_TRIG_TCP_CONNECTION);
    CASE(NL80211_WOWLAN_TRIG_WAKEUP_TCP_MATCH);
    CASE(NL80211_WOWLAN_TRIG_WAKEUP_TCP_CONNLOST);
    CASE(NL80211_WOWLAN_TRIG_WAKEUP_TCP_NOMORETOKENS);
    CASE(NL80211_WOWLAN_TRIG_NET_DETECT);
    CASE(NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS);
  default:
    return f("NL80211_WOWLAN_TRIG_%d", (int)trigger);
  }
}

Str IftypeToStr(nl80211_iftype iftype) {
  switch (iftype) {
    CASE(NL80211_IFTYPE_UNSPECIFIED);
    CASE(NL80211_IFTYPE_ADHOC);
    CASE(NL80211_IFTYPE_STATION);
    CASE(NL80211_IFTYPE_AP);
    CASE(NL80211_IFTYPE_AP_VLAN);
    CASE(NL80211_IFTYPE_WDS);
    CASE(NL80211_IFTYPE_MONITOR);
    CASE(NL80211_IFTYPE_MESH_POINT);
    CASE(NL80211_IFTYPE_P2P_CLIENT);
    CASE(NL80211_IFTYPE_P2P_GO);
    CASE(NL80211_IFTYPE_P2P_DEVICE);
    CASE(NL80211_IFTYPE_OCB);
    CASE(NL80211_IFTYPE_NAN);
  default:
    return f("NL80211_IFTYPE_%d", (int)iftype);
  }
}

Str CipherSuiteToStr(CipherSuite cipher) {
  switch (cipher) {
    CASE(CipherSuite::FallbackToGroup);
    CASE(CipherSuite::WEP40);
    CASE(CipherSuite::TKIP);
    CASE(CipherSuite::CCMP);
    CASE(CipherSuite::WEP104);
    CASE(CipherSuite::BIP);
  default:
    return f("CipherSuite::CIPHER_%u", (U32)cipher);
  }
}

Str CmdToStr(U8 cmd) {
  switch (cmd) {
    CASE(NL80211_CMD_UNSPEC);
    CASE(NL80211_CMD_GET_WIPHY);
    CASE(NL80211_CMD_SET_WIPHY);
    CASE(NL80211_CMD_NEW_WIPHY);
    CASE(NL80211_CMD_DEL_WIPHY);
    CASE(NL80211_CMD_GET_INTERFACE);
    CASE(NL80211_CMD_SET_INTERFACE);
    CASE(NL80211_CMD_NEW_INTERFACE);
    CASE(NL80211_CMD_DEL_INTERFACE);
    CASE(NL80211_CMD_GET_KEY);
    CASE(NL80211_CMD_SET_KEY);
    CASE(NL80211_CMD_NEW_KEY);
    CASE(NL80211_CMD_DEL_KEY);
    CASE(NL80211_CMD_GET_BEACON);
    CASE(NL80211_CMD_SET_BEACON);
    CASE(NL80211_CMD_START_AP);
    CASE(NL80211_CMD_STOP_AP);
    CASE(NL80211_CMD_GET_STATION);
    CASE(NL80211_CMD_SET_STATION);
    CASE(NL80211_CMD_NEW_STATION);
    CASE(NL80211_CMD_DEL_STATION);
    CASE(NL80211_CMD_GET_MPATH);
    CASE(NL80211_CMD_SET_MPATH);
    CASE(NL80211_CMD_NEW_MPATH);
    CASE(NL80211_CMD_DEL_MPATH);
    CASE(NL80211_CMD_SET_BSS);
    CASE(NL80211_CMD_SET_REG);
    CASE(NL80211_CMD_REQ_SET_REG);
    CASE(NL80211_CMD_GET_MESH_CONFIG);
    CASE(NL80211_CMD_SET_MESH_CONFIG);
    CASE(NL80211_CMD_SET_MGMT_EXTRA_IE);
    CASE(NL80211_CMD_GET_REG);
    CASE(NL80211_CMD_GET_SCAN);
    CASE(NL80211_CMD_TRIGGER_SCAN);
    CASE(NL80211_CMD_NEW_SCAN_RESULTS);
    CASE(NL80211_CMD_SCAN_ABORTED);
    CASE(NL80211_CMD_REG_CHANGE);
    CASE(NL80211_CMD_AUTHENTICATE);
    CASE(NL80211_CMD_ASSOCIATE);
    CASE(NL80211_CMD_DEAUTHENTICATE);
    CASE(NL80211_CMD_DISASSOCIATE);
    CASE(NL80211_CMD_MICHAEL_MIC_FAILURE);
    CASE(NL80211_CMD_REG_BEACON_HINT);
    CASE(NL80211_CMD_JOIN_IBSS);
    CASE(NL80211_CMD_LEAVE_IBSS);
    CASE(NL80211_CMD_TESTMODE);
    CASE(NL80211_CMD_CONNECT);
    CASE(NL80211_CMD_ROAM);
    CASE(NL80211_CMD_DISCONNECT);
    CASE(NL80211_CMD_SET_WIPHY_NETNS);
    CASE(NL80211_CMD_GET_SURVEY);
    CASE(NL80211_CMD_NEW_SURVEY_RESULTS);
    CASE(NL80211_CMD_SET_PMKSA);
    CASE(NL80211_CMD_DEL_PMKSA);
    CASE(NL80211_CMD_FLUSH_PMKSA);
    CASE(NL80211_CMD_REMAIN_ON_CHANNEL);
    CASE(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL);
    CASE(NL80211_CMD_SET_TX_BITRATE_MASK);
    CASE(NL80211_CMD_REGISTER_FRAME);
    CASE(NL80211_CMD_FRAME);
    CASE(NL80211_CMD_FRAME_TX_STATUS);
    CASE(NL80211_CMD_SET_POWER_SAVE);
    CASE(NL80211_CMD_GET_POWER_SAVE);
    CASE(NL80211_CMD_SET_CQM);
    CASE(NL80211_CMD_NOTIFY_CQM);
    CASE(NL80211_CMD_SET_CHANNEL);
    CASE(NL80211_CMD_SET_WDS_PEER);
    CASE(NL80211_CMD_FRAME_WAIT_CANCEL);
    CASE(NL80211_CMD_JOIN_MESH);
    CASE(NL80211_CMD_LEAVE_MESH);
    CASE(NL80211_CMD_UNPROT_DEAUTHENTICATE);
    CASE(NL80211_CMD_UNPROT_DISASSOCIATE);
    CASE(NL80211_CMD_NEW_PEER_CANDIDATE);
    CASE(NL80211_CMD_GET_WOWLAN);
    CASE(NL80211_CMD_SET_WOWLAN);
    CASE(NL80211_CMD_START_SCHED_SCAN);
    CASE(NL80211_CMD_STOP_SCHED_SCAN);
    CASE(NL80211_CMD_SCHED_SCAN_RESULTS);
    CASE(NL80211_CMD_SCHED_SCAN_STOPPED);
    CASE(NL80211_CMD_SET_REKEY_OFFLOAD);
    CASE(NL80211_CMD_PMKSA_CANDIDATE);
    CASE(NL80211_CMD_TDLS_OPER);
    CASE(NL80211_CMD_TDLS_MGMT);
    CASE(NL80211_CMD_UNEXPECTED_FRAME);
    CASE(NL80211_CMD_PROBE_CLIENT);
    CASE(NL80211_CMD_REGISTER_BEACONS);
    CASE(NL80211_CMD_UNEXPECTED_4ADDR_FRAME);
    CASE(NL80211_CMD_SET_NOACK_MAP);
    CASE(NL80211_CMD_CH_SWITCH_NOTIFY);
    CASE(NL80211_CMD_START_P2P_DEVICE);
    CASE(NL80211_CMD_STOP_P2P_DEVICE);
    CASE(NL80211_CMD_CONN_FAILED);
    CASE(NL80211_CMD_SET_MCAST_RATE);
    CASE(NL80211_CMD_SET_MAC_ACL);
    CASE(NL80211_CMD_RADAR_DETECT);
    CASE(NL80211_CMD_GET_PROTOCOL_FEATURES);
    CASE(NL80211_CMD_UPDATE_FT_IES);
    CASE(NL80211_CMD_FT_EVENT);
    CASE(NL80211_CMD_CRIT_PROTOCOL_START);
    CASE(NL80211_CMD_CRIT_PROTOCOL_STOP);
    CASE(NL80211_CMD_GET_COALESCE);
    CASE(NL80211_CMD_SET_COALESCE);
    CASE(NL80211_CMD_CHANNEL_SWITCH);
    CASE(NL80211_CMD_VENDOR);
    CASE(NL80211_CMD_SET_QOS_MAP);
    CASE(NL80211_CMD_ADD_TX_TS);
    CASE(NL80211_CMD_DEL_TX_TS);
    CASE(NL80211_CMD_GET_MPP);
    CASE(NL80211_CMD_JOIN_OCB);
    CASE(NL80211_CMD_LEAVE_OCB);
    CASE(NL80211_CMD_CH_SWITCH_STARTED_NOTIFY);
    CASE(NL80211_CMD_TDLS_CHANNEL_SWITCH);
    CASE(NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH);
    CASE(NL80211_CMD_WIPHY_REG_CHANGE);
    CASE(NL80211_CMD_ABORT_SCAN);
    CASE(NL80211_CMD_START_NAN);
    CASE(NL80211_CMD_STOP_NAN);
    CASE(NL80211_CMD_ADD_NAN_FUNCTION);
    CASE(NL80211_CMD_DEL_NAN_FUNCTION);
    CASE(NL80211_CMD_CHANGE_NAN_CONFIG);
    CASE(NL80211_CMD_NAN_MATCH);
    CASE(NL80211_CMD_SET_MULTICAST_TO_UNICAST);
    CASE(NL80211_CMD_UPDATE_CONNECT_PARAMS);
    CASE(NL80211_CMD_SET_PMK);
    CASE(NL80211_CMD_DEL_PMK);
    CASE(NL80211_CMD_PORT_AUTHORIZED);
    CASE(NL80211_CMD_RELOAD_REGDB);
    CASE(NL80211_CMD_EXTERNAL_AUTH);
    CASE(NL80211_CMD_STA_OPMODE_CHANGED);
    CASE(NL80211_CMD_CONTROL_PORT_FRAME);
    CASE(NL80211_CMD_GET_FTM_RESPONDER_STATS);
    CASE(NL80211_CMD_PEER_MEASUREMENT_START);
    CASE(NL80211_CMD_PEER_MEASUREMENT_RESULT);
    CASE(NL80211_CMD_PEER_MEASUREMENT_COMPLETE);
    CASE(NL80211_CMD_NOTIFY_RADAR);
    CASE(NL80211_CMD_UPDATE_OWE_INFO);
    CASE(NL80211_CMD_PROBE_MESH_LINK);
    CASE(NL80211_CMD_SET_TID_CONFIG);
    CASE(NL80211_CMD_UNPROT_BEACON);
    CASE(NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS);
    CASE(NL80211_CMD_SET_SAR_SPECS);
    CASE(NL80211_CMD_OBSS_COLOR_COLLISION);
    CASE(NL80211_CMD_COLOR_CHANGE_REQUEST);
    CASE(NL80211_CMD_COLOR_CHANGE_STARTED);
    CASE(NL80211_CMD_COLOR_CHANGE_ABORTED);
    CASE(NL80211_CMD_COLOR_CHANGE_COMPLETED);
  default:
    return f("NL80211_CMD_%d", cmd);
  }
}

Str AttrToStr(U16 attr) {
  switch (attr) {
    CASE(NL80211_ATTR_UNSPEC);
    CASE(NL80211_ATTR_WIPHY);
    CASE(NL80211_ATTR_WIPHY_NAME);
    CASE(NL80211_ATTR_IFINDEX);
    CASE(NL80211_ATTR_IFNAME);
    CASE(NL80211_ATTR_IFTYPE);
    CASE(NL80211_ATTR_MAC);
    CASE(NL80211_ATTR_KEY_DATA);
    CASE(NL80211_ATTR_KEY_IDX);
    CASE(NL80211_ATTR_KEY_CIPHER);
    CASE(NL80211_ATTR_KEY_SEQ);
    CASE(NL80211_ATTR_KEY_DEFAULT);
    CASE(NL80211_ATTR_BEACON_INTERVAL);
    CASE(NL80211_ATTR_DTIM_PERIOD);
    CASE(NL80211_ATTR_BEACON_HEAD);
    CASE(NL80211_ATTR_BEACON_TAIL);
    CASE(NL80211_ATTR_STA_AID);
    CASE(NL80211_ATTR_STA_FLAGS);
    CASE(NL80211_ATTR_STA_LISTEN_INTERVAL);
    CASE(NL80211_ATTR_STA_SUPPORTED_RATES);
    CASE(NL80211_ATTR_STA_VLAN);
    CASE(NL80211_ATTR_STA_INFO);
    CASE(NL80211_ATTR_WIPHY_BANDS);
    CASE(NL80211_ATTR_MNTR_FLAGS);
    CASE(NL80211_ATTR_MESH_ID);
    CASE(NL80211_ATTR_STA_PLINK_ACTION);
    CASE(NL80211_ATTR_MPATH_NEXT_HOP);
    CASE(NL80211_ATTR_MPATH_INFO);
    CASE(NL80211_ATTR_BSS_CTS_PROT);
    CASE(NL80211_ATTR_BSS_SHORT_PREAMBLE);
    CASE(NL80211_ATTR_BSS_SHORT_SLOT_TIME);
    CASE(NL80211_ATTR_HT_CAPABILITY);
    CASE(NL80211_ATTR_SUPPORTED_IFTYPES);
    CASE(NL80211_ATTR_REG_ALPHA2);
    CASE(NL80211_ATTR_REG_RULES);
    CASE(NL80211_ATTR_MESH_CONFIG);
    CASE(NL80211_ATTR_BSS_BASIC_RATES);
    CASE(NL80211_ATTR_WIPHY_TXQ_PARAMS);
    CASE(NL80211_ATTR_WIPHY_FREQ);
    CASE(NL80211_ATTR_WIPHY_CHANNEL_TYPE);
    CASE(NL80211_ATTR_KEY_DEFAULT_MGMT);
    CASE(NL80211_ATTR_MGMT_SUBTYPE);
    CASE(NL80211_ATTR_IE);
    CASE(NL80211_ATTR_MAX_NUM_SCAN_SSIDS);
    CASE(NL80211_ATTR_SCAN_FREQUENCIES);
    CASE(NL80211_ATTR_SCAN_SSIDS);
    CASE(NL80211_ATTR_GENERATION);
    CASE(NL80211_ATTR_BSS);
    CASE(NL80211_ATTR_REG_INITIATOR);
    CASE(NL80211_ATTR_REG_TYPE);
    CASE(NL80211_ATTR_SUPPORTED_COMMANDS);
    CASE(NL80211_ATTR_FRAME);
    CASE(NL80211_ATTR_SSID);
    CASE(NL80211_ATTR_AUTH_TYPE);
    CASE(NL80211_ATTR_REASON_CODE);
    CASE(NL80211_ATTR_KEY_TYPE);
    CASE(NL80211_ATTR_MAX_SCAN_IE_LEN);
    CASE(NL80211_ATTR_CIPHER_SUITES);
    CASE(NL80211_ATTR_FREQ_BEFORE);
    CASE(NL80211_ATTR_FREQ_AFTER);
    CASE(NL80211_ATTR_FREQ_FIXED);
    CASE(NL80211_ATTR_WIPHY_RETRY_SHORT);
    CASE(NL80211_ATTR_WIPHY_RETRY_LONG);
    CASE(NL80211_ATTR_WIPHY_FRAG_THRESHOLD);
    CASE(NL80211_ATTR_WIPHY_RTS_THRESHOLD);
    CASE(NL80211_ATTR_TIMED_OUT);
    CASE(NL80211_ATTR_USE_MFP);
    CASE(NL80211_ATTR_STA_FLAGS2);
    CASE(NL80211_ATTR_CONTROL_PORT);
    CASE(NL80211_ATTR_TESTDATA);
    CASE(NL80211_ATTR_PRIVACY);
    CASE(NL80211_ATTR_DISCONNECTED_BY_AP);
    CASE(NL80211_ATTR_STATUS_CODE);
    CASE(NL80211_ATTR_CIPHER_SUITES_PAIRWISE);
    CASE(NL80211_ATTR_CIPHER_SUITE_GROUP);
    CASE(NL80211_ATTR_WPA_VERSIONS);
    CASE(NL80211_ATTR_AKM_SUITES);
    CASE(NL80211_ATTR_REQ_IE);
    CASE(NL80211_ATTR_RESP_IE);
    CASE(NL80211_ATTR_PREV_BSSID);
    CASE(NL80211_ATTR_KEY);
    CASE(NL80211_ATTR_KEYS);
    CASE(NL80211_ATTR_PID);
    CASE(NL80211_ATTR_4ADDR);
    CASE(NL80211_ATTR_SURVEY_INFO);
    CASE(NL80211_ATTR_PMKID);
    CASE(NL80211_ATTR_MAX_NUM_PMKIDS);
    CASE(NL80211_ATTR_DURATION);
    CASE(NL80211_ATTR_COOKIE);
    CASE(NL80211_ATTR_WIPHY_COVERAGE_CLASS);
    CASE(NL80211_ATTR_TX_RATES);
    CASE(NL80211_ATTR_FRAME_MATCH);
    CASE(NL80211_ATTR_ACK);
    CASE(NL80211_ATTR_PS_STATE);
    CASE(NL80211_ATTR_CQM);
    CASE(NL80211_ATTR_LOCAL_STATE_CHANGE);
    CASE(NL80211_ATTR_AP_ISOLATE);
    CASE(NL80211_ATTR_WIPHY_TX_POWER_SETTING);
    CASE(NL80211_ATTR_WIPHY_TX_POWER_LEVEL);
    CASE(NL80211_ATTR_TX_FRAME_TYPES);
    CASE(NL80211_ATTR_RX_FRAME_TYPES);
    CASE(NL80211_ATTR_FRAME_TYPE);
    CASE(NL80211_ATTR_CONTROL_PORT_ETHERTYPE);
    CASE(NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);
    CASE(NL80211_ATTR_SUPPORT_IBSS_RSN);
    CASE(NL80211_ATTR_WIPHY_ANTENNA_TX);
    CASE(NL80211_ATTR_WIPHY_ANTENNA_RX);
    CASE(NL80211_ATTR_MCAST_RATE);
    CASE(NL80211_ATTR_OFFCHANNEL_TX_OK);
    CASE(NL80211_ATTR_BSS_HT_OPMODE);
    CASE(NL80211_ATTR_KEY_DEFAULT_TYPES);
    CASE(NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION);
    CASE(NL80211_ATTR_MESH_SETUP);
    CASE(NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX);
    CASE(NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX);
    CASE(NL80211_ATTR_SUPPORT_MESH_AUTH);
    CASE(NL80211_ATTR_STA_PLINK_STATE);
    CASE(NL80211_ATTR_WOWLAN_TRIGGERS);
    CASE(NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED);
    CASE(NL80211_ATTR_SCHED_SCAN_INTERVAL);
    CASE(NL80211_ATTR_INTERFACE_COMBINATIONS);
    CASE(NL80211_ATTR_SOFTWARE_IFTYPES);
    CASE(NL80211_ATTR_REKEY_DATA);
    CASE(NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS);
    CASE(NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN);
    CASE(NL80211_ATTR_SCAN_SUPP_RATES);
    CASE(NL80211_ATTR_HIDDEN_SSID);
    CASE(NL80211_ATTR_IE_PROBE_RESP);
    CASE(NL80211_ATTR_IE_ASSOC_RESP);
    CASE(NL80211_ATTR_STA_WME);
    CASE(NL80211_ATTR_SUPPORT_AP_UAPSD);
    CASE(NL80211_ATTR_ROAM_SUPPORT);
    CASE(NL80211_ATTR_SCHED_SCAN_MATCH);
    CASE(NL80211_ATTR_MAX_MATCH_SETS);
    CASE(NL80211_ATTR_PMKSA_CANDIDATE);
    CASE(NL80211_ATTR_TX_NO_CCK_RATE);
    CASE(NL80211_ATTR_TDLS_ACTION);
    CASE(NL80211_ATTR_TDLS_DIALOG_TOKEN);
    CASE(NL80211_ATTR_TDLS_OPERATION);
    CASE(NL80211_ATTR_TDLS_SUPPORT);
    CASE(NL80211_ATTR_TDLS_EXTERNAL_SETUP);
    CASE(NL80211_ATTR_DEVICE_AP_SME);
    CASE(NL80211_ATTR_DONT_WAIT_FOR_ACK);
    CASE(NL80211_ATTR_FEATURE_FLAGS);
    CASE(NL80211_ATTR_PROBE_RESP_OFFLOAD);
    CASE(NL80211_ATTR_PROBE_RESP);
    CASE(NL80211_ATTR_DFS_REGION);
    CASE(NL80211_ATTR_DISABLE_HT);
    CASE(NL80211_ATTR_HT_CAPABILITY_MASK);
    CASE(NL80211_ATTR_NOACK_MAP);
    CASE(NL80211_ATTR_INACTIVITY_TIMEOUT);
    CASE(NL80211_ATTR_RX_SIGNAL_DBM);
    CASE(NL80211_ATTR_BG_SCAN_PERIOD);
    CASE(NL80211_ATTR_WDEV);
    CASE(NL80211_ATTR_USER_REG_HINT_TYPE);
    CASE(NL80211_ATTR_CONN_FAILED_REASON);
    CASE(NL80211_ATTR_AUTH_DATA);
    CASE(NL80211_ATTR_VHT_CAPABILITY);
    CASE(NL80211_ATTR_SCAN_FLAGS);
    CASE(NL80211_ATTR_CHANNEL_WIDTH);
    CASE(NL80211_ATTR_CENTER_FREQ1);
    CASE(NL80211_ATTR_CENTER_FREQ2);
    CASE(NL80211_ATTR_P2P_CTWINDOW);
    CASE(NL80211_ATTR_P2P_OPPPS);
    CASE(NL80211_ATTR_LOCAL_MESH_POWER_MODE);
    CASE(NL80211_ATTR_ACL_POLICY);
    CASE(NL80211_ATTR_MAC_ADDRS);
    CASE(NL80211_ATTR_MAC_ACL_MAX);
    CASE(NL80211_ATTR_RADAR_EVENT);
    CASE(NL80211_ATTR_EXT_CAPA);
    CASE(NL80211_ATTR_EXT_CAPA_MASK);
    CASE(NL80211_ATTR_STA_CAPABILITY);
    CASE(NL80211_ATTR_STA_EXT_CAPABILITY);
    CASE(NL80211_ATTR_PROTOCOL_FEATURES);
    CASE(NL80211_ATTR_SPLIT_WIPHY_DUMP);
    CASE(NL80211_ATTR_DISABLE_VHT);
    CASE(NL80211_ATTR_VHT_CAPABILITY_MASK);
    CASE(NL80211_ATTR_MDID);
    CASE(NL80211_ATTR_IE_RIC);
    CASE(NL80211_ATTR_CRIT_PROT_ID);
    CASE(NL80211_ATTR_MAX_CRIT_PROT_DURATION);
    CASE(NL80211_ATTR_PEER_AID);
    CASE(NL80211_ATTR_COALESCE_RULE);
    CASE(NL80211_ATTR_CH_SWITCH_COUNT);
    CASE(NL80211_ATTR_CH_SWITCH_BLOCK_TX);
    CASE(NL80211_ATTR_CSA_IES);
    CASE(NL80211_ATTR_CNTDWN_OFFS_BEACON);
    CASE(NL80211_ATTR_CNTDWN_OFFS_PRESP);
    CASE(NL80211_ATTR_RXMGMT_FLAGS);
    CASE(NL80211_ATTR_STA_SUPPORTED_CHANNELS);
    CASE(NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES);
    CASE(NL80211_ATTR_HANDLE_DFS);
    CASE(NL80211_ATTR_SUPPORT_5_MHZ);
    CASE(NL80211_ATTR_SUPPORT_10_MHZ);
    CASE(NL80211_ATTR_OPMODE_NOTIF);
    CASE(NL80211_ATTR_VENDOR_ID);
    CASE(NL80211_ATTR_VENDOR_SUBCMD);
    CASE(NL80211_ATTR_VENDOR_DATA);
    CASE(NL80211_ATTR_VENDOR_EVENTS);
    CASE(NL80211_ATTR_QOS_MAP);
    CASE(NL80211_ATTR_MAC_HINT);
    CASE(NL80211_ATTR_WIPHY_FREQ_HINT);
    CASE(NL80211_ATTR_MAX_AP_ASSOC_STA);
    CASE(NL80211_ATTR_TDLS_PEER_CAPABILITY);
    CASE(NL80211_ATTR_SOCKET_OWNER);
    CASE(NL80211_ATTR_CSA_C_OFFSETS_TX);
    CASE(NL80211_ATTR_MAX_CSA_COUNTERS);
    CASE(NL80211_ATTR_TDLS_INITIATOR);
    CASE(NL80211_ATTR_USE_RRM);
    CASE(NL80211_ATTR_WIPHY_DYN_ACK);
    CASE(NL80211_ATTR_TSID);
    CASE(NL80211_ATTR_USER_PRIO);
    CASE(NL80211_ATTR_ADMITTED_TIME);
    CASE(NL80211_ATTR_SMPS_MODE);
    CASE(NL80211_ATTR_OPER_CLASS);
    CASE(NL80211_ATTR_MAC_MASK);
    CASE(NL80211_ATTR_WIPHY_SELF_MANAGED_REG);
    CASE(NL80211_ATTR_EXT_FEATURES);
    CASE(NL80211_ATTR_SURVEY_RADIO_STATS);
    CASE(NL80211_ATTR_NETNS_FD);
    CASE(NL80211_ATTR_SCHED_SCAN_DELAY);
    CASE(NL80211_ATTR_REG_INDOOR);
    CASE(NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS);
    CASE(NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL);
    CASE(NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS);
    CASE(NL80211_ATTR_SCHED_SCAN_PLANS);
    CASE(NL80211_ATTR_PBSS);
    CASE(NL80211_ATTR_BSS_SELECT);
    CASE(NL80211_ATTR_STA_SUPPORT_P2P_PS);
    CASE(NL80211_ATTR_PAD);
    CASE(NL80211_ATTR_IFTYPE_EXT_CAPA);
    CASE(NL80211_ATTR_MU_MIMO_GROUP_DATA);
    CASE(NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR);
    CASE(NL80211_ATTR_SCAN_START_TIME_TSF);
    CASE(NL80211_ATTR_SCAN_START_TIME_TSF_BSSID);
    CASE(NL80211_ATTR_MEASUREMENT_DURATION);
    CASE(NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY);
    CASE(NL80211_ATTR_MESH_PEER_AID);
    CASE(NL80211_ATTR_NAN_MASTER_PREF);
    CASE(NL80211_ATTR_BANDS);
    CASE(NL80211_ATTR_NAN_FUNC);
    CASE(NL80211_ATTR_NAN_MATCH);
    CASE(NL80211_ATTR_FILS_KEK);
    CASE(NL80211_ATTR_FILS_NONCES);
    CASE(NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED);
    CASE(NL80211_ATTR_BSSID);
    CASE(NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI);
    CASE(NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST);
    CASE(NL80211_ATTR_TIMEOUT_REASON);
    CASE(NL80211_ATTR_FILS_ERP_USERNAME);
    CASE(NL80211_ATTR_FILS_ERP_REALM);
    CASE(NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM);
    CASE(NL80211_ATTR_FILS_ERP_RRK);
    CASE(NL80211_ATTR_FILS_CACHE_ID);
    CASE(NL80211_ATTR_PMK);
    CASE(NL80211_ATTR_SCHED_SCAN_MULTI);
    CASE(NL80211_ATTR_SCHED_SCAN_MAX_REQS);
    CASE(NL80211_ATTR_WANT_1X_4WAY_HS);
    CASE(NL80211_ATTR_PMKR0_NAME);
    CASE(NL80211_ATTR_PORT_AUTHORIZED);
    CASE(NL80211_ATTR_EXTERNAL_AUTH_ACTION);
    CASE(NL80211_ATTR_EXTERNAL_AUTH_SUPPORT);
    CASE(NL80211_ATTR_NSS);
    CASE(NL80211_ATTR_ACK_SIGNAL);
    CASE(NL80211_ATTR_CONTROL_PORT_OVER_NL80211);
    CASE(NL80211_ATTR_TXQ_STATS);
    CASE(NL80211_ATTR_TXQ_LIMIT);
    CASE(NL80211_ATTR_TXQ_MEMORY_LIMIT);
    CASE(NL80211_ATTR_TXQ_QUANTUM);
    CASE(NL80211_ATTR_HE_CAPABILITY);
    CASE(NL80211_ATTR_FTM_RESPONDER);
    CASE(NL80211_ATTR_FTM_RESPONDER_STATS);
    CASE(NL80211_ATTR_TIMEOUT);
    CASE(NL80211_ATTR_PEER_MEASUREMENTS);
    CASE(NL80211_ATTR_AIRTIME_WEIGHT);
    CASE(NL80211_ATTR_STA_TX_POWER_SETTING);
    CASE(NL80211_ATTR_STA_TX_POWER);
    CASE(NL80211_ATTR_SAE_PASSWORD);
    CASE(NL80211_ATTR_TWT_RESPONDER);
    CASE(NL80211_ATTR_HE_OBSS_PD);
    CASE(NL80211_ATTR_WIPHY_EDMG_CHANNELS);
    CASE(NL80211_ATTR_WIPHY_EDMG_BW_CONFIG);
    CASE(NL80211_ATTR_VLAN_ID);
    CASE(NL80211_ATTR_HE_BSS_COLOR);
    CASE(NL80211_ATTR_IFTYPE_AKM_SUITES);
    CASE(NL80211_ATTR_TID_CONFIG);
    CASE(NL80211_ATTR_CONTROL_PORT_NO_PREAUTH);
    CASE(NL80211_ATTR_PMK_LIFETIME);
    CASE(NL80211_ATTR_PMK_REAUTH_THRESHOLD);
    CASE(NL80211_ATTR_RECEIVE_MULTICAST);
    CASE(NL80211_ATTR_WIPHY_FREQ_OFFSET);
    CASE(NL80211_ATTR_CENTER_FREQ1_OFFSET);
    CASE(NL80211_ATTR_SCAN_FREQ_KHZ);
    CASE(NL80211_ATTR_HE_6GHZ_CAPABILITY);
    CASE(NL80211_ATTR_FILS_DISCOVERY);
    CASE(NL80211_ATTR_UNSOL_BCAST_PROBE_RESP);
    CASE(NL80211_ATTR_S1G_CAPABILITY);
    CASE(NL80211_ATTR_S1G_CAPABILITY_MASK);
    CASE(NL80211_ATTR_SAE_PWE);
    CASE(NL80211_ATTR_RECONNECT_REQUESTED);
    CASE(NL80211_ATTR_SAR_SPEC);
    CASE(NL80211_ATTR_DISABLE_HE);
    CASE(NL80211_ATTR_OBSS_COLOR_BITMAP);
    CASE(NL80211_ATTR_COLOR_CHANGE_COUNT);
    CASE(NL80211_ATTR_COLOR_CHANGE_COLOR);
    CASE(NL80211_ATTR_COLOR_CHANGE_ELEMS);
  default:
    return f("NL80211_ATTR_%d", attr);
  }
}

Str BandAttrToStr(nl80211_band_attr attr) {
  switch (attr) {
    CASE(NL80211_BAND_ATTR_FREQS);
    CASE(NL80211_BAND_ATTR_RATES);
    CASE(NL80211_BAND_ATTR_HT_MCS_SET);
    CASE(NL80211_BAND_ATTR_HT_CAPA);
    CASE(NL80211_BAND_ATTR_HT_AMPDU_FACTOR);
    CASE(NL80211_BAND_ATTR_HT_AMPDU_DENSITY);
    CASE(NL80211_BAND_ATTR_VHT_MCS_SET);
    CASE(NL80211_BAND_ATTR_VHT_CAPA);
    CASE(NL80211_BAND_ATTR_IFTYPE_DATA);
    CASE(NL80211_BAND_ATTR_EDMG_CHANNELS);
    CASE(NL80211_BAND_ATTR_EDMG_BW_CONFIG);
  default:
    return f("NL80211_BAND_ATTR_%d", attr);
  }
}

Str BitrateAttrToStr(nl80211_bitrate_attr attr) {
  switch (attr) {
    CASE(NL80211_BITRATE_ATTR_RATE);
    CASE(NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE);
  default:
    return f("NL80211_BITRATE_ATTR_%d", attr);
  }
}

Str FrequencyAttrToStr(nl80211_frequency_attr attr) {
  switch (attr) {
    CASE(NL80211_FREQUENCY_ATTR_FREQ);
    CASE(NL80211_FREQUENCY_ATTR_DISABLED);
    CASE(NL80211_FREQUENCY_ATTR_NO_IR);
    CASE(NL80211_FREQUENCY_ATTR_RADAR);
    CASE(NL80211_FREQUENCY_ATTR_MAX_TX_POWER);
    CASE(NL80211_FREQUENCY_ATTR_DFS_STATE);
    CASE(NL80211_FREQUENCY_ATTR_DFS_TIME);
    CASE(NL80211_FREQUENCY_ATTR_NO_HT40_MINUS);
    CASE(NL80211_FREQUENCY_ATTR_NO_HT40_PLUS);
    CASE(NL80211_FREQUENCY_ATTR_NO_80MHZ);
    CASE(NL80211_FREQUENCY_ATTR_NO_160MHZ);
    CASE(NL80211_FREQUENCY_ATTR_DFS_CAC_TIME);
    CASE(NL80211_FREQUENCY_ATTR_INDOOR_ONLY);
    CASE(NL80211_FREQUENCY_ATTR_IR_CONCURRENT);
    CASE(NL80211_FREQUENCY_ATTR_NO_20MHZ);
    CASE(NL80211_FREQUENCY_ATTR_NO_10MHZ);
    CASE(NL80211_FREQUENCY_ATTR_WMM);
    CASE(NL80211_FREQUENCY_ATTR_NO_HE);
    CASE(NL80211_FREQUENCY_ATTR_OFFSET);
    CASE(NL80211_FREQUENCY_ATTR_1MHZ);
    CASE(NL80211_FREQUENCY_ATTR_2MHZ);
    CASE(NL80211_FREQUENCY_ATTR_4MHZ);
    CASE(NL80211_FREQUENCY_ATTR_8MHZ);
    CASE(NL80211_FREQUENCY_ATTR_16MHZ);
  default:
    return f("NL80211_FREQUENCY_ATTR_%d", attr);
  }
}

Str BssSelectAttrToStr(nl80211_bss_select_attr attr) {
  switch (attr) {
    CASE(NL80211_BSS_SELECT_ATTR_RSSI);
    CASE(NL80211_BSS_SELECT_ATTR_BAND_PREF);
    CASE(NL80211_BSS_SELECT_ATTR_RSSI_ADJUST);
  default:
    return f("NL80211_BSS_SELECT_ATTR_%d", attr);
  }
}

Str DfsStateToStr(nl80211_dfs_state state) {
  switch (state) {
    CASE(NL80211_DFS_USABLE);
    CASE(NL80211_DFS_UNAVAILABLE);
    CASE(NL80211_DFS_AVAILABLE);
  default:
    return f("NL80211_DFS_%d", state);
  }
}

Str WmmRuleToStr(nl80211_wmm_rule rule) {
  switch (rule) {
    CASE(NL80211_WMMR_CW_MIN);
    CASE(NL80211_WMMR_CW_MAX);
    CASE(NL80211_WMMR_AIFSN);
    CASE(NL80211_WMMR_TXOP);
  default:
    return f("NL80211_WMMR_%d", rule);
  }
}

Str BandToStr(nl80211_band band) {
  switch (band) {
    CASE(NL80211_BAND_2GHZ);
    CASE(NL80211_BAND_5GHZ);
    CASE(NL80211_BAND_60GHZ);
    CASE(NL80211_BAND_6GHZ);
    CASE(NL80211_BAND_S1GHZ);
  default:
    return f("NL80211_BAND_%d", band);
  }
}

#undef CASE

Str DFS::ToStr() const {
  return f("DFS(%s, time: "
           "%d ms, CAC time: %d ms)",
           nl80211::DfsStateToStr(state).c_str(), time_ms, cac_time_ms);
}

} // namespace maf::nl80211