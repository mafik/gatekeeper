#include "nl80211.hh"

#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <string>

#include "buffer_builder.hh"
#include "format.hh"
#include "hex.hh"
#include "log.hh"
#include "netlink.hh"
#include "status.hh"

namespace maf::nl80211 {

#ifndef NDEBUG
#define NL80211_WARN
#endif

// #define NL80211_DEBUG

#ifdef NL80211_WARN
#define WARN_UNKNOWN_ATTR(attr, to_str)                                        \
  LOG << "Unknown netlink attribute in " << __FUNCTION__ << " (" << __FILE__   \
      << ":" << __LINE__ << "): " << to_str(attr.type) << " "                  \
      << attr.Span().size() << " bytes " << BytesToHex(attr.Span());
#else
#define WARN_UNKNOWN_ATTR(attr, to_str)
#endif

static Str BitrateAttrToStr(U16 attr) {
  return BitrateAttrToStr((nl80211_bitrate_attr)attr);
}

static Str WmmRuleToStr(U16 rule) {
  return WmmRuleToStr((nl80211_wmm_rule)rule);
}

static Str FrequencyAttrToStr(U16 attr) {
  return FrequencyAttrToStr((nl80211_frequency_attr)attr);
}

static Str RegRuleAttrToStr(U16 attr) {
  return RegRuleAttrToStr((nl80211_reg_rule_attr)attr);
}

static Str BandAttrToStr(U16 attr) {
  return BandAttrToStr((nl80211_band_attr)attr);
}

static Str IfaceLimitAttrToStr(U16 attr) {
  return IfaceLimitAttrToStr((nl80211_iface_limit_attrs)attr);
}

static Str IfaceCombinationAttrToStr(U16 attr) {
  return IfaceCombinationAttrToStr((nl80211_if_combination_attrs)attr);
}

static Str AttrToStr(U16 attr) { return AttrToStr((nl80211_attrs)attr); }

Netlink::Netlink(Status &status) : gn("nl80211"sv, NL80211_CMD_MAX, status) {
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
      WARN_UNKNOWN_ATTR(attr5, BitrateAttrToStr);
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
      WARN_UNKNOWN_ATTR(rule_attr, WmmRuleToStr);
      break;
    }
  }
}

// See nl80211_msg_put_channel in nl80211.c in Linux kernel source.
static void ParseFrequencyAttrs(Frequency &f, Attr &freq_attrs) {
  for (auto &attr5 : freq_attrs.Unnest()) {
    nl80211_frequency_attr freq_attr = (nl80211_frequency_attr)attr5.type;
    switch (freq_attr) {
    case __NL80211_FREQUENCY_ATTR_NO_IBSS: // Obsolete equivalent of
                                           // NL80211_FREQUENCY_ATTR_NO_IR
    case NL80211_FREQUENCY_ATTR_NO_IR:
      f.no_ir = true;
      break;
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
      WARN_UNKNOWN_ATTR(attr5, FrequencyAttrToStr);
      break;
    }
  }
}

static void ParseWiphyBandAttrs(Band &band, Attr &band_attrs) {
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
        ParseFrequencyAttrs(freq, attr4);
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
      WARN_UNKNOWN_ATTR(attr2, BandAttrToStr);
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
    ParseWiphyBandAttrs(*band, attr2);
  }
}

static void ParseInterfaceCombinationAttrs(InterfaceCombination &ic,
                                           Attr &attr) {
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
            WARN_UNKNOWN_ATTR(attr4, IfaceLimitAttrToStr);
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
      WARN_UNKNOWN_ATTR(attr2, IfaceCombinationAttrToStr);
      break;
    }
  }
}

static void ParseWiphyAttrs(Vec<Wiphy> &wiphys, Attrs attrs) {
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
        ParseInterfaceCombinationAttrs(ic, attr2);
      }
      break;
    case NL80211_ATTR_DEVICE_AP_SME:
      wiphy->ap_sme = true;
      break;
    case NL80211_ATTR_FEATURE_FLAGS:
      wiphy->feature_flags = attr.As<U32>();
      break;
    case NL80211_ATTR_TX_FRAME_TYPES:
      for (auto &attr2 : attr.Unnest()) {
        nl80211_iftype iftype = (nl80211_iftype)attr2.type;
        for (auto &attr3 : attr2.Unnest()) {
          assert(attr3.type == NL80211_ATTR_FRAME_TYPE);
          int frame_type = attr3.As<U16>() >> 4;
          wiphy->tx_frame_types[iftype] |= 1 << frame_type;
        }
      }
      break;
    case NL80211_ATTR_RX_FRAME_TYPES:
      for (auto &attr2 : attr.Unnest()) {
        nl80211_iftype iftype = (nl80211_iftype)attr2.type;
        for (auto &attr3 : attr2.Unnest()) {
          assert(attr3.type == NL80211_ATTR_FRAME_TYPE);
          int frame_type = attr3.As<U16>() >> 4;
          wiphy->rx_frame_types[iftype] |= 1 << frame_type;
        }
      }
      break;
    case NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS:
      wiphy->max_num_sched_scan_plans = attr.As<U32>();
      break;
    case NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL:
      wiphy->max_scan_plan_interval = attr.As<U32>();
      break;
    case NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS:
      wiphy->max_scan_plan_iterations = attr.As<U32>();
      break;
    case NL80211_ATTR_MAC:
      wiphy->mac = attr.As<MAC>();
      break;
    case NL80211_ATTR_MAC_ADDRS:
      for (auto &attr2 : attr.Unnest()) {
        wiphy->macs.push_back(attr2.As<MAC>());
      }
      break;
    case NL80211_ATTR_VENDOR_DATA:
      for (auto &attr2 : attr.Unnest()) {
        nl80211_vendor_cmd_info cmd_info = attr2.As<nl80211_vendor_cmd_info>();
        wiphy->vendor_commands.push_back({cmd_info.vendor_id, cmd_info.subcmd});
      }
      break;
    case NL80211_ATTR_EXT_FEATURES:
      wiphy->ext_feature_flags =
          attr.As<std::bitset<NUM_NL80211_EXT_FEATURES>>();
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
      WARN_UNKNOWN_ATTR(attr, AttrToStr);
      break;
    }
  }
}

static BufferBuilder::Ref<nlmsghdr>
AppendHeader(Netlink &nl, BufferBuilder &buf, nl80211_commands cmd) {
  auto hdr = buf.AppendPrimitive(nlmsghdr{
      .nlmsg_len = 0,
      .nlmsg_type = nl.gn.family_id,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
      .nlmsg_seq = 0, // Populated by Netlink::Send
      .nlmsg_pid = 0,
  });
  buf.AppendPrimitive(genlmsghdr{
      .cmd = (U8)cmd,
      .version = 0,
  });
  return hdr;
}

static void AppendAttrPrimitive(BufferBuilder &buf, int type,
                                const auto &primitive) {
  buf.AlignTo<4>();
  buf.AppendPrimitive(nlattr{
      .nla_len = (U16)(sizeof(nlattr) + sizeof(primitive)),
      .nla_type = (U16)type,
  });
  buf.AppendPrimitive(primitive);
}

static void AppendAttrPrimitive(BufferBuilder &buf, nl80211_attrs type,
                                const auto &primitive) {
  AppendAttrPrimitive(buf, (int)type, primitive);
}

static void AppendAttrRange(BufferBuilder &buf, int type, auto &range) {
  buf.AlignTo<4>();
  buf.AppendPrimitive(nlattr{
      .nla_len = (U16)(sizeof(nlattr) + range.size() * sizeof(range[0])),
      .nla_type = (U16)type,
  });
  buf.AppendRange(range);
}

static void AppendAttrRange(BufferBuilder &buf, nl80211_attrs type,
                            auto &range) {
  AppendAttrRange(buf, (int)type, range);
}

static void AppendAttrFlag(BufferBuilder &buf, int type) {
  buf.AlignTo<4>();
  buf.AppendPrimitive(nlattr{
      .nla_len = sizeof(nlattr),
      .nla_type = (U16)type,
  });
}

static void AppendAttrFlag(BufferBuilder &buf, nl80211_attrs type) {
  AppendAttrFlag(buf, (int)type);
}

#define SEND_WITH_ACK(buf, hdr, status)                                        \
  hdr->nlmsg_len = buf.Size();                                                 \
  gn.netlink.Send(hdr, status);                                                \
  if (!OK(status)) {                                                           \
    AppendErrorMessage(status) += "Couldn't send netlink message";             \
    return;                                                                    \
  }                                                                            \
  gn.netlink.ReceiveAck(status);                                               \
  if (!OK(status)) {                                                           \
    auto &err = AppendErrorMessage(status);                                    \
    err += "Error in nl80211::";                                               \
    err += __FUNCTION__;                                                       \
    return;                                                                    \
  }

Vec<Wiphy> Netlink::GetWiphys(Status &status) {
  Vec<Wiphy> ret;

  // Required to get full wiphy description.
  Attr attr_split_wiphy_dump(sizeof(Attr), NL80211_ATTR_SPLIT_WIPHY_DUMP);
  gn.Dump(
      NL80211_CMD_GET_WIPHY, &attr_split_wiphy_dump,
      [&](Attrs attrs) { ParseWiphyAttrs(ret, attrs); }, status);
  if (!OK(status)) {
    return {};
  }
  return ret;
}

static void ParseInterfaceAttrs(Interface &i, Attrs attrs) {
  for (auto &attr : attrs) {
    switch (attr.type) {
    case NL80211_ATTR_IFINDEX:
      i.index = attr.As<U32>();
      break;
    case NL80211_ATTR_IFNAME:
      i.name = attr.Span().ToStr();
      if (i.name.ends_with("\0")) {
        i.name.pop_back();
      }
      break;
    case NL80211_ATTR_IFTYPE:
      i.type = attr.As<nl80211_iftype>();
      break;
    case NL80211_ATTR_WIPHY:
      i.wiphy_index = attr.As<U32>();
      break;
    case NL80211_ATTR_WDEV:
      i.wireless_device_id = attr.As<U64>();
      break;
    case NL80211_ATTR_MAC:
      i.mac = attr.As<MAC>();
      break;
    case NL80211_ATTR_GENERATION:
      // Ignore
      break;
    case NL80211_ATTR_4ADDR:
      i.use_4addr = (bool)attr.As<U8>();
      break;
    case NL80211_ATTR_WIPHY_FREQ:
      i.frequency_MHz = attr.As<U32>();
      break;
    case NL80211_ATTR_WIPHY_CHANNEL_TYPE:
      i.channel_type = attr.As<nl80211_channel_type>();
      break;
    case NL80211_ATTR_WIPHY_FREQ_OFFSET:
      i.frequency_offset = attr.As<U32>();
      break;
    case NL80211_ATTR_CHANNEL_WIDTH:
      i.chan_width = attr.As<nl80211_chan_width>();
      break;
    case NL80211_ATTR_CENTER_FREQ1:
      i.center_frequency1 = attr.As<U32>();
      break;
    case NL80211_ATTR_CENTER_FREQ2:
      i.center_frequency2 = attr.As<U32>();
      break;
    case NL80211_ATTR_WIPHY_TX_POWER_LEVEL:
      i.tx_power_level_mbm = attr.As<I32>();
      break;
    default:
      WARN_UNKNOWN_ATTR(attr, AttrToStr);
      break;
    }
  }
}

Vec<Interface> Netlink::GetInterfaces(Status &status) {
  Vec<Interface> interfaces;
  gn.Dump(
      NL80211_CMD_GET_INTERFACE, nullptr,
      [&](Attrs attrs) {
        Interface &i = interfaces.emplace_back();
        ParseInterfaceAttrs(i, attrs);
      },
      status);
  return interfaces;
}

Str Regulation::Rule::Describe() const {
  Str ret = f("%d - %d kHz:\n", start_kHz, end_kHz);
  ret += f("  max bandwidth: %d MHz\n", max_bandwidth_kHz / 1000);
  ret += f("  max antenna gain: %d dBi\n", max_antenna_gain_mBi / 100);
  ret += f("  max EIRP: %d dBm\n", max_eirp_mBm / 100);
  if (dfs_cac_time_ms) { // 0 means "use default DFS CAC time"
    ret += f("  DFS CAC time: %d s\n", dfs_cac_time_ms / 1000);
  }
  if (flags.any()) {
    ret += f("  flags:");
#define PRINT_FLAG(flag)                                                       \
  if (flags.to_ulong() & NL80211_RRF_##flag) {                                 \
    ret += " " #flag;                                                          \
  }
    PRINT_FLAG(NO_OFDM)
    PRINT_FLAG(NO_CCK)
    PRINT_FLAG(NO_INDOOR)
    PRINT_FLAG(NO_OUTDOOR)
    PRINT_FLAG(DFS)
    PRINT_FLAG(PTP_ONLY)
    PRINT_FLAG(PTMP_ONLY)
    PRINT_FLAG(NO_IR)
    PRINT_FLAG(AUTO_BW)
    PRINT_FLAG(IR_CONCURRENT)
    PRINT_FLAG(NO_HT40MINUS)
    PRINT_FLAG(NO_HT40PLUS)
    PRINT_FLAG(NO_80MHZ)
    PRINT_FLAG(NO_160MHZ)
    PRINT_FLAG(NO_HE)
#undef PRINT_FLAG
    ret += "\n";
  }
  return ret;
}

Str Regulation::Describe() const {
  Str ret;
  ret += "Regulation for country ";
  ret += StrView(alpha2.data(), (Size)2);
  ret += ", ";
  ret += DFSRegionToStr(dfs_region);
  ret += ":\n";
  for (auto &rule : rules) {
    ret += Indent(rule.Describe());
  }
  return ret;
}

static void ParseRegulationRuleAttrs(Regulation::Rule &rule, Attrs attrs) {
  for (auto &attr : attrs) {
    switch (attr.type) {
    case NL80211_ATTR_REG_RULE_FLAGS:
      rule.flags = attr.As<U32>();
      break;
    case NL80211_ATTR_FREQ_RANGE_START:
      rule.start_kHz = attr.As<U32>();
      break;
    case NL80211_ATTR_FREQ_RANGE_END:
      rule.end_kHz = attr.As<U32>();
      break;
    case NL80211_ATTR_FREQ_RANGE_MAX_BW:
      rule.max_bandwidth_kHz = attr.As<U32>();
      break;
    case NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN:
      rule.max_antenna_gain_mBi = attr.As<U32>();
      break;
    case NL80211_ATTR_POWER_RULE_MAX_EIRP:
      rule.max_eirp_mBm = attr.As<U32>();
      break;
    case NL80211_ATTR_DFS_CAC_TIME:
      rule.dfs_cac_time_ms = attr.As<U32>();
      break;
    default:
      WARN_UNKNOWN_ATTR(attr, RegRuleAttrToStr);
      break;
    }
  }
}

static void ParseRegulationAttrs(Regulation &reg, Attrs attrs) {
  for (auto &attr : attrs) {
    switch (attr.type) {
    case NL80211_ATTR_REG_ALPHA2:
      reg.alpha2[0] = attr.payload[0];
      reg.alpha2[1] = attr.payload[1];
      break;
    case NL80211_ATTR_DFS_REGION:
      reg.dfs_region = (nl80211_dfs_regions)attr.As<U8>();
      break;
    case NL80211_ATTR_REG_RULES:
      for (auto &rule_attrs : attr.Unnest()) {
        Regulation::Rule &rule = reg.rules.emplace_back();
        ParseRegulationRuleAttrs(rule, rule_attrs.Unnest());
      }
      break;
    default:
      WARN_UNKNOWN_ATTR(attr, AttrToStr);
    }
  }
}

Regulation Netlink::GetRegulation(Status &status) {
  Regulation reg;
  BufferBuilder buf;
  auto hdr = AppendHeader(*this, buf, NL80211_CMD_GET_REG);
  hdr->nlmsg_len = buf.Size();
  gn.netlink.Send(hdr, status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Couldn't send netlink message";
    return reg;
  }
  gn.Receive(
      [&](U8 cmd, Attrs attrs) {
        if (cmd != NL80211_CMD_GET_REG) {
          AppendErrorMessage(status) +=
              "Expected NL80211_CMD_GET_REG but got " + CmdToStr(cmd);
          return;
        }
        ParseRegulationAttrs(reg, attrs);
      },
      status);
  if (!OK(status)) {
    auto &err = AppendErrorMessage(status);
    err += "Error in nl80211::";
    err += __FUNCTION__;
    return reg;
  }
  gn.netlink.ReceiveAck(status);
  if (!OK(status)) {
    auto &err = AppendErrorMessage(status);
    err += "Error in nl80211::";
    err += __FUNCTION__;
    return reg;
  }
  return reg;
}

void Netlink::RequestSetRegulation(Span<const char, 2> alpha2, Status &status) {
  BufferBuilder buf;
  auto hdr = AppendHeader(*this, buf, NL80211_CMD_REQ_SET_REG);
  Arr<char, 3> alpha2_c_str;
  alpha2_c_str[0] = alpha2[0];
  alpha2_c_str[1] = alpha2[1];
  alpha2_c_str[2] = '\0';
  AppendAttrPrimitive(buf, NL80211_ATTR_REG_ALPHA2, alpha2_c_str);
  SEND_WITH_ACK(buf, hdr, status);
}

void Netlink::RequestSetRegulationIndoor(bool indoor, Status &status) {
  BufferBuilder buf;
  auto hdr = AppendHeader(*this, buf, NL80211_CMD_REQ_SET_REG);

  AppendAttrPrimitive(buf, NL80211_ATTR_USER_REG_HINT_TYPE,
                      (U32)NL80211_USER_REG_HINT_INDOOR);
  if (indoor) {
    AppendAttrFlag(buf, NL80211_ATTR_REG_INDOOR);
  }
  SEND_WITH_ACK(buf, hdr, status);
}

void Netlink::SetInterfaceType(Interface::Index if_index, Interface::Type type,
                               Status &status) {
  struct SetInterfaceMessage {
    nlmsghdr hdr;
    genlmsghdr genl;
    nlattr attr_ifindex;
    U32 ifindex;
    nlattr attr_iftype;
    U32 iftype;
  } set_interface{
      .hdr =
          {
              .nlmsg_len = sizeof(SetInterfaceMessage),
              .nlmsg_type = gn.family_id,
              .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
              .nlmsg_seq = 0, // Populated by Netlink::Send
              .nlmsg_pid = 0,
          },
      .genl =
          {
              .cmd = NL80211_CMD_SET_INTERFACE,
              .version = 0,
          },
      .attr_ifindex =
          {
              .nla_len = sizeof(nlattr) + sizeof(U32),
              .nla_type = NL80211_ATTR_IFINDEX,
          },
      .ifindex = if_index,
      .attr_iftype =
          {
              .nla_len = sizeof(nlattr) + sizeof(U32),
              .nla_type = NL80211_ATTR_IFTYPE,
          },
      .iftype = type,
  };
  gn.netlink.Send(set_interface.hdr, status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Couldn't send netlink message";
    return;
  }
  gn.netlink.ReceiveAck(status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Failed to change nl80211 interface type";
    return;
  }
}

void Netlink::RegisterFrame(Interface::Index if_index, U16 frame_type,
                            Status &status) {
  struct RegisterFrameMessage {
    nlmsghdr hdr;
    genlmsghdr genl;
    nlattr attr_ifindex;
    U32 ifindex;
    nlattr attr_frame_type;
    U16 frame_type;
    alignas(4) nlattr attr_frame_match;
    U8 frame_match[0];
  } msg{
      .hdr =
          {
              .nlmsg_len = sizeof(RegisterFrameMessage),
              .nlmsg_type = gn.family_id,
              .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
              .nlmsg_seq = 0, // Populated by Netlink::Send
              .nlmsg_pid = 0,
          },
      .genl = {.cmd = NL80211_CMD_REGISTER_FRAME, .version = 0},
      .attr_ifindex = {.nla_len = sizeof(nlattr) + sizeof(U32),
                       .nla_type = NL80211_ATTR_IFINDEX},
      .ifindex = if_index,
      .attr_frame_type = {.nla_len = sizeof(nlattr) + sizeof(U16),
                          .nla_type = NL80211_ATTR_FRAME_TYPE},
      .frame_type = frame_type,
      .attr_frame_match = {.nla_len = sizeof(nlattr) + 0,
                           .nla_type = NL80211_ATTR_FRAME_MATCH},
  };
  gn.netlink.Send(msg.hdr, status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Couldn't send netlink message";
    return;
  }
  gn.netlink.ReceiveAck(status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Failed to register nl80211 frame";
    return;
  }
}

void Netlink::DelStation(Interface::Index if_index, MAC *mac,
                         DisconnectReason *reason, Status &status) {
  BufferBuilder buf;
  auto hdr = AppendHeader(*this, buf, NL80211_CMD_DEL_STATION);
  AppendAttrPrimitive(buf, NL80211_ATTR_IFINDEX, if_index);
  if (mac) {
    AppendAttrPrimitive(buf, NL80211_ATTR_MAC, *mac);
  }
  if (reason) {
    U8 mgmt_subtype =
        reason->type == DisconnectReason::DEAUTHENTICATION ? 0x0c : 0x0a;
    AppendAttrPrimitive(buf, NL80211_ATTR_MGMT_SUBTYPE, mgmt_subtype);
    U16 reason_code = reason->reason_code;
    AppendAttrPrimitive(buf, NL80211_ATTR_REASON_CODE, reason_code);
  }
  SEND_WITH_ACK(buf, hdr, status);
}

// See nl80211_parse_chandef in nl80211.c in Linux kernel source.
void Netlink::SetChannel(Interface::Index ifindex, const Channel &channel,
                         Status &status) {
  BufferBuilder buf(128);
  auto hdr = AppendHeader(*this, buf, NL80211_CMD_SET_CHANNEL);
  AppendAttrPrimitive(buf, NL80211_ATTR_IFINDEX, ifindex);
  AppendAttrPrimitive(buf, NL80211_ATTR_WIPHY_FREQ, channel.frequency_MHz);
  AppendAttrPrimitive(buf, NL80211_ATTR_CHANNEL_WIDTH, channel.width);
  if (channel.width == NL80211_CHAN_WIDTH_80 ||
      channel.width == NL80211_CHAN_WIDTH_40 ||
      channel.width == NL80211_CHAN_WIDTH_80P80 ||
      channel.width == NL80211_CHAN_WIDTH_160) {
    AppendAttrPrimitive(buf, NL80211_ATTR_CENTER_FREQ1,
                        channel.center_frequency1_MHz);
    if (channel.width == NL80211_CHAN_WIDTH_80P80) {
      AppendAttrPrimitive(buf, NL80211_ATTR_CENTER_FREQ2,
                          channel.center_frequency2_MHz);
    }
  }
  SEND_WITH_ACK(buf, hdr, status);
}

void Netlink::StartAP(Interface::Index ifindex, Span<> beacon_head,
                      Span<> beacon_tail, U32 beacon_interval, U32 dtim_period,
                      StrView ssid, nl80211_hidden_ssid hidden_ssid,
                      bool privacy, nl80211_auth_type auth_type,
                      U32 wpa_versions,
                      Span<AuthenticationKeyManagement> akm_suites,
                      Span<CipherSuite> pairwise_ciphers,
                      CipherSuite group_cipher, Span<> ie, Span<> ie_probe_resp,
                      Span<> ie_assoc_resp, bool socket_owner, Status &status) {
  BufferBuilder buf(512);
  auto hdr = AppendHeader(*this, buf, NL80211_CMD_START_AP);
  AppendAttrPrimitive(buf, NL80211_ATTR_IFINDEX, ifindex);
  AppendAttrRange(buf, NL80211_ATTR_BEACON_HEAD, beacon_head);
  AppendAttrRange(buf, NL80211_ATTR_BEACON_TAIL, beacon_tail);
  AppendAttrPrimitive(buf, NL80211_ATTR_BEACON_INTERVAL, beacon_interval);
  AppendAttrPrimitive(buf, NL80211_ATTR_DTIM_PERIOD, dtim_period);
  AppendAttrRange(buf, NL80211_ATTR_SSID, ssid);
  AppendAttrPrimitive(buf, NL80211_ATTR_HIDDEN_SSID, hidden_ssid);
  if (privacy) {
    AppendAttrFlag(buf, NL80211_ATTR_PRIVACY);
  }
  AppendAttrPrimitive(buf, NL80211_ATTR_AUTH_TYPE, auth_type);
  AppendAttrPrimitive(buf, NL80211_ATTR_WPA_VERSIONS, wpa_versions);
  AppendAttrRange(buf, NL80211_ATTR_AKM_SUITES, akm_suites);
  AppendAttrRange(buf, NL80211_ATTR_CIPHER_SUITES_PAIRWISE, pairwise_ciphers);
  AppendAttrPrimitive(buf, NL80211_ATTR_CIPHER_SUITE_GROUP, group_cipher);
  AppendAttrRange(buf, NL80211_ATTR_IE, ie);
  AppendAttrRange(buf, NL80211_ATTR_IE_PROBE_RESP, ie_probe_resp);
  AppendAttrRange(buf, NL80211_ATTR_IE_ASSOC_RESP, ie_assoc_resp);
  if (socket_owner) {
    AppendAttrFlag(buf, NL80211_ATTR_SOCKET_OWNER);
  }
  SEND_WITH_ACK(buf, hdr, status);
}

void Netlink::StopAP(Interface::Index ifindex, Status &status) {
  BufferBuilder buf;
  auto hdr = AppendHeader(*this, buf, NL80211_CMD_STOP_AP);
  AppendAttrPrimitive(buf, NL80211_ATTR_IFINDEX, ifindex);
  SEND_WITH_ACK(buf, hdr, status);
}

void Netlink::SetBSS(Interface::Index ifindex, bool cts_protection,
                     bool short_preamble, U16 ht_opmode, bool ap_isolate,
                     Span<> basic_rates, Status &status) {
  BufferBuilder buf(128);
  auto hdr = AppendHeader(*this, buf, NL80211_CMD_SET_BSS);
  AppendAttrPrimitive(buf, NL80211_ATTR_IFINDEX, ifindex);
  AppendAttrPrimitive(buf, NL80211_ATTR_BSS_CTS_PROT, cts_protection);
  AppendAttrPrimitive(buf, NL80211_ATTR_BSS_SHORT_PREAMBLE, short_preamble);
  AppendAttrPrimitive(buf, NL80211_ATTR_BSS_HT_OPMODE, ht_opmode);
  AppendAttrPrimitive(buf, NL80211_ATTR_AP_ISOLATE, ap_isolate);
  AppendAttrRange(buf, NL80211_ATTR_BSS_BASIC_RATES, basic_rates);
  SEND_WITH_ACK(buf, hdr, status);
}

void Netlink::SetMulticastToUnicast(Interface::Index ifindex, bool enable,
                                    Status &status) {
  BufferBuilder buf(32);
  auto hdr = AppendHeader(*this, buf, NL80211_CMD_SET_MULTICAST_TO_UNICAST);
  AppendAttrPrimitive(buf, NL80211_ATTR_IFINDEX, ifindex);
  if (enable) {
    AppendAttrFlag(buf, NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED);
  }
  SEND_WITH_ACK(buf, hdr, status);
}

void Netlink::NewKey(Interface::Index ifindex, MAC *mac, Span<> key_data,
                     CipherSuite cipher_suite, KeyIndex key_index,
                     Status &status) {
  BufferBuilder buf(128);
  auto hdr = AppendHeader(*this, buf, NL80211_CMD_NEW_KEY);
  AppendAttrPrimitive(buf, NL80211_ATTR_IFINDEX, ifindex);
  if (mac) {
    AppendAttrPrimitive(buf, NL80211_ATTR_MAC, *mac);
  }
  BufferBuilder key_attr(64);
  AppendAttrRange(key_attr, NL80211_KEY_DATA, key_data);
  AppendAttrPrimitive(key_attr, NL80211_KEY_CIPHER, cipher_suite);
  AppendAttrPrimitive(key_attr, NL80211_KEY_IDX, key_index);
  AppendAttrRange(buf, NL80211_ATTR_KEY, key_attr.buffer);
  SEND_WITH_ACK(buf, hdr, status);
}

void Netlink::SetKey(Interface::Index ifindex, KeyIndex key_index,
                     bool key_default, bool key_default_unicast,
                     bool key_default_multicast, Status &status) {
  BufferBuilder buf(128);
  auto hdr = AppendHeader(*this, buf, NL80211_CMD_SET_KEY);
  AppendAttrPrimitive(buf, NL80211_ATTR_IFINDEX, ifindex);
  BufferBuilder key_attr(32);
  AppendAttrPrimitive(key_attr, NL80211_KEY_IDX, key_index);
  if (key_default) {
    AppendAttrFlag(key_attr, NL80211_KEY_DEFAULT);
  }
  BufferBuilder key_default_types(16);
  if (key_default_unicast) {
    key_default_types.AppendPrimitive(
        (U16)(1 << NL80211_KEY_DEFAULT_TYPE_UNICAST));
  }
  if (key_default_multicast) {
    key_default_types.AppendPrimitive(
        (U16)(1 << NL80211_KEY_DEFAULT_TYPE_MULTICAST));
  }
  AppendAttrRange(key_attr, NL80211_KEY_DEFAULT_TYPES | NLA_F_NESTED,
                  key_default_types.buffer);
  AppendAttrRange(buf, NL80211_ATTR_KEY, key_attr.buffer);
  SEND_WITH_ACK(buf, hdr, status);
}

void Netlink::SetStation(Interface::Index ifindex, MAC mac,
                         Span<nl80211_sta_flags> set_flags,
                         Span<nl80211_sta_flags> clear_flags, Status &status) {
  BufferBuilder buf(128);
  auto hdr = AppendHeader(*this, buf, NL80211_CMD_SET_STATION);
  AppendAttrPrimitive(buf, NL80211_ATTR_IFINDEX, ifindex);
  AppendAttrPrimitive(buf, NL80211_ATTR_MAC, mac);
  nl80211_sta_flag_update flag_update{.mask = 0, .set = 0};
  for (auto flag : set_flags) {
    flag_update.mask |= 1 << flag;
    flag_update.set |= 1 << flag;
  }
  for (auto flag : clear_flags) {
    flag_update.mask |= 1 << flag;
  }
  AppendAttrPrimitive(buf, NL80211_ATTR_STA_FLAGS2, flag_update);
  SEND_WITH_ACK(buf, hdr, status);
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

Str Interface::Describe() const {
  Str ret;
  ret += f("Interface %d \"%s\":\n", index, name.c_str());
  Str body;
  body += "Type: " + IftypeToStrShort(type) + "\n";
  body += "MAC: " + mac.to_string() + "\n";
  body += "Wiphy: " + std::to_string(wiphy_index) + "\n";
  body += "Wireless device ID: " + std::to_string(wireless_device_id) + "\n";
  if (use_4addr) {
    body += "4-address frames: enabled\n";
  }
  body += "Frequency: " + std::to_string(frequency_MHz) + " MHz\n";
  body += "Channel type: " + ChannelTypeToStr(channel_type) + "\n";
  body += "Frequency offset: " + std::to_string(frequency_offset) + " kHz\n";
  body += "Channel width: " + ChanWidthToStr(chan_width) + "\n";
  if (center_frequency1) {
    body +=
        "Center frequency 1: " + std::to_string(center_frequency1) + " MHz\n";
  }
  if (center_frequency2) {
    body +=
        "Center frequency 2: " + std::to_string(center_frequency2) + " MHz\n";
  }
  if (tx_power_level_mbm.has_value()) {
    body += "TX power level: " + std::to_string(*tx_power_level_mbm) + " mBm\n";
  }
  ret += Indent(body);
  return ret;
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
  if (ht.has_value()) {
    body += "High Throughput:";
    body += " capabilities=";
    body += f("%04hx", ht->capa);
    body += ", A-MPDU factor=";
    body += std::to_string(ht->ampdu_factor);
    body += ", A-MPDU density=";
    body += std::to_string(ht->ampdu_density);
    body += ", MCS set=";
    body += BytesToHex(Span<>((char *)ht->mcs_set.begin(), 16));
    body += "\n";
  }
  if (vht.has_value()) {
    body += "Very High Throughput:";
    body += " capabilities=";
    body += f("%08x", vht->capa);
    body += ", VHT mcs set=";
    body += BytesToHex(Span<>((char *)vht->mcs_set.begin(), 8));
    body += "\n";
  }
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

Str Channel::Describe() const {
  Str ret;
  switch (width) {
  case NL80211_CHAN_WIDTH_20_NOHT:
    ret += "20 MHz";
    break;
  case NL80211_CHAN_WIDTH_20:
    ret += "20 MHz HT";
    break;
  case NL80211_CHAN_WIDTH_40:
    ret += "40 MHz HT";
    break;
  case NL80211_CHAN_WIDTH_80:
    ret += "80 MHz VHT";
    break;
  case NL80211_CHAN_WIDTH_80P80:
    ret += "80+80 MHz VHT";
    break;
  case NL80211_CHAN_WIDTH_160:
    ret += "160 MHz VHT";
    break;
  default:
    ret += f("NL80211_CHAN_WIDTH_NUMBER_%d", width);
    break;
  }
  ret += " channel ";
  ret += f("%d (%d MHz)", ChannelNumber(), frequency_MHz);
  if (center_frequency1_MHz) {
    ret += f(" (center frequency 1: %d MHz)", center_frequency1_MHz);
  }
  if (center_frequency2_MHz) {
    ret += f(" (center frequency 2: %d MHz)", center_frequency2_MHz);
  }
  return ret;
}

U32 Channel::ChannelNumber() const {
  // See: ieee80211_freq_khz_to_channel
  U32 freq = frequency_MHz;
  if (freq == 2484)
    return 14;
  else if (freq < 2484)
    return (freq - 2407) / 5;
  else if (freq >= 4910 && freq <= 4980)
    return (freq - 4000) / 5;
  else if (freq < 5925)
    return (freq - 5000) / 5;
  else if (freq == 5935)
    return 2;
  else if (freq <= 45000)
    return (freq - 5950) / 5;
  else if (freq >= 58320 && freq <= 70200)
    return (freq - 56160) / 2160;
  else
    return 0;
}

nl80211_band Channel::GetBand() const {
  if (frequency_MHz < 4000) {
    return NL80211_BAND_2GHZ;
  } else if (frequency_MHz < 6000) {
    return NL80211_BAND_5GHZ;
  } else {
    return NL80211_BAND_60GHZ;
  }
}

bool Regulation::Check(U32 center_MHz, U32 bandwidth_MHz) const {
  U32 center_kHz = center_MHz * 1000;
  U32 bandwidth_kHz = bandwidth_MHz * 1000;
  U32 low_kHz = center_kHz - bandwidth_kHz / 2;
  U32 high_kHz = center_kHz + bandwidth_kHz / 2;

  // Find the rule that contains the lower frequency bound.
  int a;
  for (a = 0; a < rules.size(); ++a) {
    if (rules[a].start_kHz <= low_kHz && rules[a].end_kHz >= low_kHz) {
      break;
    }
  }
  if (a == rules.size()) {
    return false; // Lower bound of the frequency range is not regulated
  }
  // Find the rule that contains the higher frequency bound.
  int b;
  for (b = rules.size() - 1; b >= 0; --b) {
    if (rules[b].start_kHz <= high_kHz && rules[b].end_kHz >= high_kHz) {
      break;
    }
  }
  if (b < 0) {
    return false; // Upper bound of the frequency range is not regulated
  }
  for (int i = a; i <= b; ++i) {
    // Check whether rules are contiguous.
    if (i > a) {
      if (rules[i].start_kHz != rules[i - 1].end_kHz) {
        return false; // Unregulated region within the frequency range
      }
    }
    auto &r = rules[i];
    if (r.max_bandwidth_kHz < bandwidth_kHz) {
      return false;
    }
  }
  return true;
}

Vec<Channel> Wiphy::GetChannels(const Regulation &reg) const {
  Vec<Channel> ret;
  for (auto &band : bands) {
    for (int freq_i = 0; freq_i < band.frequencies.size(); ++freq_i) {
      auto &freq = band.frequencies[freq_i];
      if (freq.disabled || freq.no_ir) {
        continue;
      }
      if (!reg.Check(freq.frequency, 20)) {
        continue;
      }
      ret.emplace_back(Channel{
          .width = NL80211_CHAN_WIDTH_20_NOHT,
          .frequency_MHz = freq.frequency,
          .ht = std::nullopt,
          .vht = std::nullopt,
      });
      if (band.ht.has_value()) {
        ret.emplace_back(Channel{
            .width = NL80211_CHAN_WIDTH_20,
            .frequency_MHz = freq.frequency,
            .ht = band.ht,
            .vht = std::nullopt,
        });
        if (!freq.no_ht40_minus) {
          if (reg.Check(freq.frequency - 10, 40)) {
            ret.emplace_back(Channel{
                .width = NL80211_CHAN_WIDTH_40,
                .frequency_MHz = freq.frequency,
                .center_frequency1_MHz = freq.frequency - 10,
                .ht = band.ht,
                .vht = std::nullopt,
            });
          }
        }
        if (!freq.no_ht40_plus) {
          if (reg.Check(freq.frequency + 10, 40)) {
            ret.emplace_back(Channel{
                .width = NL80211_CHAN_WIDTH_40,
                .frequency_MHz = freq.frequency,
                .center_frequency1_MHz = freq.frequency + 10,
                .ht = band.ht,
                .vht = std::nullopt,
            });
          }
        }
        if (!freq.no_80mhz) {
          for (auto off : {-30, -10, 10, 30}) {
            U32 center_frequency1_MHz = freq.frequency + off;
            if (!reg.Check(center_frequency1_MHz, 80)) {
              continue;
            }
            ret.emplace_back(Channel{
                .width = NL80211_CHAN_WIDTH_80,
                .frequency_MHz = freq.frequency,
                .center_frequency1_MHz = center_frequency1_MHz,
                .ht = band.ht,
                .vht = band.vht,
            });
            // Separation of 80 is not possible because then we should use 160
            // MHz-wide channels. Minimum separation is therefore 85. It seems
            // that everybody uses 20 MHz spacing though.
            for (U32 center_frequency2_MHz = center_frequency1_MHz + 100;
                 center_frequency2_MHz < band.frequencies.back().frequency;
                 center_frequency2_MHz += 20) {
              if (reg.Check(center_frequency2_MHz, 80)) {
                ret.emplace_back(Channel{
                    .width = NL80211_CHAN_WIDTH_80P80,
                    .frequency_MHz = freq.frequency,
                    .center_frequency1_MHz = center_frequency1_MHz,
                    .center_frequency2_MHz = center_frequency2_MHz,
                    .ht = band.ht,
                    .vht = band.vht,
                });
              }
            }
          }
        }
        if (!freq.no_160mhz) {
          for (auto off : {-70, -50, -30, -10, 10, 30, 50, 70}) {
            if (reg.Check(freq.frequency + off, 160)) {
              ret.emplace_back(Channel{
                  .width = NL80211_CHAN_WIDTH_160,
                  .frequency_MHz = freq.frequency,
                  .center_frequency1_MHz = freq.frequency + off,
                  .ht = band.ht,
                  .vht = band.vht,
              });
            }
          }
        }
      }
    }
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
            std::to_string(max_sched_scan_match_sets) + " match sets, " +
            std::to_string(max_num_sched_scan_plans) + " plans, " +
            std::to_string(max_scan_plan_interval) + " s max interval, " +
            std::to_string(max_scan_plan_iterations) + " max iterations\n";
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
  for (int ext_feature_i = 0; ext_feature_i < NUM_NL80211_EXT_FEATURES;
       ++ext_feature_i) {
    auto ext_feature = (nl80211_ext_feature_index)ext_feature_i;
    if (ext_feature_flags[ext_feature_i]) {
      body += " " + ExtFeatureToStr(ext_feature);
    }
  }
  body += "\n";

  body += "TX frame types (bitmask):";
  {
    bool first = true;
    for (int iftype_i = 0; iftype_i < NUM_NL80211_IFTYPES; ++iftype_i) {
      nl80211_iftype iftype = (nl80211_iftype)iftype_i;
      if (tx_frame_types[iftype_i]) {
        if (first) {
          first = false;
        } else {
          body += ",";
        }
        body += " ";
        body += IftypeToStrShort(iftype);
        body += f(": %04hx", tx_frame_types[iftype_i]);
      }
    }
  }
  body += "\n";
  body += "RX frame types (bitmask):";
  {
    bool first = true;
    for (int iftype_i = 0; iftype_i < NUM_NL80211_IFTYPES; ++iftype_i) {
      nl80211_iftype iftype = (nl80211_iftype)iftype_i;
      if (rx_frame_types[iftype_i]) {
        if (first) {
          first = false;
        } else {
          body += ",";
        }
        body += " ";
        body += IftypeToStrShort(iftype);
        body += f(": %04hx", rx_frame_types[iftype_i]);
      }
    }
  }
  body += "\n";
  body += "MAC address: " + mac.to_string();
  if (!macs.empty()) {
    body += " (";
    bool first = false;
    for (auto &mac : macs) {
      if (!first) {
        first = true;
      } else {
        body += ", ";
      }
      body += mac.to_string();
    }
    body += ")";
  }
  body += "\n";
  if (!vendor_commands.empty()) {
    body += "Vendor commands:\n";
    for (auto &cmd : vendor_commands) {
      body += "  OUI " +
              f("%02x:%02x:%02x", (cmd.vendor_id >> 16) & 0xff,
                (cmd.vendor_id >> 8) & 0xff, cmd.vendor_id & 0xff) +
              ", subcommand " + std::to_string(cmd.subcommand) + "\n";
    }
  }
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

Str ChanWidthToStr(nl80211_chan_width chan_width) {
  switch (chan_width) {
    CASE(NL80211_CHAN_WIDTH_20_NOHT);
    CASE(NL80211_CHAN_WIDTH_20);
    CASE(NL80211_CHAN_WIDTH_40);
    CASE(NL80211_CHAN_WIDTH_80);
    CASE(NL80211_CHAN_WIDTH_80P80);
    CASE(NL80211_CHAN_WIDTH_160);
    CASE(NL80211_CHAN_WIDTH_5);
    CASE(NL80211_CHAN_WIDTH_10);
    CASE(NL80211_CHAN_WIDTH_1);
    CASE(NL80211_CHAN_WIDTH_2);
    CASE(NL80211_CHAN_WIDTH_4);
    CASE(NL80211_CHAN_WIDTH_8);
    CASE(NL80211_CHAN_WIDTH_16);
  default:
    return f("NL80211_CHAN_WIDTH_UNKNOWN_%d", chan_width);
  }
}

Str ExtFeatureToStr(nl80211_ext_feature_index ext_feature) {
  switch (ext_feature) {
    CASE(NL80211_EXT_FEATURE_VHT_IBSS);
    CASE(NL80211_EXT_FEATURE_RRM);
    CASE(NL80211_EXT_FEATURE_MU_MIMO_AIR_SNIFFER);
    CASE(NL80211_EXT_FEATURE_SCAN_START_TIME);
    CASE(NL80211_EXT_FEATURE_BSS_PARENT_TSF);
    CASE(NL80211_EXT_FEATURE_SET_SCAN_DWELL);
    CASE(NL80211_EXT_FEATURE_BEACON_RATE_LEGACY);
    CASE(NL80211_EXT_FEATURE_BEACON_RATE_HT);
    CASE(NL80211_EXT_FEATURE_BEACON_RATE_VHT);
    CASE(NL80211_EXT_FEATURE_FILS_STA);
    CASE(NL80211_EXT_FEATURE_MGMT_TX_RANDOM_TA);
    CASE(NL80211_EXT_FEATURE_MGMT_TX_RANDOM_TA_CONNECTED);
    CASE(NL80211_EXT_FEATURE_SCHED_SCAN_RELATIVE_RSSI);
    CASE(NL80211_EXT_FEATURE_CQM_RSSI_LIST);
    CASE(NL80211_EXT_FEATURE_FILS_SK_OFFLOAD);
    CASE(NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK);
    CASE(NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X);
    CASE(NL80211_EXT_FEATURE_FILS_MAX_CHANNEL_TIME);
    CASE(NL80211_EXT_FEATURE_ACCEPT_BCAST_PROBE_RESP);
    CASE(NL80211_EXT_FEATURE_OCE_PROBE_REQ_HIGH_TX_RATE);
    CASE(NL80211_EXT_FEATURE_OCE_PROBE_REQ_DEFERRAL_SUPPRESSION);
    CASE(NL80211_EXT_FEATURE_MFP_OPTIONAL);
    CASE(NL80211_EXT_FEATURE_LOW_SPAN_SCAN);
    CASE(NL80211_EXT_FEATURE_LOW_POWER_SCAN);
    CASE(NL80211_EXT_FEATURE_HIGH_ACCURACY_SCAN);
    CASE(NL80211_EXT_FEATURE_DFS_OFFLOAD);
    CASE(NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211);
    CASE(NL80211_EXT_FEATURE_ACK_SIGNAL_SUPPORT);
    CASE(NL80211_EXT_FEATURE_TXQS);
    CASE(NL80211_EXT_FEATURE_SCAN_RANDOM_SN);
    CASE(NL80211_EXT_FEATURE_SCAN_MIN_PREQ_CONTENT);
    CASE(NL80211_EXT_FEATURE_CAN_REPLACE_PTK0);
    CASE(NL80211_EXT_FEATURE_ENABLE_FTM_RESPONDER);
    CASE(NL80211_EXT_FEATURE_AIRTIME_FAIRNESS);
    CASE(NL80211_EXT_FEATURE_AP_PMKSA_CACHING);
    CASE(NL80211_EXT_FEATURE_SCHED_SCAN_BAND_SPECIFIC_RSSI_THOLD);
    CASE(NL80211_EXT_FEATURE_EXT_KEY_ID);
    CASE(NL80211_EXT_FEATURE_STA_TX_PWR);
    CASE(NL80211_EXT_FEATURE_SAE_OFFLOAD);
    CASE(NL80211_EXT_FEATURE_VLAN_OFFLOAD);
    CASE(NL80211_EXT_FEATURE_AQL);
    CASE(NL80211_EXT_FEATURE_BEACON_PROTECTION);
    CASE(NL80211_EXT_FEATURE_CONTROL_PORT_NO_PREAUTH);
    CASE(NL80211_EXT_FEATURE_PROTECTED_TWT);
    CASE(NL80211_EXT_FEATURE_DEL_IBSS_STA);
    CASE(NL80211_EXT_FEATURE_MULTICAST_REGISTRATIONS);
    CASE(NL80211_EXT_FEATURE_BEACON_PROTECTION_CLIENT);
    CASE(NL80211_EXT_FEATURE_SCAN_FREQ_KHZ);
    CASE(NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211_TX_STATUS);
    CASE(NL80211_EXT_FEATURE_OPERATING_CHANNEL_VALIDATION);
    CASE(NL80211_EXT_FEATURE_4WAY_HANDSHAKE_AP_PSK);
    CASE(NL80211_EXT_FEATURE_SAE_OFFLOAD_AP);
    CASE(NL80211_EXT_FEATURE_FILS_DISCOVERY);
    CASE(NL80211_EXT_FEATURE_UNSOL_BCAST_PROBE_RESP);
    CASE(NL80211_EXT_FEATURE_BEACON_RATE_HE);
    CASE(NL80211_EXT_FEATURE_SECURE_LTF);
    CASE(NL80211_EXT_FEATURE_SECURE_RTT);
    CASE(NL80211_EXT_FEATURE_PROT_RANGE_NEGO_AND_MEASURE);
    CASE(NL80211_EXT_FEATURE_BSS_COLOR);
  default:
    return f("NL80211_EXT_FEATURE_%d", (int)ext_feature);
  }
}

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

Str ChannelTypeToStr(nl80211_channel_type type) {
  switch (type) {
    CASE(NL80211_CHAN_NO_HT);
    CASE(NL80211_CHAN_HT20);
    CASE(NL80211_CHAN_HT40MINUS);
    CASE(NL80211_CHAN_HT40PLUS);
  default:
    return f("NL80211_CHAN_%d", (int)type);
  }
}

Str IfaceLimitAttrToStr(nl80211_iface_limit_attrs attr) {
  switch (attr) {
    CASE(NL80211_IFACE_LIMIT_UNSPEC);
    CASE(NL80211_IFACE_LIMIT_MAX);
    CASE(NL80211_IFACE_LIMIT_TYPES);
  default:
    return f("NL80211_IFACE_LIMIT_%d", (int)attr);
  }
}

Str IfaceCombinationAttrToStr(nl80211_if_combination_attrs attr) {
  switch (attr) {
    CASE(NL80211_IFACE_COMB_UNSPEC);
    CASE(NL80211_IFACE_COMB_LIMITS);
    CASE(NL80211_IFACE_COMB_MAXNUM);
    CASE(NL80211_IFACE_COMB_STA_AP_BI_MATCH);
    CASE(NL80211_IFACE_COMB_NUM_CHANNELS);
    CASE(NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS);
    CASE(NL80211_IFACE_COMB_RADAR_DETECT_REGIONS);
    CASE(NL80211_IFACE_COMB_BI_MIN_GCD);
  default:
    return f("NL80211_IFACE_COMB_%d", (int)attr);
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

Str AttrToStr(nl80211_attrs attr) {
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

Str RegRuleAttrToStr(nl80211_reg_rule_attr attr) {
  switch (attr) {
    CASE(NL80211_ATTR_REG_RULE_FLAGS);
    CASE(NL80211_ATTR_FREQ_RANGE_START);
    CASE(NL80211_ATTR_FREQ_RANGE_END);
    CASE(NL80211_ATTR_FREQ_RANGE_MAX_BW);
    CASE(NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN);
    CASE(NL80211_ATTR_POWER_RULE_MAX_EIRP);
    CASE(NL80211_ATTR_DFS_CAC_TIME);
  default:
    return f("NL80211_REG_RULE_ATTR_%d", attr);
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

Str DFSRegionToStr(nl80211_dfs_regions region) {
  switch (region) {
    CASE(NL80211_DFS_UNSET);
    CASE(NL80211_DFS_FCC);
    CASE(NL80211_DFS_ETSI);
    CASE(NL80211_DFS_JP);
  default:
    return f("NL80211_DFS_%d", region);
  }
}

#undef CASE

Str DFS::ToStr() const {
  return f("DFS(%s, time: "
           "%d ms, CAC time: %d ms)",
           nl80211::DfsStateToStr(state).c_str(), time_ms, cac_time_ms);
}

} // namespace maf::nl80211