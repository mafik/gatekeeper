#include "wifi.hh"

#include <csignal>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/nl80211.h>
#include <sys/socket.h>

#include "aes.hh"
#include "buffer_builder.hh"
#include "eap.hh"
#include "expirable.hh"
#include "hex.hh"
#include "hmac.hh"
#include "log.hh"
#include "nl80211.hh"
#include "pbkdf2.hh"
#include "proc.hh"
#include "random.hh"
#include "sha.hh"
#include "sock_diag.hh"
#include "span.hh"
#include "status.hh"
#include "systemd.hh"

namespace maf::wifi {

// #define DEBUG_WIFI 1

// See section 9.4.2.25 RSNE
struct RSNE_WPA2 {
  nl80211::ElementID tag_number = nl80211::ElementID::RSN;
  U8 length = sizeof(*this) - 2;
  U16 version = 1;
  Big<U32> group_cipher_suite = (U32)nl80211::CipherSuite::CCMP;
  U16 pairwise_cipher_suite_count = 1;
  Big<U32> pairwise_cipher_suite = (U32)nl80211::CipherSuite::CCMP;
  U16 akm_suite_count = 1;
  Big<U32> akm_suite = (U32)nl80211::AuthenticationKeyManagement::PSK;
  nl80211::RSNCapabilities capabilities = {
      .gtksa_replay_counter_usage =
          nl80211::ReplayCountersUsage::SIXTEEN, // Required by WMM
  };
} __attribute__((packed));

static constexpr RSNE_WPA2 kRSNE = {};

static void PRF(Span<> out, Span<> key, StrView a_label, Span<> b) {
  const U8 n = (out.size() + sizeof(SHA1) - 1) / sizeof(SHA1);
  for (U8 i = 0; i < n; ++i) {
    BufferBuilder m;
    m.AppendRange(a_label);
    m.AppendPrimitive<U8>(0);
    m.AppendRange(b);
    m.AppendPrimitive<U8>(i);
    auto hash = HMAC<SHA1>(key, m);
    memcpy(out.data() + i * sizeof(SHA1), hash.bytes,
           std::min(sizeof(SHA1), out.size() - i * sizeof(SHA1)));
  }
}

static void AppendElementRange(BufferBuilder &builder, nl80211::ElementID id,
                               auto data) {
  builder.AppendPrimitive(id);
  builder.AppendPrimitive((U8)data.size());
  builder.AppendRange(data);
};

static void AppendElementPrimitive(BufferBuilder &builder,
                                   nl80211::ElementID id, auto data) {
  builder.AppendPrimitive(id);
  builder.AppendPrimitive((U8)sizeof(data));
  builder.AppendPrimitive(data);
};

struct EAPOLReceiver : epoll::Listener {
  EAPOLReceiver(Status &status)
      : epoll::Listener(socket(AF_PACKET,
                               SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                               htons(ETH_P_PAE))) {
    if (fd == -1) {
      AppendErrorMessage(status) += "socket(AF_PACKET, SOCK_DGRAM, ETH_P_PAE)";
      return;
    }
  }

  void NotifyRead(Status &epoll_status) override;

  const char *Name() const override { return "EAPOLReceiver"; }
};

Optional<systemd::MaskGuard> wpa_supplicant_mask;
Optional<EAPOLReceiver> eapol_receiver;
Optional<nl80211::Netlink> mlme_netlink;
std::vector<AccessPoint *> access_points;

static void OnNewStation(nl80211::Interface::Index ifindex, MAC mac,
                         Status &status);

// Parse netlink message & call appropriate "OnX" handler.
static void EpollCallback(GenericNetlink::Command cmd, Netlink::Attrs attrs) {
  Expirable::Expire();
  switch (cmd) {
  case NL80211_CMD_NEW_STATION: {
    Status status;
#if DEBUG_WIFI
    LOG << "New station:";
#endif
    MAC *mac = nullptr;
    nl80211::Interface::Index *ifindex = nullptr;
    for (auto &attr : attrs) {
      switch (attr.type) {
      case NL80211_ATTR_MAC:
        mac = &attr.As<MAC>();
#if DEBUG_WIFI
        LOG << "  MAC: " << mac->to_string();
#endif
        break;
      case NL80211_ATTR_IFINDEX:
        ifindex = &attr.As<nl80211::Interface::Index>();
#if DEBUG_WIFI
        LOG << "  Interface: " << *ifindex;
#endif
        break;
      case NL80211_ATTR_GENERATION:
        // Ignore
        break;
      case NL80211_ATTR_STA_INFO:
#if DEBUG_WIFI
        LOG << "  Station info: " << BytesToHex(attr.Span());
#endif
        break;
      case NL80211_ATTR_IE:
#if DEBUG_WIFI
        LOG << "  Information elements: " << BytesToHex(attr.Span());
#endif
        break;
      default:
#if DEBUG_WIFI
        LOG << "  " << nl80211::AttrToStr(attr.type) << ": "
            << HexDump(attr.Span());
#endif
        break;
      }
    }
    if (ifindex == nullptr) {
      ERROR << "NL80211_CMD_NEW_STATION without NL80211_ATTR_IFINDEX";
      return;
    }
    if (mac == nullptr) {
      ERROR << "NL80211_CMD_NEW_STATION without NL80211_ATTR_MAC";
      return;
    }
    OnNewStation(*ifindex, *mac, status);
    break;
  }
  case NL80211_CMD_DEL_STATION: {
    MAC *mac = nullptr;
    for (auto &attr : attrs) {
      switch (attr.type) {
      case NL80211_ATTR_MAC:
        mac = (MAC *)attr.Span().data();
        break;
      }
    }
#if DEBUG_WIFI
    LOG << "Del station: " << (mac ? mac->to_string() : "??");
#endif
    break;
  }
  default:
#if DEBUG_WIFI
    LOG << "AuthenticatorThread received " << nl80211::CmdToStr(cmd) << ":";
    for (auto &attr : attrs) {
      LOG << "  " << nl80211::AttrToStr(attr.type) << ": "
          << HexDump(attr.Span());
    }
#endif
    break;
  }
}

static void KillOtherEAPOLListeners(Status &status) {
  std::unordered_set<U32> inodes, pids;
  ScanPacketSockets(
      [&](PacketSocketDescription &desc) {
        if (desc.protocol == ETH_P_PAE)
          inodes.insert(desc.inode);
      },
      status);
  RETURN_ON_ERROR(status);
  if (inodes.empty()) {
    return;
  }
  for (U32 pid : ScanProcesses(status)) {
    for (auto opened_inode : ScanOpenedSockets(pid, status)) {
      RETURN_ON_ERROR(status);
      if (inodes.contains(opened_inode)) {
        pids.insert(pid);
        break;
      }
    }
  }
  if (pids.contains(getpid())) {
    AppendErrorMessage(status) += "EAPOLListener already running";
    return;
  }
  for (U32 pid : pids) {
    Status status_ignored;
    Str process_name = GetProcessName(pid, status_ignored);
    LOG << "Killing conflicting process \"" << process_name << "\" (PID=" << pid
        << ")";
    kill(pid, SIGKILL);
  }
}

static void Start(AccessPoint &ap, Status &status) {
  if (access_points.empty()) {
    wpa_supplicant_mask.emplace("wpa_supplicant");

    KillOtherEAPOLListeners(status);
    RETURN_ON_ERROR(status);

    eapol_receiver.emplace(status);
    RETURN_ON_ERROR(status);
    mlme_netlink.emplace(status);
    RETURN_ON_ERROR(status);

    mlme_netlink->gn.AddMembership("mlme", status);
    RETURN_ON_ERROR(status);
    mlme_netlink->gn.epoll_callback = EpollCallback;
    epoll::Add(&(mlme_netlink->gn.netlink), status);
    RETURN_ON_ERROR(status);

    epoll::Add(&*eapol_receiver, status);
    RETURN_ON_ERROR(status);
  }

  access_points.push_back(&ap);
}

static void Stop(AccessPoint &ap) {
  if (auto it = std::find(access_points.begin(), access_points.end(), &ap);
      it != access_points.end()) {
    access_points.erase(it);
  }
  if (access_points.empty()) {
    {
      Status status_ignore;
      epoll::Del(&*eapol_receiver, status_ignore);
    }
    eapol_receiver.reset();
    {
      Status status_ignore;
      epoll::Del(&(mlme_netlink->gn.netlink), status_ignore);
    }
    mlme_netlink.reset();
    wpa_supplicant_mask.reset();
  }
}

AccessPoint::AccessPoint(const Interface &if_ctrl, Band, StrView ssid,
                         StrView password, Status &status)
    : netlink(status) {
  RETURN_ON_ERROR(status);

  RandomBytesSecure(gtk);
#if DEBUG_WIFI
  LOG << "GTK: " << BytesToHex(gtk);
#endif

  PBKDF2<SHA1>(psk, password, ssid, 4096);

  Start(*this, status);
  RETURN_ON_ERROR(status);

  auto wiphys = netlink.GetWiphys(status);
  RETURN_ON_ERROR(status);

  auto &wiphy = wiphys.front();

  nl80211::Band *band = nullptr;
  for (auto &band_it : wiphy.bands) {
    if (band_it.nl80211_band == NL80211_BAND_5GHZ) {
      band = &band_it;
      break;
    }
  }
  if (band == nullptr) {
    AppendErrorMessage(status) += "No 5GHz band";
    return;
  }

  {
    auto interfaces = netlink.GetInterfaces(status);
    RETURN_ON_ERROR(status);
    bool found = false;
    for (auto &i : interfaces) {
      if (i.index == if_ctrl.index) {
        this->iface = i;
        found = true;
        break;
      }
    }
    if (!found) {
      AppendErrorMessage(status) +=
          "Wireless interface " + std::to_string(if_ctrl.index) + " not found";
      return;
    }
  }

  if (iface.type != NL80211_IFTYPE_AP) {
    netlink.SetInterfaceType(iface.index, NL80211_IFTYPE_AP, status);
    RETURN_ON_ERROR(status);
    iface.type = NL80211_IFTYPE_AP;
  }

  U8 channel = 100;

  BufferBuilder beacon_head;
  BufferBuilder beacon_tail;
  BufferBuilder ie;
  BufferBuilder ie_probe_resp;
  BufferBuilder ie_assoc_resp;

  nl80211::BeaconHeader beacon_header(iface.mac);
  beacon_head.AppendPrimitive(beacon_header);

  AppendElementRange(beacon_head, nl80211::ElementID::SSID, ssid);
  // TODO: compute supported rates
  // See `hostapd_prepare_rates` from `hw_features.c` in hostapd
  // See `hostapd_eid_supp_rates` from `iee802_11.c` in hostapd
  AppendElementRange(
      beacon_head, nl80211::ElementID::SUPPORTED_RATES,
      Arr<U8, 8>{0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c});
  AppendElementPrimitive(beacon_head, nl80211::ElementID::DSSS_PARAMETER_SET,
                         (U8)channel);

  beacon_tail.AppendPrimitive(kRSNE);

  { // HT Capabilities
    BufferBuilder ht_capabilities;
    ht_capabilities.AppendPrimitive(band->ht->capa);
    U8 a_mpdu_parameters = 0;
    a_mpdu_parameters |= band->ht->ampdu_factor;
    a_mpdu_parameters |= band->ht->ampdu_density << 2;
    ht_capabilities.AppendPrimitive(a_mpdu_parameters);
    ht_capabilities.AppendRange(band->ht->mcs_set);
    ht_capabilities.AppendPrimitive((U16)0); // HT Extended Capabilities
    ht_capabilities.AppendPrimitive(
        (U32)0);                            // Transmit Beamforming Capabilities
    ht_capabilities.AppendPrimitive((U8)0); // Antenna Selection Capabilities
    AppendElementRange(beacon_tail, nl80211::ElementID::HT_CAPABILITIES,
                       (Span<>)ht_capabilities);
  }

  { // HT Operation
    BufferBuilder ht_operation;
    ht_operation.AppendPrimitive((U8)channel);
    ht_operation.AppendPrimitive(
        (U8)0x5); // Secondary Channel Offset = 1, STA Channel Width = 1
    ht_operation.AppendPrimitive((U32)0); // Everything else set to 0
    // Blank Basic HT-MCS Set
    ht_operation.buffer.insert(ht_operation.buffer.end(), 16, 0);
    AppendElementRange(beacon_tail, nl80211::ElementID::HT_OPERATION,
                       (Span<>)ht_operation);
  }

  { // Extended Capabilities
    BufferBuilder extended_capabilities;
    // See: `hostapd_eid_ext_capab`
    extended_capabilities.AppendPrimitive((U8)0x00);
    extended_capabilities.AppendPrimitive((U8)0x00);
    extended_capabilities.AppendPrimitive((U8)0x00);
    extended_capabilities.AppendPrimitive((U8)0x02); // SSID list
    AppendElementRange(beacon_tail, nl80211::ElementID::EXTENDED_CAPABILITIES,
                       (Span<>)extended_capabilities);
    AppendElementRange(ie, nl80211::ElementID::EXTENDED_CAPABILITIES,
                       (Span<>)extended_capabilities);
    AppendElementRange(ie_probe_resp, nl80211::ElementID::EXTENDED_CAPABILITIES,
                       (Span<>)extended_capabilities);
    AppendElementRange(ie_assoc_resp, nl80211::ElementID::EXTENDED_CAPABILITIES,
                       (Span<>)extended_capabilities);
  }

  { // VHT Capabilities
    BufferBuilder vht_capabilities;
    vht_capabilities.AppendPrimitive(band->vht->capa);
    vht_capabilities.buffer.insert(vht_capabilities.buffer.end(),
                                   band->vht->mcs_set.begin(),
                                   band->vht->mcs_set.end());
    AppendElementRange(beacon_tail, nl80211::ElementID::VHT_CAPABILITIES,
                       (Span<>)vht_capabilities);
  }

  { // VHT Operation
    BufferBuilder vht_operation;
    vht_operation.AppendPrimitive(nl80211::VHTOperationInformation{
        .channel_width = nl80211::VHTOperationInformation::
            CHANNEL_WIDTH_80MHZ_160MHZ_80_80MHZ,
        .channel_center_frequency_segment_0 = 0,
        .channel_center_frequency_segment_1 = 0,
    });
    // Hardcode support for MCS 0-7 on 1 spatial stream.
    // IIUC this only affects bandwidth between STAs (not between STA and AP).
    vht_operation.AppendPrimitive(nl80211::VHT_MCS_NSS_Map{
        .spatial_streams_1 = nl80211::VHT_MCS_NSS_Map::MCS_0_7,
        .spatial_streams_2 = nl80211::VHT_MCS_NSS_Map::NOT_SUPPORTED,
        .spatial_streams_3 = nl80211::VHT_MCS_NSS_Map::NOT_SUPPORTED,
        .spatial_streams_4 = nl80211::VHT_MCS_NSS_Map::NOT_SUPPORTED,
        .spatial_streams_5 = nl80211::VHT_MCS_NSS_Map::NOT_SUPPORTED,
        .spatial_streams_6 = nl80211::VHT_MCS_NSS_Map::NOT_SUPPORTED,
        .spatial_streams_7 = nl80211::VHT_MCS_NSS_Map::NOT_SUPPORTED,
        .spatial_streams_8 = nl80211::VHT_MCS_NSS_Map::NOT_SUPPORTED,
    });
    AppendElementRange(beacon_tail, nl80211::ElementID::VHT_OPERATION,
                       (Span<>)vht_operation);
  }

  { // TX Power Envelope
    // TODO: Get this from the regulatory domain
    BufferBuilder tx_power_envelope;
    tx_power_envelope.AppendPrimitive((U8)2);   // 20 MHz, 40 MHz & 80 MHz
    tx_power_envelope.AppendPrimitive((U8)127); // 20 MHz
    tx_power_envelope.AppendPrimitive((U8)127); // 40 MHz
    tx_power_envelope.AppendPrimitive((U8)127); // 80 MHz
    AppendElementRange(beacon_tail, nl80211::ElementID::TRANSMIT_POWER_ENVELOPE,
                       (Span<>)tx_power_envelope);
  }

  { // WMM
    // See `hostapd_eid_wmm`
    BufferBuilder wmm_parameter;
    AppendBigEndian(wmm_parameter.buffer, (U24)0x0050F2);
    wmm_parameter.AppendPrimitive((U8)2); // Type
    wmm_parameter.AppendPrimitive((U8)1); // Subtype
    wmm_parameter.AppendPrimitive((U8)1); // WMM version 1.0
    wmm_parameter.AppendPrimitive(nl80211::wmm::QoS_Info_AP{
        .edca_parameter_set_count = 1,
        .q_ack = 0,
        .queue_request = 0,
        .txop_request = 0,
        .uapsd = 0,
    });
    wmm_parameter.AppendPrimitive((U8)0); // Reserved
    wmm_parameter.AppendPrimitive(nl80211::wmm::AC_Parameter{
        .aifsn = 3,
        .aci = nl80211::wmm::AC::BE,
        .ecw_min = 4,
        .ecw_max = 10,
    });
    wmm_parameter.AppendPrimitive(nl80211::wmm::AC_Parameter{
        .aifsn = 7,
        .aci = nl80211::wmm::AC::BK,
        .ecw_min = 4,
        .ecw_max = 10,
    });
    wmm_parameter.AppendPrimitive(nl80211::wmm::AC_Parameter{
        .aifsn = 2,
        .aci = nl80211::wmm::AC::VI,
        .ecw_min = 3,
        .ecw_max = 4,
        .txop_limit = 94,
    });
    wmm_parameter.AppendPrimitive(nl80211::wmm::AC_Parameter{
        .aifsn = 2,
        .aci = nl80211::wmm::AC::VO,
        .ecw_min = 2,
        .ecw_max = 3,
        .txop_limit = 47,
    });
    AppendElementRange(beacon_tail, nl80211::ElementID::VENDOR_SPECIFIC,
                       (Span<>)wmm_parameter);
  }

  if_ctrl.BringUp(status);
  RETURN_ON_ERROR(status);

  // TODO: compute the frequencies
  netlink.SetChannel(iface.index, 5500, NL80211_CHAN_WIDTH_80, 5530, status);
  RETURN_ON_ERROR(status);

  nl80211::AuthenticationKeyManagement akm_suites[] = {
      nl80211::AuthenticationKeyManagement::PSK,
  };
  nl80211::CipherSuite ciphers[] = {
      nl80211::CipherSuite::CCMP,
  };

  netlink.StartAP(iface.index, beacon_head, beacon_tail, 100, 2, ssid,
                  NL80211_HIDDEN_SSID_NOT_IN_USE, true,
                  NL80211_AUTHTYPE_OPEN_SYSTEM, NL80211_WPA_VERSION_2,
                  akm_suites, ciphers, nl80211::CipherSuite::CCMP, ie,
                  ie_probe_resp, ie_assoc_resp, true, status);
  RETURN_ON_ERROR(status);

  /* // SetBSS results in ENOTSUPP
  char basic_rates[] = {0x0c, 0x18, 0x30};
  nl.SetBSS(iface.index, false, false, 0, false, basic_rates, status);
  RETURN_ON_ERROR(status);
  */

  /* // SetMulticastToUnicast results in ENOTSUPP
  nl.SetMulticastToUnicast(iface.index, false, status);
  RETURN_ON_ERROR(status);
  */

  { // Deauthenticate all stations
    MAC broadcast_mac = MAC::Broadcast();
    nl80211::DisconnectReason disconnect_reason = {
        .type = nl80211::DisconnectReason::DEAUTHENTICATION,
        .reason_code = nl80211::DisconnectReason::INVALID_AUTHENTICATION,
    };
    netlink.DelStation(iface.index, &broadcast_mac, &disconnect_reason, status);
    RETURN_ON_ERROR(status);
  }

  netlink.NewKey(iface.index, nullptr, gtk, nl80211::CipherSuite::CCMP, 1,
                 status);
  RETURN_ON_ERROR(status);
  netlink.SetKey(iface.index, 1, true, true, true, status);
  RETURN_ON_ERROR(status);
}

AccessPoint::~AccessPoint() { Stop(*this); }

static void PTK(Span<char, 48> ptk, Span<char, 32> psk, MAC ap_mac, MAC sta_mac,
                Span<char, 32> anonce, Span<char, 32> snonce) {
  static_assert(((char)0x80) > 0, "char must be unsigned");
  char msg[6 * 2 + 32 * 2];
  Span<char, 6> ap_mac_span((char *)&ap_mac, 6);
  Span<char, 6> sta_mac_span((char *)&sta_mac, 6);
  if (ap_mac_span < sta_mac_span) {
    memcpy(msg, ap_mac_span.data(), 6);
    memcpy(msg + 6, sta_mac_span.data(), 6);
  } else {
    memcpy(msg, sta_mac_span.data(), 6);
    memcpy(msg + 6, ap_mac_span.data(), 6);
  }
  if (anonce < snonce) {
    memcpy(msg + 6 * 2, anonce.data(), 32);
    memcpy(msg + 6 * 2 + 32, snonce.data(), 32);
  } else {
    memcpy(msg + 6 * 2, snonce.data(), 32);
    memcpy(msg + 6 * 2 + 32, anonce.data(), 32);
  }
  PRF(ptk, psk, "Pairwise key expansion"sv, msg);
}

static void SendEAPOL(U32 ifindex, MAC mac, Span<> eapol, Status &status) {
  sockaddr_ll sockaddr = {.sll_family = AF_PACKET,
                          .sll_protocol = htons(ETH_P_PAE),
                          .sll_ifindex = static_cast<int>(ifindex),
                          .sll_hatype = 0,  // not used for outgoing packets
                          .sll_pkttype = 0, // not used for outgoing packets
                          .sll_halen = 6,
                          .sll_addr = {mac.bytes[0], mac.bytes[1], mac.bytes[2],
                                       mac.bytes[3], mac.bytes[4],
                                       mac.bytes[5]}};
  int ret = sendto(eapol_receiver->fd, eapol.data(), eapol.size(), 0,
                   (struct sockaddr *)&sockaddr, sizeof(sockaddr_ll));
  if (ret == -1) {
    AppendErrorMessage(status) += "sendto";
  }
}

struct EAPOLKey {
  U8 protocol_version = 2;
  U8 packet_type = 3; // Key
  Big<U16> length;
  U8 key_descriptor_type = 2; // RSN
  eap::KeyInformation key_information;
  Big<U16> key_length = 0;
  Big<U64> replay_counter = 0;
  Arr<char, 32> nonce = {};
  Arr<char, 16> key_iv = {};
  Arr<char, 8> key_rsc = {};
  Arr<char, 8> key_id = {};
  Arr<char, 16> key_mic = {};
  Big<U16> key_data_length = 0;
  char key_data[0];

  static EAPOLKey *FromSpan(Span<> span, Status &status) {
    if (span.size() < sizeof(EAPOLKey)) {
      AppendErrorMessage(status) += "Message to small for EAPOL-Key";
      return nullptr;
    }
    EAPOLKey *ret = (EAPOLKey *)span.data();
    if (ret->length.Get() != span.size() - 4) {
      AppendErrorMessage(status) += "Wrong Packet Body Length";
    }
    if (ret->packet_type != 3) {
      AppendErrorMessage(status) += "Packet Type should equal 3";
    }
    if (ret->key_descriptor_type != 2) {
      AppendErrorMessage(status) += "Descriptor Type should equal 2";
    }
    if (ret->key_data_length.Get() != span.size() - sizeof(EAPOLKey)) {
      AppendErrorMessage(status) += "Wrong Key Data Length";
    }
    if (!OK(status)) {
      AppendErrorMessage(status) += "Invalid EAPOL-Key";
      return nullptr;
    }
    return ret;
  }

  Span<> AsSpan() {
    return Span<>((char *)this, sizeof(EAPOLKey) + key_data_length.Get());
  }

  bool CheckMIC(Span<char, 16> kck) {
    Arr<char, 16> original_mic = key_mic;
    key_mic.fill(0);
    auto expected_mic = HMAC<SHA1>(kck, AsSpan());
    Span<char, 16> expected_mic_span(expected_mic.bytes, 16);
    return expected_mic_span == Span<char, 16>(original_mic);
  }
} __attribute__((packed));

struct Handshake : Expirable, HashableByMAC<Handshake> {
  AccessPoint &ap;
  enum {
    kExpectingEAPOL2,
    kExpectingEAPOL4,
  } state;
  Arr<char, 32> anonce;
  union {
    Arr<char, 48> ptk;
    struct {
      Arr<char, 16> kck;
      Arr<char, 16> kek;
      Arr<char, 16> tk;
    };
  };

  Handshake(AccessPoint &ap, MAC mac)
      : Expirable(1s), HashableByMAC<Handshake>(mac), ap(ap),
        state(kExpectingEAPOL2) {}

  void HandleEAPOL(Span<> eapol, Status &status) {
    switch (state) {
    case kExpectingEAPOL2:
      HandleEAPOL2(eapol, status);
      break;
    case kExpectingEAPOL4:
      HandleEAPOL4(eapol, status);
      break;
    default:
      AppendErrorMessage(status) += "Unknown WPA-2 handshake state";
      break;
    }
  }

  void HandleEAPOL2(Span<> eapol2, Status &status) {
    EAPOLKey *eapol_key = EAPOLKey::FromSpan(eapol2, status);
    RETURN_ON_ERROR(status);
    static const eap::KeyInformation expected_key_information = {
        .key_mic = 1,
        .secure = 0,
        .error = 0,
        .request = 0,
        .encrypted_key_data = 0,
        .smk_message = 0,
        .key_descriptor_version = 2,
        .key_type_pairwise = true,
        .key_index = 0,
        .key_ack = 0,
    };
    eapol_key->key_information.Validate(expected_key_information, status);
    RETURN_ON_ERROR(status);

    PTK(ptk, ap.psk, ap.iface.mac, mac, anonce, eapol_key->nonce);

    if (!eapol_key->CheckMIC(kck)) {
      AppendErrorMessage(status) += "Invalid MIC";
      AppendErrorAdvice(status,
                        "This is usually caused by a wrong Wi-Fi password.");
      return;
    }

    state = Handshake::kExpectingEAPOL4;
    UpdateExpiration(1s);

#if DEBUG_WIFI
    LOG << "Successfully validated Handshake 2/4 for " << mac.to_string();
#endif
    AES aes_kek(kek);

    BufferBuilder eapol3(192);
    eapol3.AppendPrimitive((U8)0x02); // IEEE 802.1X-2004
    eapol3.AppendPrimitive((U8)0x03); // Key
    auto length_big_endian = eapol3.AppendPrimitive(Big<U16>(0));
    eapol3.AppendPrimitive((U8)0x02); // Key Descriptor Type (RSN)
    auto key_information = eap::KeyInformation{
        .key_mic = 1,
        .secure = 1,
        .encrypted_key_data = 1,
        .key_descriptor_version = 2,
        .key_type_pairwise = true,
        .install = true,
        .key_ack = 1,
    };
    eapol3.AppendPrimitive(key_information);
    eapol3.AppendPrimitive((U16)htons(16)); // Key Length
    eapol3.AppendPrimitive(Big<U64>(2));    // Replay Counter
    eapol3.AppendRange(anonce);
    eapol3.AppendZeroes(16);                                // Key IV
    eapol3.AppendZeroes(8);                                 // Key RSC
    eapol3.AppendZeroes(8);                                 // Key ID
    auto mic_ref = eapol3.AppendPrimitive(Arr<char, 16>()); // Key MIC
    auto key_data_length_ref = eapol3.AppendPrimitive(Big<U16>(0));

    BufferBuilder key_data;
    key_data.AppendPrimitive(kRSNE);
    Arr<char, 22> gtk_header{
        0x00,       0x0f,       0xac, // OUI
        0x01,                         // Type
        0x01,       0x00, // See "GTK KDE format" from IEEE 802.11-2016
        ap.gtk[0],  ap.gtk[1],  ap.gtk[2],  ap.gtk[3],  ap.gtk[4],  ap.gtk[5],
        ap.gtk[6],  ap.gtk[7],  ap.gtk[8],  ap.gtk[9],  ap.gtk[10], ap.gtk[11],
        ap.gtk[12], ap.gtk[13], ap.gtk[14], ap.gtk[15],
    };
    AppendElementRange(key_data, nl80211::ElementID::VENDOR_SPECIFIC,
                       gtk_header);
    if (key_data.Size() % 8) {
      key_data.AppendPrimitive<U8>(0xdd);
      if (key_data.Size() % 8) {
        key_data.AppendZeroes(8 - (key_data.Size() % 8));
      }
    }

    Span<U64> key_data_64((U64 *)key_data.buffer.data(),
                          key_data.buffer.size() / 8);

    U64 key_data_iv = aes_kek.WrapKey(key_data_64);
    eapol3.AppendPrimitive(key_data_iv);
    eapol3.AppendRange(key_data_64);

    key_data_length_ref->Set(key_data.Size() + 8);

    length_big_endian->Set(eapol3.Size() - 4);

    auto actual_mic = HMAC<SHA1>(kck, eapol3);
    memcpy(mic_ref->data(), actual_mic.bytes, 16);

    length_big_endian->Set(eapol3.Size() - 4);
    SendEAPOL(ap.iface.index, mac, eapol3, status);
    RETURN_ON_ERROR(status);
  }

  void HandleEAPOL4(Span<> eapol4, Status &status) {
    EAPOLKey *eapol_key = EAPOLKey::FromSpan(eapol4, status);
    RETURN_ON_ERROR(status);
    static const eap::KeyInformation expected_key_information = {
        .key_mic = 1,
        .secure = 1,
        .error = 0,
        .request = 0,
        .encrypted_key_data = 0,
        .smk_message = 0,
        .key_descriptor_version = 2,
        .key_type_pairwise = true,
        .key_index = 0,
        .key_ack = 0,
    };
    eapol_key->key_information.Validate(expected_key_information, status);
    RETURN_ON_ERROR(status);

    if (!eapol_key->CheckMIC(kck)) {
      AppendErrorMessage(status) += "Invalid MIC";
      AppendErrorAdvice(status,
                        "This is usually caused by a wrong Wi-Fi password.");
      return;
    }

#if DEBUG_WIFI
    LOG << "Successfully validated Handshake 4/4 for " << mac.to_string();
#endif

    ap.netlink.NewKey(ap.iface.index, &mac, tk, nl80211::CipherSuite::CCMP, 0,
                      status);
    RETURN_ON_ERROR(status);
    nl80211_sta_flags set_flags[] = {
        NL80211_STA_FLAG_AUTHORIZED,
    };
    ap.netlink.SetStation(ap.iface.index, mac, set_flags, {}, status);
    RETURN_ON_ERROR(status);
    delete this;
  }
};

void OnNewStation(nl80211::Interface::Index ifindex, MAC mac, Status &status) {
  AccessPoint *ap = nullptr;
  for (auto ap_it : access_points) {
    if (ap_it->iface.index == ifindex) {
      ap = ap_it;
      break;
    }
  }
  if (ap == nullptr) {
    AppendErrorMessage(status) +=
        "Received NL80211_CMD_NEW_STATION for wireless interface without "
        "active Access Point index " +
        std::to_string(ifindex);
    return;
  }
  nl80211_sta_flags clear_flags[] = {
      NL80211_STA_FLAG_AUTHORIZED,
      NL80211_STA_FLAG_SHORT_PREAMBLE,
      NL80211_STA_FLAG_WME,
      NL80211_STA_FLAG_MFP,
  };
  ap->netlink.SetStation(ifindex, mac, {}, clear_flags, status);
  if (!OK(status)) {
    ERROR << status;
    return;
  }
  Handshake *h = new Handshake(*ap, mac);
  RandomBytesSecure(h->anonce);

  BufferBuilder eapol(128);
  eapol.AppendPrimitive((U8)0x02); // IEEE 802.1X-2004
  eapol.AppendPrimitive((U8)0x03); // Key
  auto length_big_endian = eapol.AppendPrimitive(Big<U16>(0x0000));
  eapol.AppendPrimitive((U8)0x02); // Key Descriptor Type (RSN)
  auto key_information = eap::KeyInformation{
      .key_descriptor_version = 2,
      .key_type_pairwise = true,
      .key_ack = 1,
  };
  eapol.AppendPrimitive(key_information);
  eapol.AppendPrimitive((U16)htons(16)); // Key Length
  Big<U64> replay_ctr = 1;
  eapol.AppendPrimitive(replay_ctr);
  eapol.AppendRange(h->anonce);
  eapol.AppendZeroes(16);               // Key IV
  eapol.AppendZeroes(8);                // Key RSC
  eapol.AppendZeroes(8);                // Key ID
  eapol.AppendZeroes(16);               // Key MIC
  eapol.AppendPrimitive((U16)htons(0)); // Key Data Length

  length_big_endian->Set(eapol.Size() - 4);
  SendEAPOL(ifindex, mac, eapol, status);
  if (!OK(status)) {
    ERROR << status;
    status.Reset();
    return;
  }
#if DEBUG_WIFI
  LOG << "Sent Handshake 1/4 to " << mac.to_string();
#endif
}

void EAPOLReceiver::NotifyRead(Status &epoll_status) {
  char buf[2048];
  sockaddr_ll addr;
  socklen_t addr_len = sizeof(addr);
  int bytes_received =
      recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addr_len);
  if (bytes_received == -1) {
    // This will break out of the epoll::Loop
    AppendErrorMessage(epoll_status) += "recvfrom";
    return;
  }
  MAC mac(addr.sll_addr[0], addr.sll_addr[1], addr.sll_addr[2],
          addr.sll_addr[3], addr.sll_addr[4], addr.sll_addr[5]);
#if DEBUG_WIFI
  LOG << "Received " << bytes_received << " bytes from " << mac.to_string();
#endif
  Span<> eapol(buf, bytes_received);
  if (auto h = Handshake::Find(mac); h != nullptr) {
    Status status;
    h->HandleEAPOL(eapol, status);
    if (!OK(status)) {
      ERROR << status;
      return;
    }
  } else {
    ERROR << "Received EAPOL frame from unknown station " << mac.to_string();
    return;
  }
}

} // namespace maf::wifi