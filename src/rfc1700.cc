#include "rfc1700.hh"

namespace maf::rfc1700 {

const char *kHardwareTypeNames[] = {"Not hardware address",
                                    "Ethernet (10Mb)",
                                    "Experimental Ethernet (3Mb)",
                                    "Amateur Radio AX.25",
                                    "Proteon ProNET Token Ring",
                                    "Chaos",
                                    "IEEE 802 Networks",
                                    "ARCNET",
                                    "Hyperchannel",
                                    "Lanstar",
                                    "Autonet Short Address",
                                    "LocalTalk",
                                    "LocalNet (IBM PCNet or SYTEK LocalNET)",
                                    "Ultra link",
                                    "SMDS",
                                    "Frame Relay",
                                    "Asynchronous Transmission Mode (ATM)",
                                    "HDLC",
                                    "Fibre Channel",
                                    "Asynchronous Transmission Mode (ATM)",
                                    "Serial Line",
                                    "Asynchronous Transmission Mode (ATM)"};

Str HardwareTypeToStr(U8 type) {
  if (type < sizeof(kHardwareTypeNames) / sizeof(kHardwareTypeNames[0])) {
    return kHardwareTypeNames[type];
  }
  return "Unknown hardware type " + ToStr(type);
}

} // namespace maf::rfc1700