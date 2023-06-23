#pragma once

#include <functional>

#include <linux/netlink.h>
#include <span>

#include "fd.hh"
#include "status.hh"

namespace maf {

// Netlink allows communication with the Linux kernel via a packet-oriented IPC.
//
// This class wraps the netlink socket and provides methods for sending and
// receiving messages.
//
// Users of this class should be intimately familiar with the netlink protocol.
// See: https://docs.kernel.org/userspace-api/netlink/intro.html.
struct Netlink {

  // C++ sibling of `struct nlattr` from <linux/netlink.h>.
  struct Attr {
    uint16_t len;  // Length includes the header but not the trailing padding!
    uint16_t type; // Enum value (based on nlmsghdr.nlmsg_type)
    char c[0];     // Helper for accessing the payload

    std::string_view View() const { return {c, len - sizeof(*this)}; }
    template <typename T> T &As() { return *(T *)c; }
  };

  static_assert(sizeof(Attr) == 4, "NLAttr must be 4 bytes");

  // The netlink socket.
  FD fd;

  // The sequence number of the next message to be sent.
  uint32_t seq = 1;

  int protocol = -1;
  uint32_t fixed_message_size = 0;

  // Establishes connection with the specified netlink protocol.
  //
  // See: #include <linux/netlink.h> for a list of protocols.
  //
  // See: https://docs.kernel.org/userspace-api/netlink/intro.html for an
  // explanation of NETLINK_GENERIC protocol.
  Netlink(int protocol, Status &status);

  // Send a simple netlink message.
  //
  // The `msg.nlmsg_seq` will be updated with an incremented sequence number and
  // send in its own netlink packet.
  //
  // Optional `status` will be used instead of the default `status` of this
  // object to report errors.
  void Send(nlmsghdr &msg, Status &status);

  // Send a netlink message with a single extra attribute of variable size.
  //
  // This method allows sending large messages and attributes without having to
  // copy them into a continuous buffer.
  //
  // The `msg.nlmsg_seq` will be updated with an incremented sequence number and
  // send in its own netlink packet.
  //
  // The `msg.nlmsg_len` field will be updated to include `attr.nla_len`.
  //
  // Optional `status` will be used instead of the default `status` of this
  // object to report errors.
  void SendWithAttr(nlmsghdr &msg, Attr &attr, Status &status);

  // Send an arbitrary sequence of bytes as a netlink message.
  //
  // This can be used to efficiently send multiple messages in a single batch.
  //
  // Users of this method may want to manually update the sequence number of the
  // sent messages (it's not required but might help with tracking errors).
  //
  // Optional `status` will be used instead of the default `status` of this
  // object to report errors.
  void SendRaw(std::string_view, Status &status);

  using ReceiveCallback = std::function<void(uint16_t type, void *fixed_message,
                                             std::span<Attr *> attributes)>;

  // Receive one or more netlink messages.
  //
  // Each netlink message is composed of a header, a fixed-size struct & a
  // sequence of attributes. This method will predict the size of fixed size
  // struct and the maximum number of attributes based on message type.
  //
  // The `callback` will be called once for each response message received. For
  // `BATCH` requests it may be called multiple times - for each multipart
  // message.
  //
  // Note that many netlink messages do not generate any response unless
  // `NLM_F_ACK` is set in `nlmsghdr::nlmsg_flags`.
  //
  // This method will block so call it only if you expect a message.
  //
  // Errors will be reported using either the `status` argument or the `status`
  // field of this netlink connection.
  void Receive(ReceiveCallback callback, Status &status);
};

} // namespace maf