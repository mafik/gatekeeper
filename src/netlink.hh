#pragma once

#include <cassert>
#include <linux/netlink.h>

#include "epoll.hh"
#include "fn.hh"
#include "format.hh"
#include "span.hh"
#include "status.hh"

namespace maf {

// Netlink allows communication with the Linux kernel via a packet-oriented IPC.
//
// This class wraps the netlink socket and provides methods for sending and
// receiving messages.
//
// Users of this class should be intimately familiar with the netlink protocol.
// See: https://docs.kernel.org/userspace-api/netlink/intro.html.
struct Netlink : epoll::Listener {

  using MessageType = U16;

  struct Attr;

  struct Attrs {
    struct iterator {
      Attr *attr;
      iterator &operator++() {
        attr = (Attr *)((uintptr_t)attr + ((attr->len + 3) & ~3));
        return *this;
      }
      bool operator!=(const iterator &other) const {
        return attr != other.attr;
      }
      Attr &operator*() const { return *attr; }
    };

    char *ptr;
    Size size;

    template <typename T> T &RemovePrefixHeader(Status &status) {
      T &ret = *(T *)ptr;
      if (size < sizeof(T)) {
        AppendErrorMessage(status) +=
            f("Netlink message too small to contain %s (%d vs %d bytes)",
              typeid(T).name(), size, sizeof(T));
      } else {
        Size header_size = NLA_ALIGN(sizeof(T));
        ptr += header_size;
        if (size >= header_size)
          size -= header_size;
        else
          size = 0;
      }
      return ret;
    }

    iterator begin() const { return {(Attr *)ptr}; }
    iterator end() const { return {(Attr *)(ptr + ((size + 3) & ~3))}; }
  };

  // C++ sibling of `struct nlattr` from <linux/netlink.h>.
  struct alignas(4) Attr {
    U16 len; // Length includes the header but not the trailing padding!
    // bool nested : 1; // Nested attribute flag.
    U16 type : 14; // Enum value (based on nlmsghdr.nlmsg_type)
    bool big_endian : 1;
    bool nested : 1;
    char payload[0]; // Helper for accessing the payload

    Attr(U16 len, U16 type) : len(len), type(type) {}

    // Payload is stored immediately after Attr. Copying it to a different
    // place in memory would miss the payload.
    Attr(const Attr &) = delete;

    Span<> Span() { return {payload, len - sizeof(*this)}; }
    template <typename T> T &As() {
      assert(len == sizeof(*this) + sizeof(T));
      return *(T *)payload;
    }
    Attrs Unnest() {
      return Attrs{
          .ptr = payload,
          .size = len - sizeof(*this),
      };
    }
  };

  static_assert(sizeof(Attr) == 4, "Netlink::Attr must be 4 bytes");

  // The sequence number of the next message to be sent.
  U32 seq = 1;

  int protocol = -1;
  U32 fixed_message_size = 0;

  // Establishes connection with the specified netlink protocol.
  //
  // See: #include <linux/netlink.h> for a list of protocols.
  //
  // See: https://docs.kernel.org/userspace-api/netlink/intro.html for an
  // explanation of NETLINK_GENERIC protocol.
  Netlink(int protocol, Status &status);

  using ReceiveCallback = Fn<void(MessageType, Attrs)>;

  ReceiveCallback epoll_callback;

  const char *Name() const override;
  void NotifyRead(Status &) override;

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

  // Receive one or more netlink messages.
  //
  // Each netlink message is composed of a header, a fixed-size struct & a
  // sequence of attributes.
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
  // Errors will be reported through the `status` argument.
  void Receive(ReceiveCallback, Status &);

  void ReceiveAck(Status &);

  template <MessageType expected_type, typename T>
  void ReceiveT(Fn<void(T &message, Attrs)> cb, Status &status) {
    Receive(
        [&](MessageType message_type, Attrs attrs) {
          if (message_type != expected_type) {
            AppendErrorMessage(status) +=
                "Unexpected message type: 0x" + f("%04hx", message_type);
            return;
          }
          T &message = attrs.RemovePrefixHeader<T>(status);
          RETURN_ON_ERROR(status);
          cb(message, attrs);
        },
        status);
  }
};

} // namespace maf