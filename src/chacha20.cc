#include "chacha20.hh"

namespace maf::rfc7539 {

ChaCha20::ChaCha20(Span<const U8, 32> key, U32 counter,
                   Span<const U8, 12> nonce)
    : constant{0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x33,
               0x32, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B},
      key{key[0],  key[1],  key[2],  key[3],  key[4],  key[5],  key[6],
          key[7],  key[8],  key[9],  key[10], key[11], key[12], key[13],
          key[14], key[15], key[16], key[17], key[18], key[19], key[20],
          key[21], key[22], key[23], key[24], key[25], key[26], key[27],
          key[28], key[29], key[30], key[31]},
      counter(counter),
      nonce{nonce[0], nonce[1], nonce[2], nonce[3], nonce[4],  nonce[5],
            nonce[6], nonce[7], nonce[8], nonce[9], nonce[10], nonce[11]} {}

#define U8V(v) ((U8)(v)&0xFFU)
#define U32V(v) ((U32)(v)&0xFFFFFFFFU)

#define ROTL32(v, n) (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define U8TO32_LITTLE(p)                                                       \
  (((U32)((p)[0])) | ((U32)((p)[1]) << 8) | ((U32)((p)[2]) << 16) |            \
   ((U32)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v)                                                    \
  do {                                                                         \
    (p)[0] = U8V((v));                                                         \
    (p)[1] = U8V((v) >> 8);                                                    \
    (p)[2] = U8V((v) >> 16);                                                   \
    (p)[3] = U8V((v) >> 24);                                                   \
  } while (0)

#define ROTATE(v, c) (ROTL32(v, c))
#define XOR(v, w) ((v) ^ (w))
#define PLUS(v, w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v), 1))

#define QUARTERROUND(a, b, c, d)                                               \
  a = PLUS(a, b);                                                              \
  d = ROTATE(XOR(d, a), 16);                                                   \
  c = PLUS(c, d);                                                              \
  b = ROTATE(XOR(b, c), 12);                                                   \
  a = PLUS(a, b);                                                              \
  d = ROTATE(XOR(d, a), 8);                                                    \
  c = PLUS(c, d);                                                              \
  b = ROTATE(XOR(b, c), 7);

void ChaCha20::Crypt(MemView mem) {
  U32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  I32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  U8 tmp[64];

  U32 *x_input = (U32 *)this;

  j0 = x_input[0];
  j1 = x_input[1];
  j2 = x_input[2];
  j3 = x_input[3];
  j4 = x_input[4];
  j5 = x_input[5];
  j6 = x_input[6];
  j7 = x_input[7];
  j8 = x_input[8];
  j9 = x_input[9];
  j10 = x_input[10];
  j11 = x_input[11];
  j12 = x_input[12];
  j13 = x_input[13];
  j14 = x_input[14];
  j15 = x_input[15];

  for (;;) {
    U8 *m = mem.data();
    if (mem.size() < 64) {
      for (int i = 0; i < mem.size(); ++i)
        tmp[i] = mem[i];
      m = tmp;
    }
    x0 = j0;
    x1 = j1;
    x2 = j2;
    x3 = j3;
    x4 = j4;
    x5 = j5;
    x6 = j6;
    x7 = j7;
    x8 = j8;
    x9 = j9;
    x10 = j10;
    x11 = j11;
    x12 = j12;
    x13 = j13;
    x14 = j14;
    x15 = j15;
    for (int i = 20; i > 0; i -= 2) {
      QUARTERROUND(x0, x4, x8, x12)
      QUARTERROUND(x1, x5, x9, x13)
      QUARTERROUND(x2, x6, x10, x14)
      QUARTERROUND(x3, x7, x11, x15)
      QUARTERROUND(x0, x5, x10, x15)
      QUARTERROUND(x1, x6, x11, x12)
      QUARTERROUND(x2, x7, x8, x13)
      QUARTERROUND(x3, x4, x9, x14)
    }
    x0 = PLUS(x0, j0);
    x1 = PLUS(x1, j1);
    x2 = PLUS(x2, j2);
    x3 = PLUS(x3, j3);
    x4 = PLUS(x4, j4);
    x5 = PLUS(x5, j5);
    x6 = PLUS(x6, j6);
    x7 = PLUS(x7, j7);
    x8 = PLUS(x8, j8);
    x9 = PLUS(x9, j9);
    x10 = PLUS(x10, j10);
    x11 = PLUS(x11, j11);
    x12 = PLUS(x12, j12);
    x13 = PLUS(x13, j13);
    x14 = PLUS(x14, j14);
    x15 = PLUS(x15, j15);

    x0 = XOR(x0, U8TO32_LITTLE(m + 0));
    x1 = XOR(x1, U8TO32_LITTLE(m + 4));
    x2 = XOR(x2, U8TO32_LITTLE(m + 8));
    x3 = XOR(x3, U8TO32_LITTLE(m + 12));
    x4 = XOR(x4, U8TO32_LITTLE(m + 16));
    x5 = XOR(x5, U8TO32_LITTLE(m + 20));
    x6 = XOR(x6, U8TO32_LITTLE(m + 24));
    x7 = XOR(x7, U8TO32_LITTLE(m + 28));
    x8 = XOR(x8, U8TO32_LITTLE(m + 32));
    x9 = XOR(x9, U8TO32_LITTLE(m + 36));
    x10 = XOR(x10, U8TO32_LITTLE(m + 40));
    x11 = XOR(x11, U8TO32_LITTLE(m + 44));
    x12 = XOR(x12, U8TO32_LITTLE(m + 48));
    x13 = XOR(x13, U8TO32_LITTLE(m + 52));
    x14 = XOR(x14, U8TO32_LITTLE(m + 56));
    x15 = XOR(x15, U8TO32_LITTLE(m + 60));

    j12 = PLUSONE(j12);
    if (!j12) {
      j13 = PLUSONE(j13);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }

    U32TO8_LITTLE(m + 0, x0);
    U32TO8_LITTLE(m + 4, x1);
    U32TO8_LITTLE(m + 8, x2);
    U32TO8_LITTLE(m + 12, x3);
    U32TO8_LITTLE(m + 16, x4);
    U32TO8_LITTLE(m + 20, x5);
    U32TO8_LITTLE(m + 24, x6);
    U32TO8_LITTLE(m + 28, x7);
    U32TO8_LITTLE(m + 32, x8);
    U32TO8_LITTLE(m + 36, x9);
    U32TO8_LITTLE(m + 40, x10);
    U32TO8_LITTLE(m + 44, x11);
    U32TO8_LITTLE(m + 48, x12);
    U32TO8_LITTLE(m + 52, x13);
    U32TO8_LITTLE(m + 56, x14);
    U32TO8_LITTLE(m + 60, x15);

    if (mem.size() <= 64) {
      if (mem.size() < 64) {
        for (int i = 0; i < mem.size(); ++i)
          mem[i] = m[i];
      }
      x_input[12] = j12;
      x_input[13] = j13;
      return;
    }
    mem = mem.subspan(64);
  }
}

} // namespace maf::rfc7539