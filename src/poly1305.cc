#include "poly1305.hh"

#include "int.hh"

// From https://github.com/floodyberry/poly1305-donna (public domain)
namespace maf {

#define MUL(out, x, y) out = ((U128)x * y)
#define ADD(out, in) out += in
#define ADDLO(out, in) out += in
#define SHR(in, shift) (U64)(in >> (shift))
#define LO(in) (U64)(in)

/* interpret eight 8 bit unsigned integers as a 64 bit unsigned integer in
 * little endian */
static U64 U8TO64(const char *p) {
  return (((U64)(p[0] & 0xff)) | ((U64)(p[1] & 0xff) << 8) |
          ((U64)(p[2] & 0xff) << 16) | ((U64)(p[3] & 0xff) << 24) |
          ((U64)(p[4] & 0xff) << 32) | ((U64)(p[5] & 0xff) << 40) |
          ((U64)(p[6] & 0xff) << 48) | ((U64)(p[7] & 0xff) << 56));
}

/* store a 64 bit unsigned integer as eight 8 bit unsigned integers in little
 * endian */
static void U64TO8(char *p, U64 v) {
  p[0] = (v) & 0xff;
  p[1] = (v >> 8) & 0xff;
  p[2] = (v >> 16) & 0xff;
  p[3] = (v >> 24) & 0xff;
  p[4] = (v >> 32) & 0xff;
  p[5] = (v >> 40) & 0xff;
  p[6] = (v >> 48) & 0xff;
  p[7] = (v >> 56) & 0xff;
}

static void Blocks(Poly1305::Builder &builder, Span<> m) {
  const U64 hibit = (builder.final) ? 0 : ((U64)1 << 40); /* 1 << 128 */
  U64 r0, r1, r2;
  U64 s1, s2;
  U64 h0, h1, h2;
  U64 c;
  U128 d0, d1, d2, d;

  r0 = builder.r[0];
  r1 = builder.r[1];
  r2 = builder.r[2];

  h0 = builder.h[0];
  h1 = builder.h[1];
  h2 = builder.h[2];

  s1 = r1 * (5 << 2);
  s2 = r2 * (5 << 2);

  while (m.size() >= Poly1305::kBlockSize) {
    U64 t0, t1;

    /* h += m[i] */
    t0 = U8TO64(&m[0]);
    t1 = U8TO64(&m[8]);

    h0 += ((t0) & 0xfffffffffff);
    h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
    h2 += (((t1 >> 24)) & 0x3ffffffffff) | hibit;

    /* h *= r */
    MUL(d0, h0, r0);
    MUL(d, h1, s2);
    ADD(d0, d);
    MUL(d, h2, s1);
    ADD(d0, d);
    MUL(d1, h0, r1);
    MUL(d, h1, r0);
    ADD(d1, d);
    MUL(d, h2, s2);
    ADD(d1, d);
    MUL(d2, h0, r2);
    MUL(d, h1, r1);
    ADD(d2, d);
    MUL(d, h2, r0);
    ADD(d2, d);

    /* (partial) h %= p */
    c = SHR(d0, 44);
    h0 = LO(d0) & 0xfffffffffff;
    ADDLO(d1, c);
    c = SHR(d1, 44);
    h1 = LO(d1) & 0xfffffffffff;
    ADDLO(d2, c);
    c = SHR(d2, 42);
    h2 = LO(d2) & 0x3ffffffffff;
    h0 += c * 5;
    c = (h0 >> 44);
    h0 = h0 & 0xfffffffffff;
    h1 += c;

    m = m.subspan(Poly1305::kBlockSize);
  }

  builder.h[0] = h0;
  builder.h[1] = h1;
  builder.h[2] = h2;
}

static void FinalizeTo(Poly1305::Builder &builder, Poly1305 &mac) {
  U64 h0, h1, h2, c;
  U64 g0, g1, g2;
  U64 t0, t1;

  /* process the remaining block */
  if (builder.leftover) {
    size_t i = builder.leftover;
    builder.buffer[i] = 1;
    for (i = i + 1; i < Poly1305::kBlockSize; i++)
      builder.buffer[i] = 0;
    builder.final = 1;
    Blocks(builder, builder.buffer);
  }

  /* fully carry h */
  h0 = builder.h[0];
  h1 = builder.h[1];
  h2 = builder.h[2];

  c = (h1 >> 44);
  h1 &= 0xfffffffffff;
  h2 += c;
  c = (h2 >> 42);
  h2 &= 0x3ffffffffff;
  h0 += c * 5;
  c = (h0 >> 44);
  h0 &= 0xfffffffffff;
  h1 += c;
  c = (h1 >> 44);
  h1 &= 0xfffffffffff;
  h2 += c;
  c = (h2 >> 42);
  h2 &= 0x3ffffffffff;
  h0 += c * 5;
  c = (h0 >> 44);
  h0 &= 0xfffffffffff;
  h1 += c;

  /* compute h + -p */
  g0 = h0 + 5;
  c = (g0 >> 44);
  g0 &= 0xfffffffffff;
  g1 = h1 + c;
  c = (g1 >> 44);
  g1 &= 0xfffffffffff;
  g2 = h2 + c - ((U64)1 << 42);

  /* select h if h < p, or h + -p if h >= p */
  c = (g2 >> ((sizeof(U64) * 8) - 1)) - 1;
  g0 &= c;
  g1 &= c;
  g2 &= c;
  c = ~c;
  h0 = (h0 & c) | g0;
  h1 = (h1 & c) | g1;
  h2 = (h2 & c) | g2;

  /* h = (h + pad) */
  t0 = builder.pad[0];
  t1 = builder.pad[1];

  h0 += ((t0) & 0xfffffffffff);
  c = (h0 >> 44);
  h0 &= 0xfffffffffff;
  h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c;
  c = (h1 >> 44);
  h1 &= 0xfffffffffff;
  h2 += (((t1 >> 24)) & 0x3ffffffffff) + c;
  h2 &= 0x3ffffffffff;

  /* mac = h % (2^128) */
  h0 = ((h0) | (h1 << 44));
  h1 = ((h1 >> 20) | (h2 << 24));

  U64TO8(mac.bytes, h0);
  U64TO8(mac.bytes + 8, h1);

  /* zero out the state */
  builder.h[0] = 0;
  builder.h[1] = 0;
  builder.h[2] = 0;
  builder.r[0] = 0;
  builder.r[1] = 0;
  builder.r[2] = 0;
  builder.pad[0] = 0;
  builder.pad[1] = 0;
}

Poly1305::Poly1305(Span<char, 16> b)
    : bytes{b[0], b[1], b[2],  b[3],  b[4],  b[5],  b[6],  b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]} {}

Poly1305::Poly1305(Span<> m, Span<char, 32> key) {
  Builder builder(key);
  builder.Update(m);
  FinalizeTo(builder, *this);
}

Poly1305::Builder::Builder(Span<char, 32> key) {
  U64 t0, t1;

  /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
  t0 = U8TO64(&key[0]);
  t1 = U8TO64(&key[8]);

  r[0] = (t0) & 0xffc0fffffff;
  r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
  r[2] = ((t1 >> 24)) & 0x00ffffffc0f;

  /* h = 0 */
  h[0] = 0;
  h[1] = 0;
  h[2] = 0;

  /* save pad for later */
  pad[0] = U8TO64(&key[16]);
  pad[1] = U8TO64(&key[24]);

  leftover = 0;
  final = 0;
}

Poly1305::Builder &Poly1305::Builder::Update(Span<> m) {
  size_t i;

  /* handle leftover */
  if (leftover) {
    size_t want = (Poly1305::kBlockSize - leftover);
    if (want > m.size())
      want = m.size();
    for (i = 0; i < want; i++)
      buffer[leftover + i] = m[i];
    m = m.subspan(want);
    leftover += want;
    if (leftover < Poly1305::kBlockSize)
      return *this;
    Blocks(*this, buffer);
    leftover = 0;
  }

  /* process full blocks */
  if (m.size() >= Poly1305::kBlockSize) {
    size_t want = (m.size() & ~(Poly1305::kBlockSize - 1));
    Blocks(*this, m.subspan(0, want));
    m = m.subspan(want);
  }

  /* store leftover */
  if (m.size()) {
    for (i = 0; i < m.size(); i++)
      buffer[leftover + i] = m[i];
    leftover += m.size();
  }

  return *this;
}

Poly1305 Poly1305::Builder::Finalize() {
  Poly1305 ret;
  FinalizeTo(*this, ret);
  return ret;
}

} // namespace maf