#include "sha.hh"

#include <bit>
#include <cstring>

// From https://github.com/vog/sha1 (public domain)
namespace {

static constexpr size_t BLOCK_INTS = 16;
static constexpr size_t BLOCK_BYTES = BLOCK_INTS * 4;

inline static uint32_t rol(const uint32_t value, const size_t bits) {
  return (value << bits) | (value >> (32 - bits));
}

inline static uint32_t blk(const uint32_t block[BLOCK_INTS], const size_t i) {
  return rol(block[(i + 13) & 15] ^ block[(i + 8) & 15] ^ block[(i + 2) & 15] ^
                 block[i],
             1);
}

/*
 * (R0+R1), R2, R3, R4 are the different operations used in SHA1
 */

inline static void R0(const uint32_t block[BLOCK_INTS], const uint32_t v,
                      uint32_t &w, const uint32_t x, const uint32_t y,
                      uint32_t &z, const size_t i) {
  z += ((w & (x ^ y)) ^ y) + block[i] + 0x5a827999 + rol(v, 5);
  w = rol(w, 30);
}

inline static void R1(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w,
                      const uint32_t x, const uint32_t y, uint32_t &z,
                      const size_t i) {
  block[i] = blk(block, i);
  z += ((w & (x ^ y)) ^ y) + block[i] + 0x5a827999 + rol(v, 5);
  w = rol(w, 30);
}

inline static void R2(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w,
                      const uint32_t x, const uint32_t y, uint32_t &z,
                      const size_t i) {
  block[i] = blk(block, i);
  z += (w ^ x ^ y) + block[i] + 0x6ed9eba1 + rol(v, 5);
  w = rol(w, 30);
}

inline static void R3(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w,
                      const uint32_t x, const uint32_t y, uint32_t &z,
                      const size_t i) {
  block[i] = blk(block, i);
  z += (((w | x) & y) | (w & x)) + block[i] + 0x8f1bbcdc + rol(v, 5);
  w = rol(w, 30);
}

inline static void R4(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w,
                      const uint32_t x, const uint32_t y, uint32_t &z,
                      const size_t i) {
  block[i] = blk(block, i);
  z += (w ^ x ^ y) + block[i] + 0xca62c1d6 + rol(v, 5);
  w = rol(w, 30);
}

/*
 * Hash a single 512-bit block. This is the core of the algorithm.
 */

inline static void transform(uint32_t digest[5], uint32_t block[BLOCK_INTS]) {
  /* Copy digest[] to working vars */
  uint32_t a = digest[0];
  uint32_t b = digest[1];
  uint32_t c = digest[2];
  uint32_t d = digest[3];
  uint32_t e = digest[4];

  /* 4 rounds of 20 operations each. Loop unrolled. */
  R0(block, a, b, c, d, e, 0);
  R0(block, e, a, b, c, d, 1);
  R0(block, d, e, a, b, c, 2);
  R0(block, c, d, e, a, b, 3);
  R0(block, b, c, d, e, a, 4);
  R0(block, a, b, c, d, e, 5);
  R0(block, e, a, b, c, d, 6);
  R0(block, d, e, a, b, c, 7);
  R0(block, c, d, e, a, b, 8);
  R0(block, b, c, d, e, a, 9);
  R0(block, a, b, c, d, e, 10);
  R0(block, e, a, b, c, d, 11);
  R0(block, d, e, a, b, c, 12);
  R0(block, c, d, e, a, b, 13);
  R0(block, b, c, d, e, a, 14);
  R0(block, a, b, c, d, e, 15);
  R1(block, e, a, b, c, d, 0);
  R1(block, d, e, a, b, c, 1);
  R1(block, c, d, e, a, b, 2);
  R1(block, b, c, d, e, a, 3);
  R2(block, a, b, c, d, e, 4);
  R2(block, e, a, b, c, d, 5);
  R2(block, d, e, a, b, c, 6);
  R2(block, c, d, e, a, b, 7);
  R2(block, b, c, d, e, a, 8);
  R2(block, a, b, c, d, e, 9);
  R2(block, e, a, b, c, d, 10);
  R2(block, d, e, a, b, c, 11);
  R2(block, c, d, e, a, b, 12);
  R2(block, b, c, d, e, a, 13);
  R2(block, a, b, c, d, e, 14);
  R2(block, e, a, b, c, d, 15);
  R2(block, d, e, a, b, c, 0);
  R2(block, c, d, e, a, b, 1);
  R2(block, b, c, d, e, a, 2);
  R2(block, a, b, c, d, e, 3);
  R2(block, e, a, b, c, d, 4);
  R2(block, d, e, a, b, c, 5);
  R2(block, c, d, e, a, b, 6);
  R2(block, b, c, d, e, a, 7);
  R3(block, a, b, c, d, e, 8);
  R3(block, e, a, b, c, d, 9);
  R3(block, d, e, a, b, c, 10);
  R3(block, c, d, e, a, b, 11);
  R3(block, b, c, d, e, a, 12);
  R3(block, a, b, c, d, e, 13);
  R3(block, e, a, b, c, d, 14);
  R3(block, d, e, a, b, c, 15);
  R3(block, c, d, e, a, b, 0);
  R3(block, b, c, d, e, a, 1);
  R3(block, a, b, c, d, e, 2);
  R3(block, e, a, b, c, d, 3);
  R3(block, d, e, a, b, c, 4);
  R3(block, c, d, e, a, b, 5);
  R3(block, b, c, d, e, a, 6);
  R3(block, a, b, c, d, e, 7);
  R3(block, e, a, b, c, d, 8);
  R3(block, d, e, a, b, c, 9);
  R3(block, c, d, e, a, b, 10);
  R3(block, b, c, d, e, a, 11);
  R4(block, a, b, c, d, e, 12);
  R4(block, e, a, b, c, d, 13);
  R4(block, d, e, a, b, c, 14);
  R4(block, c, d, e, a, b, 15);
  R4(block, b, c, d, e, a, 0);
  R4(block, a, b, c, d, e, 1);
  R4(block, e, a, b, c, d, 2);
  R4(block, d, e, a, b, c, 3);
  R4(block, c, d, e, a, b, 4);
  R4(block, b, c, d, e, a, 5);
  R4(block, a, b, c, d, e, 6);
  R4(block, e, a, b, c, d, 7);
  R4(block, d, e, a, b, c, 8);
  R4(block, c, d, e, a, b, 9);
  R4(block, b, c, d, e, a, 10);
  R4(block, a, b, c, d, e, 11);
  R4(block, e, a, b, c, d, 12);
  R4(block, d, e, a, b, c, 13);
  R4(block, c, d, e, a, b, 14);
  R4(block, b, c, d, e, a, 15);

  /* Add the working vars back into digest[] */
  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
}

inline static void buffer_to_block(const char buffer[BLOCK_BYTES],
                                   uint32_t block[BLOCK_INTS]) {
  /* Convert the std::string (byte buffer) to a uint32_t array (MSB) */
  for (size_t i = 0; i < BLOCK_INTS; i++) {
    block[i] = (buffer[4 * i + 3] & 0xff) | (buffer[4 * i + 2] & 0xff) << 8 |
               (buffer[4 * i + 1] & 0xff) << 16 |
               (buffer[4 * i + 0] & 0xff) << 24;
  }
}

} // namespace

// From https://github.com/WaterJuice/WjCryptLib (public domain)
namespace {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  MACROS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define ROR64(value, bits) (((value) >> (bits)) | ((value) << (64 - (bits))))

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define LOAD64H(x, y)                                                          \
  {                                                                            \
    x = (((uint64_t)((y)[0] & 255)) << 56) |                                   \
        (((uint64_t)((y)[1] & 255)) << 48) |                                   \
        (((uint64_t)((y)[2] & 255)) << 40) |                                   \
        (((uint64_t)((y)[3] & 255)) << 32) |                                   \
        (((uint64_t)((y)[4] & 255)) << 24) |                                   \
        (((uint64_t)((y)[5] & 255)) << 16) |                                   \
        (((uint64_t)((y)[6] & 255)) << 8) | (((uint64_t)((y)[7] & 255)));      \
  }

#define STORE64H(x, y)                                                         \
  {                                                                            \
    (y)[0] = (uint8_t)(((x) >> 56) & 255);                                     \
    (y)[1] = (uint8_t)(((x) >> 48) & 255);                                     \
    (y)[2] = (uint8_t)(((x) >> 40) & 255);                                     \
    (y)[3] = (uint8_t)(((x) >> 32) & 255);                                     \
    (y)[4] = (uint8_t)(((x) >> 24) & 255);                                     \
    (y)[5] = (uint8_t)(((x) >> 16) & 255);                                     \
    (y)[6] = (uint8_t)(((x) >> 8) & 255);                                      \
    (y)[7] = (uint8_t)((x)&255);                                               \
  }

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  CONSTANTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// The K array
static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

#define BLOCK_SIZE 128

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  INTERNAL FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Various logical functions
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#define Maj(x, y, z) (((x | y) & z) | (x & y))
#define S(x, n) ROR64(x, n)
#define R(x, n) (((x)&0xFFFFFFFFFFFFFFFFULL) >> ((uint64_t)n))
#define Sigma0(x) (S(x, 28) ^ S(x, 34) ^ S(x, 39))
#define Sigma1(x) (S(x, 14) ^ S(x, 18) ^ S(x, 41))
#define Gamma0(x) (S(x, 1) ^ S(x, 8) ^ R(x, 7))
#define Gamma1(x) (S(x, 19) ^ S(x, 61) ^ R(x, 6))

#define Sha512Round(a, b, c, d, e, f, g, h, i)                                 \
  t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];                              \
  t1 = Sigma0(a) + Maj(a, b, c);                                               \
  d += t0;                                                                     \
  h = t0 + t1;

static void TransformFunction(uint64_t state[8], uint8_t const *Buffer) {
  uint64_t S[8];
  uint64_t W[80];
  uint64_t t0;
  uint64_t t1;
  int i;

  // Copy state into S
  for (i = 0; i < 8; i++) {
    S[i] = state[i];
  }

  // Copy the state into 1024-bits into W[0..15]
  for (i = 0; i < 16; i++) {
    LOAD64H(W[i], Buffer + (8 * i));
  }

  // Fill W[16..79]
  for (i = 16; i < 80; i++) {
    W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
  }

  // Compress
  for (i = 0; i < 80; i += 8) {
    Sha512Round(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i + 0);
    Sha512Round(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], i + 1);
    Sha512Round(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], i + 2);
    Sha512Round(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], i + 3);
    Sha512Round(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], i + 4);
    Sha512Round(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], i + 5);
    Sha512Round(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], i + 6);
    Sha512Round(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], i + 7);
  }

  // Feedback
  for (i = 0; i < 8; i++) {
    state[i] = state[i] + S[i];
  }
}

}; // namespace

std::string SHA1(std::string_view str) {
  uint64_t total_bits = str.size() * 8;
  uint32_t digest[5] = {
      0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
  };
  uint32_t block[BLOCK_INTS];

  while (str.size() >= BLOCK_BYTES) {
    buffer_to_block(str.data(), block);
    transform(digest, block);
    str.remove_prefix(BLOCK_BYTES);
  }

  char final_buffer[BLOCK_BYTES];
  memcpy(final_buffer, str.data(), str.size());
  final_buffer[str.size()] = 0x80; /* Padding */
  bzero(final_buffer + str.size() + 1, BLOCK_BYTES - str.size() - 1);

  buffer_to_block(final_buffer, block);

  if (str.size() + 1 > BLOCK_BYTES - 8) {
    transform(digest, block);
    for (size_t i = 0; i < BLOCK_INTS - 2; i++) {
      block[i] = 0;
    }
  }

  /* Append total_bits, split this uint64_t into two uint32_t */
  block[BLOCK_INTS - 1] = (uint32_t)total_bits;
  block[BLOCK_INTS - 2] = (uint32_t)(total_bits >> 32);
  transform(digest, block);

  for (size_t i = 0; i < 5; i++) {
    digest[i] = std::byteswap(digest[i]);
  }

  return std::string((char *)digest, 20);
}

static void FinalizeTo(SHA512::Builder &builder, SHA512 &sha) {
  int i;

  // Increase the length of the message
  builder.length += builder.curlen * 8ULL;

  // Append the '1' bit
  builder.buf[builder.curlen++] = (uint8_t)0x80;

  // If the length is currently above 112 bytes we append zeros
  // then compress.  Then we can fall back to padding zeros and length
  // encoding like normal.
  if (builder.curlen > 112) {
    while (builder.curlen < 128) {
      builder.buf[builder.curlen++] = (uint8_t)0;
    }
    TransformFunction(builder.state, builder.buf);
    builder.curlen = 0;
  }

  // Pad up to 120 bytes of zeroes
  // note: that from 112 to 120 is the 64 MSB of the length.  We assume that you
  // won't hash > 2^64 bits of data... :-)
  while (builder.curlen < 120) {
    builder.buf[builder.curlen++] = (uint8_t)0;
  }

  // Store length
  STORE64H(builder.length, builder.buf + 120);
  TransformFunction(builder.state, builder.buf);

  // Copy output
  for (i = 0; i < 8; i++) {
    STORE64H(builder.state[i], sha.bytes + (8 * i));
  }
}

SHA512::SHA512(std::string_view str) {
  Builder builder;
  builder.Update(str);
  FinalizeTo(builder, *this);
}

SHA512::Builder::Builder() {
  curlen = 0;
  length = 0;
  state[0] = 0x6a09e667f3bcc908ULL;
  state[1] = 0xbb67ae8584caa73bULL;
  state[2] = 0x3c6ef372fe94f82bULL;
  state[3] = 0xa54ff53a5f1d36f1ULL;
  state[4] = 0x510e527fade682d1ULL;
  state[5] = 0x9b05688c2b3e6c1fULL;
  state[6] = 0x1f83d9abfb41bd6bULL;
  state[7] = 0x5be0cd19137e2179ULL;
}

SHA512::Builder &SHA512::Builder::Update(std::string_view str) {
  while (str.size() > 0) {
    if (curlen == 0 && str.size() >= BLOCK_SIZE) {
      TransformFunction(state, (uint8_t *)str.data());
      length += BLOCK_SIZE * 8;
      str.remove_prefix(BLOCK_SIZE);
    } else {
      uint32_t n = MIN(str.size(), (BLOCK_SIZE - curlen));
      memcpy(buf + curlen, str.data(), (size_t)n);
      curlen += n;
      str.remove_prefix(n);
      if (curlen == BLOCK_SIZE) {
        TransformFunction(state, buf);
        length += 8 * BLOCK_SIZE;
        curlen = 0;
      }
    }
  }
  return *this;
}

SHA512 SHA512::Builder::Finalize() {
  SHA512 sha;
  FinalizeTo(*this, sha);
  return sha;
}
