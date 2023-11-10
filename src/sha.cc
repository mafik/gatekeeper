#include "sha.hh"

#include <bit>
#include <cstring>

namespace maf {

// From https://github.com/vog/sha1 (public domain)
namespace {

static constexpr size_t BLOCK_INTS = 16;
static constexpr size_t BLOCK_BYTES = BLOCK_INTS * 4;

inline static U32 rol(const U32 value, const size_t bits) {
  return (value << bits) | (value >> (32 - bits));
}

inline static U32 blk(const U32 block[BLOCK_INTS], const size_t i) {
  return rol(block[(i + 13) & 15] ^ block[(i + 8) & 15] ^ block[(i + 2) & 15] ^
                 block[i],
             1);
}

/*
 * (R0+R1), R2, R3, R4 are the different operations used in SHA1
 */

inline static void R0(const U32 block[BLOCK_INTS], const U32 v, U32 &w,
                      const U32 x, const U32 y, U32 &z, const size_t i) {
  z += ((w & (x ^ y)) ^ y) + block[i] + 0x5a827999 + rol(v, 5);
  w = rol(w, 30);
}

inline static void R1(U32 block[BLOCK_INTS], const U32 v, U32 &w, const U32 x,
                      const U32 y, U32 &z, const size_t i) {
  block[i] = blk(block, i);
  z += ((w & (x ^ y)) ^ y) + block[i] + 0x5a827999 + rol(v, 5);
  w = rol(w, 30);
}

inline static void R2(U32 block[BLOCK_INTS], const U32 v, U32 &w, const U32 x,
                      const U32 y, U32 &z, const size_t i) {
  block[i] = blk(block, i);
  z += (w ^ x ^ y) + block[i] + 0x6ed9eba1 + rol(v, 5);
  w = rol(w, 30);
}

inline static void R3(U32 block[BLOCK_INTS], const U32 v, U32 &w, const U32 x,
                      const U32 y, U32 &z, const size_t i) {
  block[i] = blk(block, i);
  z += (((w | x) & y) | (w & x)) + block[i] + 0x8f1bbcdc + rol(v, 5);
  w = rol(w, 30);
}

inline static void R4(U32 block[BLOCK_INTS], const U32 v, U32 &w, const U32 x,
                      const U32 y, U32 &z, const size_t i) {
  block[i] = blk(block, i);
  z += (w ^ x ^ y) + block[i] + 0xca62c1d6 + rol(v, 5);
  w = rol(w, 30);
}

/*
 * Hash a single 512-bit block. This is the core of the algorithm.
 */

inline static void transform(U32 digest[5], U32 block[BLOCK_INTS]) {
  /* Copy digest[] to working vars */
  U32 a = digest[0];
  U32 b = digest[1];
  U32 c = digest[2];
  U32 d = digest[3];
  U32 e = digest[4];

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
                                   U32 block[BLOCK_INTS]) {
  /* Convert the std::string (byte buffer) to a U32 array (MSB) */
  for (size_t i = 0; i < BLOCK_INTS; i++) {
    block[i] = (buffer[4 * i + 3] & 0xff) | (buffer[4 * i + 2] & 0xff) << 8 |
               (buffer[4 * i + 1] & 0xff) << 16 |
               (buffer[4 * i + 0] & 0xff) << 24;
  }
}

} // namespace

// From https://github.com/983/SHA-256 (public domain)
namespace {

static inline U32 rotr(U32 x, int n) { return (x >> n) | (x << (32 - n)); }

static inline U32 step1(U32 e, U32 f, U32 g) {
  return (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ ((~e) & g));
}

static inline U32 step2(U32 a, U32 b, U32 c) {
  return (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) +
         ((a & b) ^ (a & c) ^ (b & c));
}

static inline void update_w(U32 *w, int i, const U8 *buffer) {
  int j;
  for (j = 0; j < 16; j++) {
    if (i < 16) {
      w[j] = ((U32)buffer[0] << 24) | ((U32)buffer[1] << 16) |
             ((U32)buffer[2] << 8) | ((U32)buffer[3]);
      buffer += 4;
    } else {
      U32 a = w[(j + 1) & 15];
      U32 b = w[(j + 14) & 15];
      U32 s0 = (rotr(a, 7) ^ rotr(a, 18) ^ (a >> 3));
      U32 s1 = (rotr(b, 17) ^ rotr(b, 19) ^ (b >> 10));
      w[j] += w[(j + 9) & 15] + s0 + s1;
    }
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
    x = (((U64)((y)[0] & 255)) << 56) | (((U64)((y)[1] & 255)) << 48) |        \
        (((U64)((y)[2] & 255)) << 40) | (((U64)((y)[3] & 255)) << 32) |        \
        (((U64)((y)[4] & 255)) << 24) | (((U64)((y)[5] & 255)) << 16) |        \
        (((U64)((y)[6] & 255)) << 8) | (((U64)((y)[7] & 255)));                \
  }

#define STORE64H(x, y)                                                         \
  {                                                                            \
    (y)[0] = (U8)(((x) >> 56) & 255);                                          \
    (y)[1] = (U8)(((x) >> 48) & 255);                                          \
    (y)[2] = (U8)(((x) >> 40) & 255);                                          \
    (y)[3] = (U8)(((x) >> 32) & 255);                                          \
    (y)[4] = (U8)(((x) >> 24) & 255);                                          \
    (y)[5] = (U8)(((x) >> 16) & 255);                                          \
    (y)[6] = (U8)(((x) >> 8) & 255);                                           \
    (y)[7] = (U8)((x) & 255);                                                  \
  }

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  CONSTANTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// The K array
static const U64 K[80] = {
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
#define R(x, n) (((x) & 0xFFFFFFFFFFFFFFFFULL) >> ((U64)n))
#define Sigma0(x) (S(x, 28) ^ S(x, 34) ^ S(x, 39))
#define Sigma1(x) (S(x, 14) ^ S(x, 18) ^ S(x, 41))
#define Gamma0(x) (S(x, 1) ^ S(x, 8) ^ R(x, 7))
#define Gamma1(x) (S(x, 19) ^ S(x, 61) ^ R(x, 6))

#define Sha512Round(a, b, c, d, e, f, g, h, i)                                 \
  t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];                              \
  t1 = Sigma0(a) + Maj(a, b, c);                                               \
  d += t0;                                                                     \
  h = t0 + t1;

static void TransformFunction(U64 state[8], U8 const *Buffer) {
  U64 S[8];
  U64 W[80];
  U64 t0;
  U64 t1;
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

SHA1::SHA1(Span<> mem) {
  U64 total_bits = mem.size() * 8;
  U32 digest[5] = {
      0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
  };
  U32 block[BLOCK_INTS];

  while (mem.size() >= BLOCK_BYTES) {
    buffer_to_block(mem.data(), block);
    transform(digest, block);
    mem = mem.subspan<BLOCK_BYTES>();
  }

  char final_buffer[BLOCK_BYTES];
  memcpy(final_buffer, mem.data(), mem.size());
  final_buffer[mem.size()] = 0x80; /* Padding */
  bzero(final_buffer + mem.size() + 1, BLOCK_BYTES - mem.size() - 1);

  buffer_to_block(final_buffer, block);

  if (mem.size() + 1 > BLOCK_BYTES - 8) {
    transform(digest, block);
    for (size_t i = 0; i < BLOCK_INTS - 2; i++) {
      block[i] = 0;
    }
  }

  /* Append total_bits, split this U64 into two U32 */
  block[BLOCK_INTS - 1] = (U32)total_bits;
  block[BLOCK_INTS - 2] = (U32)(total_bits >> 32);
  transform(digest, block);

  for (size_t i = 0; i < 5; i++) {
    digest[i] = std::byteswap(digest[i]);
  }

  memcpy(this->bytes, digest, sizeof(digest));
}

static void FinalizeTo(SHA1::Builder &builder, SHA1 &sha) {
  U32 block[BLOCK_INTS];

  // Increase the length of the message
  builder.length += builder.curlen * 8ULL;

  // Append the '1' bit
  builder.buffer[builder.curlen++] = (char)0x80;

  // Zero remaining bits
  bzero(builder.buffer + builder.curlen, BLOCK_BYTES - builder.curlen);

  buffer_to_block(builder.buffer, block);

  if (builder.curlen > BLOCK_BYTES - 8) {
    transform(builder.digest, block);
    for (size_t i = 0; i < BLOCK_INTS - 2; i++) {
      block[i] = 0;
    }
  }

  /* Append total_bits, split this U64 into two U32 */
  block[BLOCK_INTS - 1] = (U32)builder.length;
  block[BLOCK_INTS - 2] = (U32)(builder.length >> 32);
  transform(builder.digest, block);

  for (size_t i = 0; i < 5; i++) {
    builder.digest[i] = std::byteswap(builder.digest[i]);
  }

  memcpy(sha.bytes, builder.digest, sizeof(SHA1));
}

SHA1::Builder::Builder()
    : length(0),
      digest{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0},
      curlen(0) {}

SHA1::Builder &SHA1::Builder::Update(Span<> mem) {
  U32 block[BLOCK_INTS];
  while (!mem.empty()) {
    if (curlen == 0 && mem.size() >= BLOCK_BYTES) {
      buffer_to_block(mem.data(), block);
      transform(digest, block);
      length += BLOCK_BYTES * 8;
      mem = mem.subspan<BLOCK_BYTES>();
    } else {
      Size n = MIN(mem.size(), (BLOCK_BYTES - curlen));
      memcpy(buffer + curlen, mem.data(), n);
      curlen += n;
      mem = mem.subspan(n);
      if (curlen == BLOCK_BYTES) {
        buffer_to_block(buffer, block);
        transform(digest, block);
        length += BLOCK_BYTES * 8;
        curlen = 0;
      }
    }
  }
  return *this;
}

SHA1 SHA1::Builder::Finalize() {
  SHA1 sha;
  FinalizeTo(*this, sha);
  return sha;
}

SHA256::Builder::Builder()
    : state{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
      n_bits(0), buffer_counter(0) {}

static void Block(SHA256::Builder &sha) {
  U32 *state = sha.state;

  static const U32 k[8 * 8] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  };

  U32 a = state[0];
  U32 b = state[1];
  U32 c = state[2];
  U32 d = state[3];
  U32 e = state[4];
  U32 f = state[5];
  U32 g = state[6];
  U32 h = state[7];

  U32 w[16];

  int i, j;
  for (i = 0; i < 64; i += 16) {
    update_w(w, i, sha.buffer);

    for (j = 0; j < 16; j += 4) {
      U32 temp;
      temp = h + step1(e, f, g) + k[i + j + 0] + w[j + 0];
      h = temp + d;
      d = temp + step2(a, b, c);
      temp = g + step1(h, e, f) + k[i + j + 1] + w[j + 1];
      g = temp + c;
      c = temp + step2(d, a, b);
      temp = f + step1(g, h, e) + k[i + j + 2] + w[j + 2];
      f = temp + b;
      b = temp + step2(c, d, a);
      temp = e + step1(f, g, h) + k[i + j + 3] + w[j + 3];
      e = temp + a;
      a = temp + step2(b, c, d);
    }
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

static void AppendByte(SHA256::Builder &builder, U8 byte) {
  builder.buffer[builder.buffer_counter++] = byte;
  builder.n_bits += 8;

  if (builder.buffer_counter == 64) {
    builder.buffer_counter = 0;
    Block(builder);
  }
}

SHA256::Builder &SHA256::Builder::Update(Span<> mem) {
  for (auto byte : mem) {
    AppendByte(*this, byte);
  }
  return *this;
}

static void FinalizeTo(SHA256::Builder &builder, SHA256 &out_sha) {
  char *ptr = out_sha.bytes;

  U64 n_bits = builder.n_bits;

  AppendByte(builder, 0x80);

  while (builder.buffer_counter != 56) {
    AppendByte(builder, 0);
  }

  for (int i = 7; i >= 0; i--) {
    U8 byte = (n_bits >> 8 * i) & 0xff;
    AppendByte(builder, byte);
  }

  for (int i = 0; i < 8; i++) {
    for (int j = 3; j >= 0; j--) {
      *ptr++ = (builder.state[i] >> j * 8) & 0xff;
    }
  }
}

SHA256::SHA256(Span<> mem) {
  Builder builder;
  builder.Update(mem);
  FinalizeTo(builder, *this);
}

SHA256 SHA256::Builder::Finalize() {
  SHA256 sha;
  FinalizeTo(*this, sha);
  return sha;
}

static void FinalizeTo(SHA512::Builder &builder, SHA512 &sha) {
  int i;

  // Increase the length of the message
  builder.length += builder.curlen * 8ULL;

  // Append the '1' bit
  builder.buf[builder.curlen++] = (U8)0x80;

  // If the length is currently above 112 bytes we append zeros
  // then compress.  Then we can fall back to padding zeros and length
  // encoding like normal.
  if (builder.curlen > 112) {
    while (builder.curlen < 128) {
      builder.buf[builder.curlen++] = (U8)0;
    }
    TransformFunction(builder.state, builder.buf);
    builder.curlen = 0;
  }

  // Pad up to 120 bytes of zeroes
  // note: that from 112 to 120 is the 64 MSB of the length.  We assume that you
  // won't hash > 2^64 bits of data... :-)
  while (builder.curlen < 120) {
    builder.buf[builder.curlen++] = (U8)0;
  }

  // Store length
  STORE64H(builder.length, builder.buf + 120);
  TransformFunction(builder.state, builder.buf);

  // Copy output
  for (i = 0; i < 8; i++) {
    STORE64H(builder.state[i], sha.bytes + (8 * i));
  }
}

SHA512::SHA512(Span<> mem) {
  Builder builder;
  builder.Update(mem);
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

SHA512::Builder &SHA512::Builder::Update(Span<> mem) {
  while (mem.size() > 0) {
    if (curlen == 0 && mem.size() >= BLOCK_SIZE) {
      TransformFunction(state, (U8 *)mem.data());
      length += BLOCK_SIZE * 8;
      mem = mem.subspan<BLOCK_SIZE>();
    } else {
      Size n = MIN(mem.size(), (BLOCK_SIZE - curlen));
      memcpy(buf + curlen, mem.data(), (size_t)n);
      curlen += n;
      mem = mem.subspan(n);
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

} // namespace maf