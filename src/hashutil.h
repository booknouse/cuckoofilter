#ifndef CUCKOO_FILTER_HASHUTIL_H_
#define CUCKOO_FILTER_HASHUTIL_H_

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <string>

#include <openssl/evp.h>
#include <random>
#include <string.h>

namespace cuckoofilter {

class HashUtil {
 public:
  // Bob Jenkins Hash
  static uint32_t BobHash(const void *buf, size_t length, uint32_t seed = 0);
  static uint32_t BobHash(const std::string &s, uint32_t seed = 0);

  // Bob Jenkins Hash that returns two indices in one call
  // Useful for Cuckoo hashing, power of two choices, etc.
  // Use idx1 before idx2, when possible. idx1 and idx2 should be initialized to seeds.
  static void BobHash(const void *buf, size_t length, uint32_t *idx1,
                      uint32_t *idx2);
  static void BobHash(const std::string &s, uint32_t *idx1, uint32_t *idx2);

  // MurmurHash2
  static uint32_t MurmurHash(const void *buf, size_t length, uint32_t seed = 0);
  static uint32_t MurmurHash(const std::string &s, uint32_t seed = 0);

  // SuperFastHash
  static uint32_t SuperFastHash(const void *buf, size_t len);
  static uint32_t SuperFastHash(const std::string &s);

  // Null hash (shift and mask)
  static uint32_t NullHash(const void *buf, size_t length, uint32_t shiftbytes);

  // Wrappers for MD5 and SHA1 hashing using EVP
  static std::string MD5Hash(const char *inbuf, size_t in_length);
  static std::string SHA1Hash(const char *inbuf, size_t in_length);

 private:
  HashUtil();
};

// See Martin Dietzfelbinger, "Universal hashing and k-wise independent random
// variables via integer arithmetic without primes".
class TwoIndependentMultiplyShift {
  unsigned __int128 multiply_, add_;

 public:
  TwoIndependentMultiplyShift() {
    ::std::random_device random;
    for (auto v : {&multiply_, &add_}) {
      *v = random();
      for (int i = 1; i <= 4; ++i) {
        *v = *v << 32;
        *v |= random();
      }
    }
  }

  uint64_t operator()(uint64_t key) const {
    return (add_ + multiply_ * static_cast<decltype(multiply_)>(key)) >> 64;
  }

  unsigned char *serialize(unsigned char *buf) {
    /*unsigned int total_sz = 2 * sizeof(unsigned __int128);
    memmove(buf, &total_sz, sizeof(total_sz));
    buf += sizeof(total_sz);*/
    memmove(buf, &multiply_, sizeof(multiply_));
    buf += sizeof(multiply_);
    memmove(buf, &add_, sizeof(add_));
    buf += sizeof(add_);
    return buf;
  }
  unsigned int serializedSize() const {
    return 2 * sizeof(unsigned __int128);
  }
  int fromBuf(unsigned char *buf, unsigned int len) {
    auto buf_start = buf;
    memmove(&multiply_, buf, sizeof(multiply_));
    buf += sizeof(multiply_);
    memmove(&add_, buf, sizeof(add_));
    buf += sizeof(add_);
    if (buf - buf_start != len) return 1;
    return 0;
  }
};

// See Patrascu and Thorup's "The Power of Simple Tabulation Hashing"
class SimpleTabulation {
  uint64_t tables_[sizeof(uint64_t)][1 << CHAR_BIT];

 public:
  SimpleTabulation() {
    ::std::random_device random;
    for (unsigned i = 0; i < sizeof(uint64_t); ++i) {
      for (int j = 0; j < (1 << CHAR_BIT); ++j) {
        tables_[i][j] = random() | ((static_cast<uint64_t>(random())) << 32);
      }
    }
  }

  uint64_t operator()(uint64_t key) const {
    uint64_t result = 0;
    for (unsigned i = 0; i < sizeof(key); ++i) {
      result ^= tables_[i][reinterpret_cast<uint8_t *>(&key)[i]];
    }
    return result;
  }

  unsigned char *serialize(unsigned char *buf) {
    /*unsigned int total_sz = sizeof(tables_);
    memmove(buf, &total_sz, sizeof(total_sz));*/
    auto array_dimeny_sz = sizeof(tables_[0]);
    auto array_dimenx_sz = sizeof(tables_) / array_dimeny_sz;
    for (unsigned int i = 0; i < array_dimenx_sz; i++) {
      memmove(buf, tables_[i], array_dimeny_sz);
      buf += array_dimeny_sz;
    }
    return buf;
  }
  unsigned int serializedSize() const {
    return sizeof(tables_);
  }
  int fromBuf(unsigned char *buf, unsigned int len) {
    auto buf_start = buf;
    auto array_dimeny_sz = sizeof(tables_[0]);
    auto array_dimenx_sz = sizeof(tables_) / array_dimeny_sz;
    for (unsigned int i = 0; i < array_dimenx_sz; i++) {
      memmove(tables_[i], buf, array_dimeny_sz);
      buf += array_dimeny_sz;
    }
    if (buf - buf_start != len) return 1;
    return 0;
  }
};
}

#endif  // CUCKOO_FILTER_HASHUTIL_H_
