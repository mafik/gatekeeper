#include "base64.hh"

#include <openssl/bio.h>
#include <openssl/evp.h>

std::string Base64Encode(std::string_view str) {
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO *mem = BIO_new(BIO_s_mem());
  BIO_push(b64, mem);
  BIO_write(b64, str.data(), str.size());
  BIO_flush(b64);
  char *ptr;
  long size = BIO_get_mem_data(mem, &ptr);
  std::string ret(ptr, size);
  BIO_free_all(b64);
  return ret;
}
