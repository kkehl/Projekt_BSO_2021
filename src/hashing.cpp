#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/sha.h>
#include <sstream>

unsigned long long *SHA256(const char *const path) {
  std::ifstream fp(path, std::ios::in | std::ios::binary);

  constexpr const std::size_t buffer_size{1 << 12};
  char buffer[buffer_size];

  unsigned char hash[SHA256_DIGEST_LENGTH] = {0};

  SHA256_CTX ctx;
  SHA256_Init(&ctx);

  while (fp.good()) {
    fp.read(buffer, buffer_size);
    SHA256_Update(&ctx, buffer, fp.gcount());
  }

  SHA256_Final(hash, &ctx);
  fp.close();

  // wartosc hashu w czterech liczbach dla usprawnienia porownan
  unsigned long long part1 = ((unsigned long long)(hash[7]) << 56) |
                             ((unsigned long long)(hash[6]) << 48) |
                             ((unsigned long long)(hash[5]) << 40) |
                             ((unsigned long long)(hash[4]) << 32) |
                             ((unsigned long long)(hash[3]) << 24) |
                             ((unsigned long long)(hash[2]) << 16) |
                             ((unsigned long long)(hash[1]) << 8) |
                             ((unsigned long long)(hash[0]));
  unsigned long long part2 = ((unsigned long long)(hash[15]) << 56) |
                             ((unsigned long long)(hash[14]) << 48) |
                             ((unsigned long long)(hash[13]) << 40) |
                             ((unsigned long long)(hash[12]) << 32) |
                             ((unsigned long long)(hash[11]) << 24) |
                             ((unsigned long long)(hash[10]) << 16) |
                             ((unsigned long long)(hash[9]) << 8) |
                             ((unsigned long long)(hash[8]));
  unsigned long long part3 = ((unsigned long long)(hash[23]) << 56) |
                             ((unsigned long long)(hash[22]) << 48) |
                             ((unsigned long long)(hash[21]) << 40) |
                             ((unsigned long long)(hash[20]) << 32) |
                             ((unsigned long long)(hash[19]) << 24) |
                             ((unsigned long long)(hash[18]) << 16) |
                             ((unsigned long long)(hash[17]) << 8) |
                             ((unsigned long long)(hash[16]));
  unsigned long long part4 = ((unsigned long long)(hash[31]) << 56) |
                             ((unsigned long long)(hash[30]) << 48) |
                             ((unsigned long long)(hash[29]) << 40) |
                             ((unsigned long long)(hash[28]) << 32) |
                             ((unsigned long long)(hash[27]) << 24) |
                             ((unsigned long long)(hash[26]) << 16) |
                             ((unsigned long long)(hash[25]) << 8) |
                             ((unsigned long long)(hash[24]));

  static unsigned long long result[4];

  result[0] = part1;
  result[1] = part2;
  result[2] = part3;
  result[3] = part4;

  return result;
}
