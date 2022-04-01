#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <openssl/aes.h>

using std::string;

int cipher(const string &src, const string &dst, int mode) {
  int bytes_read;
  unsigned char indata[AES_BLOCK_SIZE];
  unsigned char outdata[AES_BLOCK_SIZE];

  unsigned char ckey[] = "HLUjcXNbXFMG4UyT";

  unsigned char ivec[] = "vCgHxPthWrTwtPZB";

  AES_KEY key;
  AES_set_encrypt_key(ckey, 128, &key);

  int num = 0;

  FILE *ifp = fopen(src.c_str(), "rb");

  if (ifp == nullptr) {
    return -1;
  }

  FILE *ofp = fopen(dst.c_str(), "w");

  if (ofp == nullptr) {
    return -1;
  }

  while (true) {
    bytes_read = fread(indata, 1, AES_BLOCK_SIZE, ifp);
    AES_cfb128_encrypt(indata, outdata, bytes_read, &key, ivec, &num, mode);
    // mode: AES_ENCRYPT or AES_DECRYPT

    fwrite(outdata, 1, bytes_read, ofp);
    if (bytes_read < AES_BLOCK_SIZE){
      break;
    }
  }
  int check;

  check = fclose(ifp);
  if (check != 0) {
    return check;
  }

  check = fclose(ofp);
  return check;
}
