#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

int main(int argc, char **argv) {
  if (argc != 4) {
    printf("usage: decrypt KEY INPUT OUTPUT\n");
    return 1;
  }
  const char * const key_filename = argv[1];
  const char * const input_filename = argv[2];
  const char * const output_filename = argv[3];
  EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
  if (!evp_ctx) {
    printf("error creating libcrypto context: %s\n",
        ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }
  EVP_PKEY *private_key = NULL;
  FILE *key_file = fopen(key_filename, "r");
  if (!key_file) {
    printf("error opening key file: %s\n", key_filename);
    return 1;
  }
  PEM_read_PrivateKey(key_file, &private_key, NULL, NULL);
  if (!private_key) {
    printf("error parsing key file: %s\n",
        ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }
  fclose(key_file);
  printf("loaded key file: %s\n", key_filename);

  FILE *input_file = fopen(input_filename, "r");
  if (!input_file) {
    printf("couldn't open input file: %s\n", input_filename);
    return 1;
  }

  uint8_t ekey[256] = {0};  // encrypted key
  uint8_t iv[16] = {0};  // initialization vector
  if (sizeof(ekey) != fread(ekey, 1, sizeof(ekey), input_file)) {
    printf("couldn't read encrypted key block from input file\n");
    return 1;
  }
  if (sizeof(iv) != fread(iv, 1, sizeof(iv), input_file)) {
    printf("couldn't read iv from input file\n");
    return 1;
  }

  int rc;
  rc = EVP_OpenInit(evp_ctx, EVP_aes_256_cbc(), ekey, sizeof(ekey),
      iv, private_key);
  if (1 != rc) {
    printf("error opening encrypted file: %s\n",
        ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }
  printf("opened encrypted file successfully\n");
  
  FILE *output_file = fopen(output_filename, "w");
  if (!output_file) {
    printf("unable to open output file\n");
    return 1;
  }

  while (!feof(input_file)) {
    uint8_t ebuf[2048] = {0};  // encrypted buffer
    uint8_t dbuf[4096] = {0};  // decrypted buffer
    int nread = fread(ebuf, 1, sizeof(ebuf), input_file);
    if (nread < 0) {
      printf("error reading input file\n");
      return 1;
    }

    int len = 0;
    rc = EVP_OpenUpdate(evp_ctx, dbuf, &len, ebuf, nread);
    if (rc != 1) {
      printf("decryption error: %s\n",
          ERR_error_string(ERR_get_error(), NULL));
    }
    //printf("decrypted %d bytes OK\n", len);
    if (len) {
      rc = fwrite(dbuf, 1, len, output_file);
      if (rc != len) {
        printf("error writing output file\n");
        return 1;
      }
    }
    /*
    for (int i = 0; i < (int)32; i++) {
      printf("0x%02x (%c)\n",
          (unsigned)dbuf[i], (int)dbuf[i]);
    }
    */
  }

  printf("have a nice day\n");
  return 0;
}
