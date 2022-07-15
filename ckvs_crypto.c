// ckvs_crypto

#include "ckvs_crypto.h"
#include "ckvs.h"
#include "error.h"
#include <assert.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

#define AUTH_MESSAGE "Auth Key"
#define C1_MESSAGE "Master Key Encryption"

/**
 * @brief Compute HMAC-SHA256 of the given message with the given key
 *
 * @param key (const void*) the key used to compute HMAC which is a byte array
 * of length CKVS_SHA256_LENGTH
 * @param msg (const unsigned char*) the message to compute HMAC
 * @param msg_len (size_t) the length of the message (in bytes)
 * @param md (unsigned char*) the resulting HMAC of length CKVS_SHA256_LENGTH
 * @return int, error code
 */
static int compute_HMAC256(const void *key, const unsigned char *msg,
                           size_t msg_len, unsigned char *md) {
  M_REQUIRE_NON_NULL(key);
  M_REQUIRE_NON_NULL(msg);
  M_REQUIRE_NON_NULL(md);

  unsigned char *err = NULL;
  unsigned int md_len = 0;
  err =
      HMAC(EVP_sha256(), key, SHA256_DIGEST_LENGTH, msg, msg_len, md, &md_len);
  if (err == NULL) {
    return ERR_INVALID_COMMAND;
  }

  // Test if auth key has correct size
  if (md_len != SHA256_DIGEST_LENGTH) {
    return ERR_INVALID_COMMAND;
  }

  return ERR_NONE;
}

int ckvs_client_encrypt_pwd(ckvs_memrecord_t *mr, const char *key,
                            const char *pwd) {
  // Check if parameters are not null
  M_REQUIRE_NON_NULL(mr);
  M_REQUIRE_NON_NULL(key);
  M_REQUIRE_NON_NULL(pwd);

  // Initialize mr struct
  memset(mr, 0, sizeof(ckvs_memrecord_t));

  // Compute SHA256( key + "|" + pwd ) (+2, because of the '|' separator)
  size_t buffer_size_ =
      strnlen(key, CKVS_MAXKEYLEN) + strnlen(pwd, CKVS_MAXKEYLEN) + 2;
  char *buffer = calloc(buffer_size_, sizeof(char));
  if (buffer == NULL) {
    return ERR_OUT_OF_MEMORY;
  }

  strncpy(buffer, key, buffer_size_);
  strcat(buffer, "|");
  strncat(buffer, pwd, buffer_size_);
  buffer[buffer_size_ - 1] = '\0';

  // Generate SHA256( key + "|" + pwd )
  SHA256((unsigned char *)buffer, strlen(buffer), mr->stretched_key.sha);

  free(buffer);
  buffer = NULL;

  // Generate the auth key
  int err = compute_HMAC256(mr->stretched_key.sha,
                            (const unsigned char *)AUTH_MESSAGE,
                            strlen(AUTH_MESSAGE), mr->auth_key.sha);
  if (err != ERR_NONE) {
    return err;
  }

  // Generate c1
  err =
      compute_HMAC256(mr->stretched_key.sha, (const unsigned char *)C1_MESSAGE,
                      strlen(C1_MESSAGE), mr->c1.sha);

  return err;
}

int ckvs_client_compute_masterkey(struct ckvs_memrecord *mr,
                                  const struct ckvs_sha *c2) {
  // Check if parameters are not null
  M_REQUIRE_NON_NULL(mr);
  M_REQUIRE_NON_NULL(c2);

  int err = compute_HMAC256(&mr->c1.sha, (const unsigned char *)&c2->sha,
                            SHA256_DIGEST_LENGTH, mr->master_key.sha);
  return err;
}

int ckvs_client_crypt_value(const struct ckvs_memrecord *mr,
                            const int do_encrypt, const unsigned char *inbuf,
                            size_t inbuflen, unsigned char *outbuf,
                            size_t *outbuflen) {
  /* ======================================
   * Implementation adapted from the web:
   *     https://man.openbsd.org/EVP_EncryptInit.3
   * Man page: EVP_EncryptInit
   * Reference:
   *    https://www.coder.work/article/6383682
   * ======================================
   */

  // constant IV -- ok given the entropy in c2
  unsigned char iv[16];
  bzero(iv, 16);

  // Don't set key or IV right away; we want to check lengths
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, do_encrypt);

  assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
  assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

  // Now we can set key and IV
  const unsigned char *const key = (const unsigned char *)mr->master_key.sha;
  EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

  int outlen = 0;
  if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, (int)inbuflen)) {
    // Error
    EVP_CIPHER_CTX_free(ctx);
    return ERR_INVALID_ARGUMENT;
  }

  int tmplen = 0;
  if (!EVP_CipherFinal_ex(ctx, outbuf + outlen, &tmplen)) {
    // Error
    debug_printf("crypt inbuflen %ld outlen %d tmplen %d", inbuflen, outlen,
                 tmplen);
    EVP_CIPHER_CTX_free(ctx);
    return ERR_INVALID_ARGUMENT;
  }

  outlen += tmplen;
  EVP_CIPHER_CTX_free(ctx);

  *outbuflen = (size_t)outlen;

  return ERR_NONE;
}
