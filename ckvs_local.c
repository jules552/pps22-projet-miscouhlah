#include "ckvs_local.h"
#include "ckvs_crypto.h"
#include "util.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>

/**
 * @brief Opens the CKVS database at the given filename and executes the 'set'
 * or 'get command, ie. get: fetches, decrypts and prints the entry
 * corresponding to the key and password. ie. set: fetches the entry
 * corresponding to the key and password and then sets the encrypted content of
 * valuefilename as new content.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param key (const char*) the key of the entry to set or get
 * @param pwd (const char*) the password of the entry to set or get
 * @param set_value (const char*) if NULL, the function will work as a get,
 * otherwise it will work as a set
 * @return int, an error code
 */
static int ckvs_local_getset(const char *filename, const char *key,
                             const char *pwd, const char *set_value);

int ckvs_local_stats(const char *filename, int optargc,
                     _unused char *optargv[]) {
  M_REQUIRE_NON_NULL(filename);

  if (optargc > 0) {
    return ERR_TOO_MANY_ARGUMENTS;
  }

  CKVS ckvs;
  int file_open = ckvs_open(filename, &ckvs);

  if (file_open != ERR_NONE) {
    return file_open;
  } else {
    print_header(&(ckvs.header));

    // print each entries
    for (size_t i = 0; i < ckvs.header.table_size; i++) {
      if (strlen(ckvs.entries[i].key)) {
        print_entry(&ckvs.entries[i]);
      }
    }
  }

  ckvs_close(&ckvs);

  return ERR_NONE;
}

int ckvs_local_get(const char *filename, int optargc, char *optargv[]) {
  M_REQUIRE_NON_NULL(filename);

  const char *key = NULL;
  const char *pwd = NULL;

  if (optargc < 2) {
    return ERR_NOT_ENOUGH_ARGUMENTS;
  } else if (optargc > 2) {
    return ERR_TOO_MANY_ARGUMENTS;
  } else {
    M_REQUIRE_NON_NULL(optargv);
    key = optargv[0];
    pwd = optargv[1];
  }

  return ckvs_local_getset(filename, key, pwd, NULL);
}

int ckvs_local_set(const char *filename, int optargc, char *optargv[]) {
  M_REQUIRE_NON_NULL(filename);

  const char *key = NULL;
  const char *pwd = NULL;
  const char *valuefilename = NULL;

  if (optargc < 3) {
    return ERR_NOT_ENOUGH_ARGUMENTS;
  } else if (optargc > 3) {
    return ERR_TOO_MANY_ARGUMENTS;
  } else {
    M_REQUIRE_NON_NULL(optargv);
    key = optargv[0];
    pwd = optargv[1];
    valuefilename = optargv[2];
  }

  char *buf = NULL;
  size_t buf_size;

  // read value to write
  int err = read_value_file_content(valuefilename, &buf, &buf_size);
  if (err != ERR_NONE) {
    return err;
  }

  // set value
  err = ckvs_local_getset(filename, key, pwd, buf);
  free(buf);

  return err;
}

static int ckvs_local_getset(const char *filename, const char *key,
                             const char *pwd, const char *set_value) {
  M_REQUIRE_NON_NULL(filename);
  M_REQUIRE_NON_NULL(key);
  M_REQUIRE_NON_NULL(pwd);

  // generate memrecord
  ckvs_memrecord_t memrecord;
  int err = ckvs_client_encrypt_pwd(&memrecord, key, pwd);
  if (err != ERR_NONE) {
    return err;
  }

  // open ckvs database
  CKVS ckvs;
  err = ckvs_open(filename, &ckvs);
  if (err != ERR_NONE) {
    return err;
  }

  // find ckvs entry
  struct ckvs_entry *entry = ckvs.entries;
  err = ckvs_find_entry(&ckvs, key, &memrecord.auth_key, &entry);
  if (err != ERR_NONE) {
    ckvs_close(&ckvs);
    return err;
  }

  // get case
  if (set_value == NULL) {

    if (entry->value_len == 0) {
      ckvs_close(&ckvs);
      return ERR_NO_VALUE;
    }

    // compute master key
    err = ckvs_client_compute_masterkey(&memrecord, &entry->c2);
    if (err != ERR_NONE) {
      ckvs_close(&ckvs);
      return err;
    }

    // look for the text location
    err = fseek(ckvs.file, (long int)entry->value_off, SEEK_SET);
    if (err != 0) {
      ckvs_close(&ckvs);
      return ERR_IO;
    }

    unsigned char *inbuf = calloc(entry->value_len + 1, 1);
    if (inbuf == NULL) {
      ckvs_close(&ckvs);
      return ERR_OUT_OF_MEMORY;
    }

    // reading file
    err = (int)fread(inbuf, 1, entry->value_len, ckvs.file);
    if (err != (int)entry->value_len) {
      free(inbuf);
      ckvs_close(&ckvs);
      return ERR_IO;
    }
    inbuf[entry->value_len] = '\0';

    unsigned char *outbuf =
        calloc(entry->value_len + EVP_MAX_BLOCK_LENGTH + 1, 1);
    if (outbuf == NULL) {
      free(inbuf);
      ckvs_close(&ckvs);
      return ERR_OUT_OF_MEMORY;
    }

    // decrypting the text
    size_t outbuflen = 0;
    err = ckvs_client_crypt_value(&memrecord, 0, inbuf, entry->value_len,
                                  outbuf, &outbuflen);
    if (err != ERR_NONE) {
      ckvs_close(&ckvs);
      free(inbuf);
      free(outbuf);
      return err;
    }
    outbuf[outbuflen] = '\0';

    // printing the value
    pps_printf("%s", outbuf);
    free(inbuf);
    free(outbuf);
  } else {
    // set case
    // recreate c2 key
    unsigned char *outbuf = NULL;
    size_t outbuflen = 0;

    err = ckvs_encrypt_value(&(entry->c2), &memrecord, set_value, &outbuf,
                             &outbuflen);
    if (err != ERR_NONE) {
      ckvs_close(&ckvs);
      return err;
    }

    // writing the encripted value
    err = ckvs_write_encrypted_value(&ckvs, entry, outbuf, outbuflen);
    if (err != ERR_NONE) {
      free(outbuf);
      ckvs_close(&ckvs);
      return err;
    }

// check that when encrypting and decrypting the value stays the same
#ifdef DEBUG
    unsigned char *test = calloc(outbuflen + EVP_MAX_BLOCK_LENGTH, 1);
    if (test == NULL) {
      ckvs_close(&ckvs);
      return ERR_OUT_OF_MEMORY;
    }
    size_t test_len = 0;
    err = ckvs_client_crypt_value(&memrecord, 0, outbuf, outbuflen, test,
                                  &test_len);
    if (err != ERR_NONE) {
      free(test);
      free(outbuf);
      ckvs_close(&ckvs);
      return err;
    }
    if (strcmp(test, set_value) != 0) {
      free(test);
      free(outbuf);
      ckvs_close(&ckvs);
      pps_printf(
          "Error: the value is not the same after encryption and decryption\n");
      return ERR_IO;
    }
    pps_printf("It works\n");
    free(test);
#endif

    free(outbuf);
  }
  ckvs_close(&ckvs);

  return ERR_NONE;
}

int ckvs_local_new(const char *filename, int optargc, char *optargv[]) {
  M_REQUIRE_NON_NULL(filename);

  const char *key = NULL;
  const char *pwd = NULL;

  if (optargc < 2) {
    return ERR_NOT_ENOUGH_ARGUMENTS;
  } else if (optargc > 2) {
    return ERR_TOO_MANY_ARGUMENTS;
  } else {
    M_REQUIRE_NON_NULL(optargv);
    key = optargv[0];
    pwd = optargv[1];
  }

  // open ckvs database
  CKVS ckvs;
  int err = ckvs_open(filename, &ckvs);
  if (err != ERR_NONE) {
    return err;
  }

  // Check if there is space for the new entry
  if (ckvs.header.num_entries + 1 > ckvs.header.threshold_entries) {
    ckvs_close(&ckvs);
    return ERR_MAX_FILES;
  }

  // Check if the key is not too long
  if (strlen(key) > CKVS_MAXKEYLEN) {
    ckvs_close(&ckvs);
    return ERR_INVALID_ARGUMENT;
  }

  struct ckvs_memrecord memrec;

  // We need to optain the auth key
  err = ckvs_client_encrypt_pwd(&memrec, key, pwd);
  if (err != ERR_NONE) {
    ckvs_close(&ckvs);
    return err;
  }

  struct ckvs_entry *e_out = NULL;

  // We add the new entry to the ckvs
  err = ckvs_new_entry(&ckvs, key, &memrec.auth_key, &e_out);
  if (err != ERR_NONE) {
    ckvs_close(&ckvs);
    return err;
  }

  ckvs_close(&ckvs);

  return ERR_NONE;
}