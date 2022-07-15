#include "ckvs_io.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdlib.h>

/**
 * @brief Check if the given number is a power of 2.
 *
 * @param x (uint32_t) the number to check
 * @return (bool) true if that's the case, false otherwise
 */
static bool isPowerOfTwo(uint32_t x) {
  return (x != 0) && ((x & (x - 1)) == 0);
}

/**
 * @brief Rewrite the cks file at entry idx.
 *
 * @param ckvs (ckvs) the ckvs to modify
 * @param idx (uint32_t) the index of the place to modify
 * @return (int) an error code
 */
static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx);

/**
 * @brief Helping function that give you the index where you should find your
 * key inside the ckvs entries
 *
 * @param ckvs (ckvs) the ckvs where to find the key you're searching for
 * @param key (const char) the key you want the index inside the ckvs' entries
 * @return (uint32_t) the index of the key inside the ckvs' entries
 */
static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key) {
  M_REQUIRE_NON_NULL(ckvs);
  M_REQUIRE_NON_NULL(key);

  unsigned char hashed_key[CKVS_MAXKEYLEN];

  SHA256((const unsigned char *)key, strnlen(key, CKVS_MAXKEYLEN), hashed_key);

  // Keep only the four first bytes of hashed_key
  uint32_t hash = (uint32_t)(hashed_key[3] << 24 | hashed_key[2] << 16 |
                             hashed_key[1] << 8 | hashed_key[0]);

  // Create the mask for selecting the correct amount of LSB
  uint32_t mask = ckvs->header.table_size - 1;

  // Mask the hash with this value
  uint32_t result = hash & mask;

  return result;
}

int ckvs_open(const char *filename, struct CKVS *ckvs) {
  M_REQUIRE_NON_NULL(filename);
  M_REQUIRE_NON_NULL(ckvs);

  // We set all the fields to zero of ckvs
  memset(ckvs, 0, sizeof(struct CKVS));

  // We open the file in read and write mode
  ckvs->file = fopen(filename, "rb+");
  if (ckvs->file == NULL) {
    return ERR_IO;
  }

  // Reading the header
  struct ckvs_header header;
  size_t size = fread(&header, sizeof(struct ckvs_header), 1, ckvs->file);
  if (size != 1) {
    return ERR_IO;
  }

  // Checking the header is valid
  if (strcmp(header.header_string, CKVS_HEADERSTRING_PREFIX) != 0) {
    return ERR_CORRUPT_STORE;
  } else if (header.version != 1) {
    return ERR_CORRUPT_STORE;
  }
  // check if table_size is power of 2
  else if (isPowerOfTwo(header.table_size) == false) {
    return ERR_CORRUPT_STORE;
  }

  ckvs->header = header;

  // We allocate the entries
  ckvs->entries = calloc(ckvs->header.table_size, sizeof(struct ckvs_entry));
  if (ckvs->entries == NULL) {
    return ERR_OUT_OF_MEMORY;
  }

  for (size_t i = 0; i < ckvs->header.table_size; i++) {
    struct ckvs_entry entry;
    fread(&entry, sizeof(struct ckvs_entry), 1, ckvs->file);

    // We check if the entry is valid
    if (strlen(entry.key)) {
      ckvs->entries[i] = entry;
    }
  }

  return ERR_NONE;
}

void ckvs_close(struct CKVS *ckvs) {
  if (ckvs->file != NULL) {
    // deallocate the entries
    if (ckvs->entries != NULL) {
      free(ckvs->entries);
    }
    ckvs->entries = NULL;

    fclose(ckvs->file);
    ckvs->file = NULL;
  }
}

int ckvs_find_entry(struct CKVS *ckvs, const char *key,
                    const struct ckvs_sha *auth_key,
                    struct ckvs_entry **e_out) {
  M_REQUIRE_NON_NULL(ckvs);
  M_REQUIRE_NON_NULL(key);
  M_REQUIRE_NON_NULL(auth_key);
  M_REQUIRE_NON_NULL(e_out);

  uint32_t initial_index = ckvs_hashkey(ckvs, key);
  uint32_t current_index = initial_index;
  // since table size is power of two -> can use (&mask) for modulo
  uint32_t mask = (ckvs->header.table_size - 1);

  bool empty_place_found = false;
  do {
    if (strlen(ckvs->entries[current_index].key) == 0 && !empty_place_found) {
      // We found an empty place
      *e_out = &(ckvs->entries[current_index]);
      empty_place_found = true;
    }
    // We check if the key is the same
    if (strncmp(key, ckvs->entries[current_index].key, CKVS_MAXKEYLEN) == 0) {
      // We found the key & the auth_key is the same
      if (ckvs_cmp_sha(auth_key, &(ckvs->entries[current_index].auth_key)) ==
          0) {
        *e_out = &(ckvs->entries[current_index]);
        return ERR_NONE;
      } else {
        return ERR_DUPLICATE_ID;
      }
    }

    current_index = (current_index + 1) & mask;

  } while (current_index != initial_index);

  return ERR_KEY_NOT_FOUND;
}

int read_value_file_content(const char *filename, char **buffer_ptr,
                            size_t *buffer_size) {
  M_REQUIRE_NON_NULL(filename);
  M_REQUIRE_NON_NULL(buffer_ptr);
  M_REQUIRE_NON_NULL(buffer_size);

  FILE *file = fopen(filename, "rb");
  if (file == NULL) {
    return ERR_IO;
  }

  // get file size
  int err = fseek(file, 0, SEEK_END);
  if (err != 0) {
    fclose(file);
    return ERR_IO;
  }

  *buffer_size = (size_t)ftell(file);

  err = fseek(file, 0, SEEK_SET);
  if (err != 0) {
    fclose(file);
    return ERR_IO;
  }

  *buffer_ptr = calloc(*buffer_size + 1, 1); //+1 for null terminator
  if (*buffer_ptr == NULL) {
    fclose(file);
    return ERR_OUT_OF_MEMORY;
  }

  // read entry
  size_t read_size = fread(*buffer_ptr, 1, *buffer_size, file);
  if (read_size != *buffer_size) {
    free(*buffer_ptr);
    fclose(file);
    return ERR_IO;
  }

  (*buffer_ptr)[*buffer_size] = '\0';
  fclose(file);
  return ERR_NONE;
}

int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e,
                               const unsigned char *buf, uint64_t buflen) {
  M_REQUIRE_NON_NULL(ckvs);
  M_REQUIRE_NON_NULL(e);
  M_REQUIRE_NON_NULL(buf);

  // look for end of file
  int err = fseek(ckvs->file, 0, SEEK_END);
  if (err != 0) {
    return ERR_IO;
  }

  // write entry
  err = (int)fwrite(buf, 1, buflen, ckvs->file);
  if (err != (int)buflen) {
    return ERR_IO;
  }

  // update entry
  e->value_off = (uint64_t)ftell(ckvs->file);
  e->value_len = buflen;
  e->value_off -= e->value_len;

  err = ckvs_write_entry_to_disk(ckvs, (uint32_t)(e - ckvs->entries));
  if (err != ERR_NONE) {
    return err;
  }

  return ERR_NONE;
}

static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx) {
  M_REQUIRE_NON_NULL(ckvs);

  // seek the entry location
  int err = fseek(
      ckvs->file,
      (long int)(sizeof(struct ckvs_header) + idx * sizeof(struct ckvs_entry)),
      SEEK_SET);
  if (err != 0) {
    return ERR_IO;
  }

  print_SHA("", &(ckvs->entries[idx].c2));

  // rewrite the entry
  err = (int)fwrite(&(ckvs->entries[idx]), sizeof(struct ckvs_entry), 1,
                    ckvs->file);
  if (err != 1) {
    return ERR_IO;
  }

  return ERR_NONE;
}

/**
 * @brief Write the new header of the ckvs to the file indicated inside the ckvs
 * struct
 *
 * @param ckvs (ckvs) the ckvs struct with the header to write
 * @return int an error code
 */
static int ckvs_write_header_to_disk(struct CKVS *ckvs) {
  // go to the beginning of the file
  int err = fseek(ckvs->file, 0, SEEK_SET);
  if (err != 0) {
    return ERR_IO;
  }

  // write the new header
  err = (int)fwrite(&ckvs->header, sizeof(struct ckvs_header), 1, ckvs->file);
  if (err != 1) {
    return ERR_IO;
  }

  return ERR_NONE;
}

int ckvs_new_entry(struct CKVS *ckvs, const char *key,
                   struct ckvs_sha *auth_key, struct ckvs_entry **e_out) {
  M_REQUIRE_NON_NULL(ckvs);
  M_REQUIRE_NON_NULL(key);
  M_REQUIRE_NON_NULL(auth_key);
  M_REQUIRE_NON_NULL(e_out);

  int err = ckvs_find_entry(ckvs, key, auth_key, e_out);
  if (err == ERR_NONE) {
    // entry already exists
    return ERR_DUPLICATE_ID;
  } else if (err != ERR_KEY_NOT_FOUND) {
    return err;
  }

  memset(*e_out, 0, sizeof(struct ckvs_entry));

  // Copy the key and the auth_key into the entry
  strncpy((*e_out)->key, key, CKVS_MAXKEYLEN);
  (*e_out)->auth_key = *auth_key;

  // Add the entry to the list
  uint32_t entry_pos = (uint32_t)(*e_out - ckvs->entries);
  err = ckvs_write_entry_to_disk(ckvs, entry_pos);
  if (err != ERR_NONE) {
    return err;
  }

  ckvs->header.num_entries += 1;

  // write the new header
  err = ckvs_write_header_to_disk(ckvs);
  if (err != ERR_NONE) {
    return err;
  }

  return ERR_NONE;
}

int ckvs_encrypt_value(struct ckvs_sha *e, ckvs_memrecord_t *memrecord,
                       const char *v_in, char **v_out, size_t *v_out_len) {
  M_REQUIRE_NON_NULL(e);
  M_REQUIRE_NON_NULL(memrecord);
  M_REQUIRE_NON_NULL(v_in);
  M_REQUIRE_NON_NULL(v_out);
  M_REQUIRE_NON_NULL(v_out_len);

  int err = RAND_bytes(e, SHA256_DIGEST_LENGTH);
  if (err != 1) {
    ;
    return ERR_IO;
  }

  err = ckvs_client_compute_masterkey(memrecord, e);
  if (err != ERR_NONE) {
    return err;
  }

  *v_out = calloc(strlen(v_in) + EVP_MAX_BLOCK_LENGTH + 1, 1);
  if (*v_out == NULL) {
    return ERR_OUT_OF_MEMORY;
  }

  // encrypting the text
  err = ckvs_client_crypt_value(memrecord, 1, (unsigned const char *)v_in,
                                strlen(v_in), *v_out, v_out_len);

  return err;
}