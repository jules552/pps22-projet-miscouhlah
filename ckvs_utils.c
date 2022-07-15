#include "ckvs.h"
#include "util.h"
#include <stdlib.h>

void print_header(const struct ckvs_header *header) {

  if (header == NULL)
    return;
  pps_printf("CKVS Header type       : ");
  pps_printf(STR_LENGTH_FMT(CKVS_HEADERSTRINGLEN), header->header_string);
  pps_printf("\n");
  pps_printf("CKVS Header version    : %u\n", header->version);
  pps_printf("CKVS Header table_size : %u\n", header->table_size);
  pps_printf("CKVS Header threshold  : %u\n", header->threshold_entries);
  pps_printf("CKVS Header num_entries: %u\n", header->num_entries);
}

void print_entry(const struct ckvs_entry *entry) {
  if (entry == NULL)
    return;
  pps_printf("    Key   : ");
  pps_printf(STR_LENGTH_FMT(CKVS_MAXKEYLEN), entry->key);
  pps_printf("\n");
  pps_printf("    Value : off %lu len %lu\n", entry->value_off,
             entry->value_len);
  print_SHA("    Auth  : ", &entry->auth_key);
  print_SHA("    C2    : ", &entry->c2);
}

void print_SHA(const char *prefix, const struct ckvs_sha *sha) {
  if (sha == NULL)
    return;

  char buf[2 * SHA256_DIGEST_LENGTH + 1];
  SHA256_to_string(sha, buf);

  if (prefix != NULL) {
    pps_printf("%s%s\n", prefix, buf);
  } else {
    pps_printf("%s\n", buf);
  }
}

void hex_encode(const uint8_t *in, size_t len, char *buf) {

  if (in == NULL || buf == NULL)
    return;

  for (size_t i = 0; i < len; i++) {
    sprintf(buf + i * 2, "%02x", in[i]);
  }
  buf[len * 2] = '\0';
}

void SHA256_to_string(const struct ckvs_sha *sha, char *buf) {

  if (sha == NULL || buf == NULL)
    return;

  hex_encode(sha->sha, SHA256_DIGEST_LENGTH, buf);
}

int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b) {
  M_REQUIRE_NON_NULL(a);
  M_REQUIRE_NON_NULL(b);

  return memcmp(a->sha, b->sha, SHA256_DIGEST_LENGTH);
}

int hex_decode(const char *input, uint8_t *output) {
  if (input == NULL || output == NULL)
    return -1;
  // If the input string has length odd, prepend a 0 to it.
  char *input_copy = calloc(strlen(input) + 2, sizeof(char));
  if (input_copy == NULL)
    return -1;

  if (strlen(input) % 2 != 0)
    sprintf(input_copy, "0%s", input);
  else
    sprintf(input_copy, "%s", input);

  size_t len = strlen(input_copy);
  // We clean the errno flag
  errno = 0;

  // We convert input_copy to an array of bytes.
  for (size_t i = 0; i < len; i += 2) {
    char byte[3] = {input_copy[i], input_copy[i + 1], '\0'};
    output[i / 2] = (uint8_t)strtol(byte, NULL, 16);
    if (errno != 0) {
      free(input_copy);
      return -1;
    }
  }
  // If evevrything went well without errno triggering, then the number of bytes
  // that have changed is simply half of the length of the input string (with
  // the correction for the 0 at the beginning when needed).
  free(input_copy);
  return (int)(len / 2);
}

int SHA256_from_string(const char *input, struct ckvs_sha *sha) {
  return hex_decode(input, sha->sha) == SHA256_DIGEST_LENGTH
             ? SHA256_DIGEST_LENGTH
             : -1;
}
