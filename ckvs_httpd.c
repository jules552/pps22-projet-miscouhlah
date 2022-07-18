/**
 * @file ckvs_httpd.c
 * @brief webserver
 *
 * @author Edouard Bugnion
 */

#include "ckvs_httpd.h"
#include "ckvs.h"
#include "ckvs_crypto.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "error.h"
#include "mongoose.h"
#include "util.h"
#include <assert.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <string.h>

// Handle interrupts, like Ctrl-C
static int s_signo;

#define HTTP_ERROR_CODE 500
#define HTTP_OK_CODE 200
#define HTTP_FOUND_CODE 302
#define HTTP_NOTFOUND_CODE 404

#define MAX_NAME_SIZE 64

/**
 * @brief handles http stats call
 *
 * @param nc the http connection
 * @param ckvs the ckvs instance that will be filled with the stats
 * @param hm unused
 */
static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs,
                              _unused struct mg_http_message *hm);
/**
 * @brief handles http get call
 *
 * @param nc the http connection
 * @param ckvs the ckvs database
 * @param hm the http message
 */
static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs,
                            struct mg_http_message *hm);

/**
 * @brief handles http set call
 *
 * @param nc the http connection
 * @param ckvs the ckvs database
 * @param hm the http message
 */
static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs,
                            struct mg_http_message *hm);

/**
 * @brief Get the entry from json input
 *
 * @param hm (struct mg_http_message*) the http message
 * @param e_out (struct ckvs_entry**) the entry to fill
 * @param ckvs (struct CKVS*) the ckvs database
 * @param nc (struct mg_connection*) the http connection
 */
static void get_entry_from_json(struct mg_http_message *hm,
                                struct ckvs_entry **e_out, struct CKVS *ckvs,
                                struct mg_connection *nc);

/**
 * @brief Extract key from json input and unescape it
 *
 * @param hm (struct mg_http_message*)
 * @param arg (const char*) the param to look for
 * @return char* the key
 */
static char *get_urldecoded_argument(struct mg_http_message *hm,
                                     const char *arg);

/**
 * @brief Sends an http error message
 * @param nc the http connection
 * @param err the error code corresponding the error message
 */
void mg_error_msg(struct mg_connection *nc, int err) {
  assert(err >= 0 && err < ERR_NB_ERR);
  mg_http_reply(nc, HTTP_ERROR_CODE, NULL, "Error: %s", ERR_MESSAGES[err]);
}

/**
 * @brief Handles signal sent to program, eg. Ctrl+C
 */
static void signal_handler(int signo) { s_signo = signo; }

// ======================================================================
/**
 * @brief Handles server events (eg HTTP requests).
 * For more check https://cesanta.com/docs/#event-handler-function
 */
static void ckvs_event_handler(struct mg_connection *nc, int ev, void *ev_data,
                               void *fn_data) {
  struct mg_http_message *hm = (struct mg_http_message *)ev_data;
  struct CKVS *ckvs = (struct CKVS *)fn_data;

  if (ev != MG_EV_POLL)
    debug_printf("Event received %d", ev);

  switch (ev) {
  case MG_EV_POLL:
  case MG_EV_CLOSE:
  case MG_EV_READ:
  case MG_EV_WRITE:
  case MG_EV_HTTP_CHUNK:
    break;

  case MG_EV_ERROR:
    debug_printf("httpd mongoose error \n");
    break;
  case MG_EV_ACCEPT:
    // students: no need to implement SSL
    assert(ckvs->listening_addr);
    debug_printf("accepting connection at %s\n", ckvs->listening_addr);
    assert(mg_url_is_ssl(ckvs->listening_addr) == 0);
    break;

  case MG_EV_HTTP_MSG:
    // TODO: handle commands calls
    if (mg_http_match_uri(hm, "/stats"))
      handle_stats_call(nc, ckvs, hm);
    else if (mg_http_match_uri(hm, "/get"))
      handle_get_call(nc, ckvs, hm);
    else if (mg_http_match_uri(hm, "/set"))
      handle_set_call(nc, ckvs, hm);
    else
      mg_error_msg(nc, NOT_IMPLEMENTED);
    break;

  default:
    fprintf(stderr, "ckvs_event_handler %u\n", ev);
    assert(0);
  }
}

// ======================================================================
int ckvs_httpd_mainloop(const char *filename, int optargc, char **optargv) {
  if (optargc < 1)
    return ERR_NOT_ENOUGH_ARGUMENTS;
  else if (optargc > 1)
    return ERR_TOO_MANY_ARGUMENTS;

  /* Create server */

  signal(SIGINT,
         signal_handler); // adds interruption signals to the signal handler
  signal(SIGTERM, signal_handler);

  struct CKVS ckvs;
  int err = ckvs_open(filename, &ckvs);

  if (err != ERR_NONE) {
    return err;
  }

  ckvs.listening_addr = optargv[0];

  struct mg_mgr mgr;
  struct mg_connection *c;

  mg_mgr_init(&mgr);

  c = mg_http_listen(&mgr, ckvs.listening_addr, ckvs_event_handler, &ckvs);
  if (c == NULL) {
    debug_printf("Error starting server on address %s\n", ckvs.listening_addr);
    ckvs_close(&ckvs);
    return ERR_IO;
  }

  debug_printf("Starting CKVS server on %s for database %s\n",
               ckvs.listening_addr, filename);

  while (s_signo == 0) {
    mg_mgr_poll(&mgr,
                1000); // infinite loop as long as no termination signal occurs
  }
  mg_mgr_free(&mgr);
  ckvs_close(&ckvs);
  debug_printf("Exiting HTTPD server\n");
  return ERR_NONE;
}

static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs,
                              _unused struct mg_http_message *hm) {
  if (nc == NULL || ckvs == NULL) {
    mg_error_msg(nc, ERR_IO);
    return;
  }

  struct json_object *json = json_object_new_object();

  // Add the header information to the json object
  json_object_object_add(json, "header_string",
                         json_object_new_string(ckvs->header.header_string));
  json_object_object_add(json, "version",
                         json_object_new_int((int32_t)ckvs->header.version));
  json_object_object_add(json, "table_size",
                         json_object_new_int((int32_t)ckvs->header.table_size));
  json_object_object_add(
      json, "threshold_entries",
      json_object_new_int((int32_t)ckvs->header.threshold_entries));
  json_object_object_add(
      json, "num_entries",
      json_object_new_int((int32_t)ckvs->header.num_entries));

  // Add the entries to the json object
  struct json_object *entries = json_object_new_array();
  for (uint32_t i = 0; i < ckvs->header.table_size; i++) {
    if (strlen(ckvs->entries[i].key))
      json_object_array_add(entries,
                            json_object_new_string(ckvs->entries[i].key));
  }
  json_object_object_add(json, "keys", entries);

  // Convert the json object to a string format
  const char *json_string = json_object_to_json_string(json);

  mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n",
                json_string);
  json_object_put(json);
}

static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs,
                            struct mg_http_message *hm) {
  if (nc == NULL || ckvs == NULL || hm == NULL) {
    mg_error_msg(nc, ERR_IO);
    return;
  }

  // We get the key from the url
  struct ckvs_entry *e_out = NULL;
  get_entry_from_json(hm, &e_out, ckvs, nc);
  if (e_out == NULL) {
    // error message already sent
    return;
  }

  struct json_object *json = json_object_new_object();

  // We get back the c2 key from the entry and convert it into hexadecimal
  char c2_hex[2 * CKVS_MAXKEYLEN + 1];
  hex_encode(e_out->c2.sha, CKVS_MAXKEYLEN, c2_hex);
  json_object_object_add(json, "c2", json_object_new_string(c2_hex));

  // We set the cursor on the file to read the data
  int err = fseek(ckvs->file, (long)e_out->value_off, SEEK_SET);
  if (err != 0) {
    json_object_put(json);
    mg_error_msg(nc, ERR_IO);
    return;
  }

  // We declare a buffer to store the data
  char *inbuf = calloc(e_out->value_len + 1, sizeof(char));
  if (inbuf == NULL) {
    json_object_put(json);
    mg_error_msg(nc, ERR_OUT_OF_MEMORY);
    return;
  }

  // We read the data from the file
  err = (int)fread(inbuf, sizeof(char), e_out->value_len, ckvs->file);
  if (err != (int)e_out->value_len) {
    json_object_put(json);
    free(inbuf);
    mg_error_msg(nc, ERR_IO);
    return;
  }

  // Next we convert the data we found into hexadecimal
  char *hex_data = calloc(2 * e_out->value_len + 1, sizeof(char));
  if (hex_data == NULL) {
    json_object_put(json);
    free(inbuf);
    mg_error_msg(nc, ERR_OUT_OF_MEMORY);
    return;
  }

  // We encode the data into hexadecimal
  hex_encode((const unsigned char *)inbuf, e_out->value_len, hex_data);
  free(inbuf);

  // We add the data to the json object
  json_object_object_add(json, "data", json_object_new_string(hex_data));

  // We convert the json object to a string format
  const char *json_string = json_object_to_json_string(json);
  // We send the data to the client
  mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n",
                json_string);

  free(hex_data);
  json_object_put(json);
}

static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs,
                            struct mg_http_message *hm) {
  if (nc == NULL || ckvs == NULL || hm == NULL) {
    mg_error_msg(nc, ERR_IO);
    return;
  }

  if (hm->body.len > 0) {
    // store in temporary buffer the result
    mg_http_upload(nc, hm, "/tmp");
    return; // handle_set_call(nc, ckvs, hm);
  } else {

    struct ckvs_entry *e_out = NULL;
    get_entry_from_json(hm, &e_out, ckvs, nc);

    if (e_out == NULL) {
      // error message already sent
      return;
    }

    // get the name from the url
    char buffer_name[MAX_NAME_SIZE];
    int err =
        mg_http_get_var(&(hm->query), "name", buffer_name, sizeof(buffer_name));
    if (err <= 0) {
      mg_error_msg(nc, ERR_INVALID_ARGUMENT);
      return;
    }

    // read the file tmp/name
    char buffer_file[MAX_NAME_SIZE + 6];
    sprintf(buffer_file, "/tmp/%s", buffer_name);

    size_t file_len = 0;
    char *data = NULL;
    err = read_value_file_content(buffer_file, &data, &file_len);
    if (err != ERR_NONE) {
      mg_error_msg(nc, err);
      return;
    }

    // get the data
    struct json_object *result = json_tokener_parse(data);

    struct json_object *c2_j = NULL, *data_j = NULL;
    json_object_object_get_ex(result, "c2", &c2_j);
    json_object_object_get_ex(result, "data", &data_j);

    if (c2_j == NULL || data_j == NULL) {
      free(data);
      json_object_put(result);
      mg_error_msg(nc, ERR_INVALID_ARGUMENT);
      return;
    }

    // We get the c2 from the json
    const char *c2_h = json_object_get_string(c2_j);
    struct ckvs_sha c2;
    err = hex_decode(c2_h, c2.sha);
    if (err == -1) {
      free(data);
      json_object_put(result);
      mg_error_msg(nc, ERR_INVALID_ARGUMENT);
      return;
    }

    // We get the data from the json
    int data_len = json_object_get_string_len(data_j);
    const char *data_h = json_object_get_string(data_j);
    char *data_d = calloc(data_len, sizeof(char));
    if (data_d == NULL) {
      free(data);
      json_object_put(result);
      mg_error_msg(nc, ERR_OUT_OF_MEMORY);
      return;
    }

    err = hex_decode(data_h, data_d);
    if (err == -1) {
      free(data);
      json_object_put(result);
      mg_error_msg(nc, ERR_INVALID_ARGUMENT);
      return;
    }

    // update the entry
    memcpy(e_out->c2.sha, c2.sha, SHA256_DIGEST_LENGTH);

    // We update the data
    pps_printf("data_d: %s\n", data_d);
    ckvs_write_encrypted_value(ckvs, e_out, data_d, data_len / 2);

    free(data);
    free(data_d);

    
    json_object_put(result);

    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "",
                  NULL);
  }
}

static char *get_urldecoded_argument(struct mg_http_message *hm,
                                     const char *arg) {
  if (hm == NULL || arg == NULL) {
    return NULL;
  }

  // We query the url to get the argument value
  char buffer_key[BUFFER_SIZE];
  int err = mg_http_get_var(&(hm->query), arg, buffer_key, sizeof(buffer_key));
  if (err <= 0)
    return NULL;

  CURL *curl = curl_easy_init();
  if (curl == NULL)
    return NULL;

  // We unscape the value we got because it was previously escaped
  char *decoded =
      curl_easy_unescape(curl, buffer_key, (int)strlen(buffer_key), NULL);
  curl_easy_cleanup(curl);
  return decoded;
}

static void get_entry_from_json(struct mg_http_message *hm,
                                struct ckvs_entry **e_out, struct CKVS *ckvs,
                                struct mg_connection *nc) {
  if (hm == NULL || e_out == NULL || ckvs == NULL || nc == NULL) {
    mg_error_msg(nc, ERR_INVALID_ARGUMENT);
    return;
  }

  char *key = get_urldecoded_argument(hm, "key");
  if (key == NULL) {
    mg_error_msg(nc, ERR_INVALID_ARGUMENT);
    return;
  }

  // We get the auth_key from the url
  char auth_buf[BUFFER_SIZE];
  int err =
      mg_http_get_var(&(hm->query), "auth_key", auth_buf, sizeof(auth_buf));
  if (err <= 0) {
    curl_free(key);
    mg_error_msg(nc, err);
    return;
  }

  // We format it to get back its value
  struct ckvs_sha auth_key;
  err = SHA256_from_string(auth_buf, &auth_key);
  if (err == -1) {
    curl_free(key);
    mg_error_msg(nc, err);
    return;
  }

  // We seek the key in the database, if we don't find it, return an error
  *e_out = ckvs->entries;
  err = ckvs_find_entry(ckvs, key, &auth_key, e_out);
  curl_free(key);
  if (err == ERR_KEY_NOT_FOUND) {
    mg_error_msg(nc, ERR_NO_VALUE);
    *e_out = NULL;
  } else if (err != ERR_NONE) {
    mg_error_msg(nc, err);
    *e_out = NULL;
  }
}
