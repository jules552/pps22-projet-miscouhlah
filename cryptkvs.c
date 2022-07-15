/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */

#include "ckvs_client.h"
#include "ckvs_httpd.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"
#include "error.h"
#include <stdio.h>

#define HTTP_CHECK_LENGTH 4

/* *************************************************** *
 * TODO WEEK 09-11: Add then augment usage messages    *
 * *************************************************** */
typedef int (*ckvs_command)(const char *, int, char **);
typedef struct ckvs_command_mapping {
  const char *name;
  const char *description;
  ckvs_command command_local;
  ckvs_command command_remote;
} ckvs_command_mapping_t;

static const ckvs_command_mapping_t commands[] = {
    {"stats", "", &ckvs_local_stats, &ckvs_client_stats},
    {"get", "<key> <password>", &ckvs_local_get, &ckvs_client_get},
    {"set", "<key> <password> <filename>", &ckvs_local_set, &ckvs_client_set},
    {"new", "<key> <password>", &ckvs_local_new, NULL},
    {"httpd", "<url>", &ckvs_httpd_mainloop, NULL}};

/* *************************************************** *
 * TODO WEEK 04-07: add message                        *
 * TODO WEEK 09: Refactor usage()                      *
 * *************************************************** */
static void usage(const char *execname, int err) {
  if (err == ERR_INVALID_COMMAND) {
    pps_printf("Available commands:\n");
    size_t nb_commands = sizeof(commands) / sizeof(ckvs_command_mapping_t);
    for (size_t i = 0; i < nb_commands; i++) {
      if (i < nb_commands - 1)
        pps_printf("- cryptkvs [<database>|<url>] %s %s\n", commands[i].name,
                   commands[i].description);
      else
        pps_printf("- cryptkvs <database> %s %s\n", commands[i].name,
                   commands[i].description);
    }
  } else if (err >= 0 && err < ERR_NB_ERR) {
    pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
  } else {
    pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
  }
}

/* *************************************************** *
 * TODO WEEK 04-11: Add more commands                  *
 * TODO WEEK 09: Refactor ckvs_local_*** commands      *
 * *************************************************** */
/**
 * @brief Runs the command requested by the user in the command line, or returns
 * ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int) the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 */
int ckvs_do_one_cmd(int argc, char *argv[]) {
  M_REQUIRE_NON_NULL(argv);

  static const size_t nb_commands =
      sizeof(commands) / sizeof(ckvs_command_mapping_t);
  if (argc < 3) {
    return ERR_INVALID_COMMAND;
  }

  for (size_t i = 0; i < nb_commands; i++) {
    if (strcmp(argv[2], commands[i].name) == 0) {
      if (strncmp(argv[1], "http", HTTP_CHECK_LENGTH) == 0) {
        // valid command only in local
        if (commands[i].command_remote == NULL) {
          return ERR_INVALID_COMMAND;
        }
        return commands[i].command_remote(argv[1], argc - 3, argv + 3);
      } else {
        return commands[i].command_local(argv[1], argc - 3, argv + 3);
      }
    }
  }
  return ERR_INVALID_COMMAND;
}

#ifndef FUZZ
/**
 * @brief main function, runs the requested command and prints the resulting
 * error if any.
 */
int main(int argc, char *argv[]) {
  int ret = ckvs_do_one_cmd(argc, argv);
  if (ret != ERR_NONE) {
    usage(argv[0], ret);
  }
  return ret;
}
#endif
