/**
 * @file ckvs_client.h
 * @brief Implementation of the commands for a remote database
 * @version 1.0
 * @date 2022-06-05
 *
 * @copyright Copyright (c) 2022
 *
 */

#pragma once

/**
 * @brief Open the database at the given url and execute the equivalent of a
 * stats command onto it.
 *
 * @param url (const chat *) the url of the database
 * @param optargc (int) the number of arguments (should be 0)
 * @param optargv (const char**) the arguments (should be empty)
 * @return int an error code
 */
int ckvs_client_stats(const char *url, int optargc, char *optargv[]);

/**
 * @brief Get the data stored at the given url using the key to identify this
 * database and the auth_key to authenticate the request.
 *
 * @param url (const char *) the url of the database
 * @param optargc (int) the number of arguments (should be 2)
 * @param optargv (const char**) the arguments (should be: key, pwd)
 * @return int an error code
 */
int ckvs_client_get(const char *url, int optargc, char *optargv[]);

/**
 * @brief Set the data of the online database of the given key/pwd to the given
 * value which is a file cointaining the data to set.
 *
 * @param url (const char*) the url of the database
 * @param optargc (int) the number of arguments (should be 3)
 * @param optargv (const char**) the arguments (should be: key, pwd, value)
 * @return int an error code
 */
int ckvs_client_set(const char *url, int optargc, char *optargv[]);