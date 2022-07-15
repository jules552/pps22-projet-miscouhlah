/**
 * @file ckvs_local.h
 * @brief ckvs_local -- operations on local databases
 *
 * @author E. Bugnion
 */
#pragma once

#include "ckvs_io.h"

/* *************************************************** *
 * TODO WEEK 04                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'stats'
 * command, ie. prints information about the database. DO NOT FORGET TO USE
 * pps_printf to print the header/entries!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) the number of arguments (should be 0)
 * @param optargv (const char**) the arguments (should be empty)
 * @return int, an error code
 */
int ckvs_local_stats(const char *filename, int optargc, char *optargv[]);

/* *************************************************** *
 * TODO WEEK 05                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'get'
 * command, ie. fetches, decrypts and prints the entry corresponding to the key
 * and password. DO NOT FORGET TO USE pps_printf to print to value!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) the number of arguments (should be 2)
 * @param optargv (const char**) the arguments (should be: key, pwd)
 *  - key (const char*) the key of the entry to get
 *  - pwd (const char*) the password of the entry to get
 * @return int, an error code
 */
int ckvs_local_get(const char *filename, int optargc, char *optargv[]);

/* *************************************************** *
 * TODO WEEK 06                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'set'
 * command, ie. fetches the entry corresponding to the key and password and then
 * sets the encrypted content of valuefilename as new content.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) the number of arguments (should be 3)
 * @param optargv (const char**) the arguments (should be: key, pwd,
 * valuefilename)
 *  - key (const char*) the key of the entry to set
 *  - pwd (const char*) the password of the entry to set
 *  - valuefilename (const char*) the path to the file which contains what will
 * become the new encrypted content of the entry.
 * @return int, an error code
 */
int ckvs_local_set(const char *filename, int optargc, char *optargv[]);

/* *************************************************** *
 * TODO WEEK 07                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'new'
 * command, ie. creates a new entry with the given key and password.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) the number of arguments (should be 2)
 * @param optargv (const char**) the arguments (should be key and password)
 *  - key (const char*) the key of the entry to create
 *  - pwd (const char*) the password of the entry to create
 * @return int, an error code
 */
int ckvs_local_new(const char *filename, int optargc, char *optargv[]);

/* *************************************************** *
 * TODO WEEK 09: Refactor ckvs_local_*** commands      *
 * *************************************************** */
