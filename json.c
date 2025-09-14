/**
 * @file json.c
 * @brief Utilities for JSON parsing
 *
 * For low-level token extraction from JSON string,
 * we use JSMN library (https://github.com/zserge/jsmn)
 *
 *
 * @author Simone Iori
 * @date 14.09.2025
 */

#include <stdlib.h>
#include <string.h>

#include "jsmn.h"




#define MIN(a,b)	( (a) < (b) ? (a) : (b) )
#define MAX(a,b)	( (a) > (b) ? (a) : (b) )

/**
 * @brief Parse a string value from a JSON string
 *
 * It looks for the provided key inside the JSON string,
 * and return the found value up to 'outsz' characters.
 *
 * @param s Pointer to the entire JSON string
 * @param key Key we are looking for
 * @param out Pointer to the parse value string, if found. If not found is NULL
 * @param outsz Size of the output buffer
 * @return Nothing
 */
void parse_str_field(const char *s, const char *key, char *out, size_t outsz) {

	jsmn_parser parser;
	jsmntok_t tokens[20]; // Array to hold tokens

    jsmn_init(&parser);
    int ret = jsmn_parse(&parser, s, strlen(s), tokens, 30);

	const char *valPtr;
    int valLen;

    for (int i = 0; i < ret - 1; i++) {
	   if ((tokens[i].type == JSMN_STRING) && (tokens[i + 1].type == JSMN_STRING)) {
		   const char *keyPtr = s + tokens[i].start;
		   int keyLen = tokens[i].end - tokens[i].start;

		   if (strncmp(keyPtr, key, keyLen) == 0) {

			   valPtr = s + tokens[i + 1].start;
			   valLen = tokens[i + 1].end - tokens[i + 1].start;

			   int maxLen = MIN(outsz - 1, valLen);
			   strncpy (out, valPtr, maxLen);
			   out[maxLen] = '\0';
			   return;
		   }
	   }
    }

    out[0] = '\0';
}

/**
 * @brief Parse an integer value from a JSON string
 *
 * It looks for the provided key inside the JSON string,
 * and return the found value.
 *
 * @param s Pointer to the entire JSON string
 * @param key Key we are looking for
 * @return The parse value on success, -1 if value is not found.
 */
int parse_int_field(const char *s, const char *key) {

	jsmn_parser parser;
	jsmntok_t tokens[20]; // Array to hold tokens

    jsmn_init(&parser);
    int ret = jsmn_parse(&parser, s, strlen(s), tokens, 30);

    for (int i = 0; i < ret - 1; i++) {
	   if ((tokens[i].type == JSMN_STRING) && (tokens[i + 1].type == JSMN_PRIMITIVE)) {
		   const char *keyPtr = s + tokens[i].start;
		   int keyLen = tokens[i].end - tokens[i].start;

		   if (strncmp(keyPtr, key, keyLen) == 0) {
			   const char *valPtr = s + tokens[i + 1].start;
			   return strtol (valPtr, NULL, 10);
		   }
	   }
    }

    return -1;
}
