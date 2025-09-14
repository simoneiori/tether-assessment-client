#ifndef JSON_H
#define JSON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>


void parse_str_field(const char *s, const char *key, char *out, size_t outsz);

int parse_int_field(const char *s, const char *key);




#ifdef __cplusplus
}
#endif

#endif /* JSON_H */
