#ifndef TCP_BLOCK_UTIL_H
#define TCP_BLOCK_UTIL_H

#include <cstring>
#include <cstdint>
#include <netinet/ip.h>

const char *strnstr(const char* haystack, const char *needle, size_t len);
uint16_t checksum(uint16_t *buffer, size_t size);
void dump(const uint8_t *buf, int size);

#endif //TCP_BLOCK_UTIL_H
