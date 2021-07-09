#include <cstdio>
#include "util.h"

const char *strnstr(const char *haystack, const char *needle, size_t len) {
    size_t needle_len = strlen(needle);

    if (needle_len == 0) {
        return reinterpret_cast<const char *>(haystack);
    }

    for (int i = 0; i <= int(len - needle_len); i++) {
        if ((haystack[0] == needle[0]) && (strncmp(haystack, needle, needle_len) == 0)) {
            return reinterpret_cast<const char *>(haystack);
        }
        haystack++;
    }
    return nullptr;
}

uint16_t checksum(uint16_t *buffer, size_t size) {
    uint32_t result = 0;

    for (int i = 0; i < size; i++) {
        result += ntohs(*buffer);
        buffer++;
    }

    result = (result >> 16) + (result & 0xffff);
    result += result >> 16;

    return htons(~result & 0xffff);
}

void dump(const uint8_t *buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        else if (i != 0 && i % 8 == 0)
            printf("\t");

        printf("%02X ", buf[i]);
    }
    printf("\n");
}
