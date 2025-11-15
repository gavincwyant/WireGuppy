#include <stdio.h>
#include <stddef.h>

void print_strings(const unsigned char *data, size_t len, int min_len) {
    int count = 0;
    size_t start = 0;
    if (!data || len <= 0) return;
    for (size_t i = 0; i < len; i++) {
        if (data[i] >= 32 && data[i] <= 126) {
            if (count == 0) start = i;
            count++;
        } else {
            if (count >= min_len) {
                for (size_t j = start; j < start + count; j++)
                    putchar(data[j]);
                putchar('\n');
            }
            count = 0;
        }
    }

    if (count >= min_len) {
        for (size_t j = start; j < start + count; j++)
            putchar(data[j]);
        putchar('\n');
    }
}
