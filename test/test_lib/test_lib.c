#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((visibility("hidden")))
void vuln(const char *input, int len) {

    if (input[0] == 'A' && input[1] == 'B') {
        if (len > 16) {
            char *buf = malloc(16);

            if (buf == NULL)
                return;

            memcpy(buf, input, len);
            free(buf);
        }
    }
}

__attribute__((visibility("default")))
void process(const char *input) {
    int len = strlen(input);

    if (len >= 2 && input[0] == 'A') {
        if (input[1] == 'B') {
            vuln(input, len);
        }
    }
}
