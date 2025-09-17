#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libopendkim/dkim.h"
#include "libopendkim/dkim-internal.h"

int main() {
    DKIM_LIB *lib;
    char *output = NULL;
    DKIM_STAT result;

    // Initialize DKIM library
    lib = dkim_init(NULL, NULL);
    if (lib == NULL) {
        printf("Failed to init DKIM library\n");
        return 1;
    }

    // Test cases
    const char *test_domains[] = {
        "example.com",           // ASCII domain
        "münchen.de",           // German umlaut
        "тест.рф",              // Cyrillic
        "測試.台灣",             // Chinese
        "テスト.日本",           // Japanese
        NULL
    };

    for (int i = 0; test_domains[i] != NULL; i++) {
        printf("Testing: %s\n", test_domains[i]);

        result = dkim_convert_domain(test_domains[i], &output);

        if (result == DKIM_STAT_OK) {
            printf("  -> %s ✓\n", output);
            free(output);
            output = NULL;
        } else {
            printf("  -> ERROR (code: %d) ✗\n", result);
        }
        printf("\n");
    }

    dkim_close(lib);
    return 0;
}
