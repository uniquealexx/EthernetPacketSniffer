#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "packet_sniffer.h"

void UsageMessage(const char *progname) {
    // when err
    fprintf(stdout, "Usage: %s -i <interface> -s <ip | mac>\n", progname);
}

int main(int argc, char *argv[]) {
    int iOption = { };
    char* pInterface = NULL;
    char* pHighlight = NULL;

    while ((iOption = getopt(argc, argv, "i:s:h")) != -1) {
        switch (iOption) {
            case 'i':
                pInterface = optarg;
            break;
            case 's':
                pHighlight = optarg;
            break;
            default:
                UsageMessage(argv[0]);
            return 1; // err!
        }
    }

    if (!pInterface || !pHighlight) {
        UsageMessage(argv[0]);
        return 1; // err!
    }

    if (strcmp(pHighlight, "ip") != 0 && strcmp(pHighlight, "mac") != 0) {
        fprintf(stderr, "Invalid highlight option: %s\n", pHighlight);
        UsageMessage(argv[0]);
        return 1; // err!
    }

    if (StartSniffer(pInterface, pHighlight) != 0) {
        fprintf(stderr, "Failed to start sniffer on interface %s\n", pInterface);
        return 1; // err!
    }

    printf("Hello, World!\n");
    return 0;
}