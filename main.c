#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "packet_sniffer.h"

void HelpMessage(const char *programName) {
    printf("Usage: %s -i <interface> -s <highlight>\n", programName);
    printf("Options:\n");
    printf("  -i <interface>   Specify the interface to use (required)\n");
    printf("  -s <highlight>   Specify the highlight value (required)\n");
    printf("  -h               Show this help message and exit\n");
    printf("\nExample:\n");
    printf("  %s -i eth0 -s 192.168.1.1\n", programName);
}

int main(int argc, char *argv[]) {
    int iOption = { };
    char* pInterface = NULL;
    char* pHighlight = NULL;

    // parameter 'h' is stub for output info about usage program (like when user wrong input parameters)
    while ((iOption = getopt(argc, argv, "i:s:h")) != -1) {
        switch (iOption) {
            case 'i':
                pInterface = optarg;
            break;
            case 's':
                pHighlight = optarg;
            break;
            case 'h':
                HelpMessage(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                HelpMessage(argv[0]);
            return 1; // err!
        }
    }

    if (!pInterface || !pHighlight) {
        HelpMessage(argv[0]);
        return 1; // err!
    }

    if (strcmp(pHighlight, "ip") != 0 && strcmp(pHighlight, "mac") != 0) {
        fprintf(stderr, "Invalid highlight option: %s\n", pHighlight);
        HelpMessage(argv[0]);
        return 1; // err!
    }

    if (StartSniffer(pInterface, pHighlight) != 0) {
        fprintf(stderr, "Failed to start sniffer on interface %s\n", pInterface);
        return 1; // err!
    }

    printf("Hello, World!\n");
    return 0;
}