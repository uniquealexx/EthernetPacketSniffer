#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include "packet_sniffer.h"

void MacAddressMessage(const unsigned char* szMac, const char* szLabel) {
    printf("%s MAC: \033[1m%02x:%02x:%02x:%02x:%02x:%02x\033[0m\n", szLabel,
           szMac[0], szMac[1], szMac[2], szMac[3], szMac[4], szMac[5]);
}

void IPAddressMessage(const uint32_t* uIp, const char* szLabel) {
    struct in_addr addr;
    addr.s_addr = *uIp;
    printf("%s IP: \033[1m%s\033[0m\n", szLabel, inet_ntoa(addr));
}

void PacketHandler(const unsigned char* szPacket, const char* szIighlight) {
    struct ether_header* ethHeader = (struct ether_header *)szPacket;
    struct iphdr* ipHeader = (struct iphdr *)(szPacket + sizeof(struct ether_header));

    printf("Ethernet packet captured:\n");
    if (strcmp(szIighlight, "mac") == 0) {
        MacAddressMessage(ethHeader->ether_shost, "Source");
        MacAddressMessage(ethHeader->ether_dhost, "Destination");
    } else if (strcmp(szIighlight, "ip") == 0) {
        IPAddressMessage(&ipHeader->saddr, "Source");
        IPAddressMessage(&ipHeader->daddr, "Destination");
    }

    printf("\nPacket data:");
    for (int i = 0; i < 64; i++) {
        if (i % 32 == 0) {
            printf("\n");
        }
        printf("%02x ", szPacket[i]);
    }
    printf("\n\n");
}

int StartSniffer(const char* szInterface, const char* szHighlight) {
    int iSockfd;
    struct ifreq ifIdx;
    struct sockaddr_ll socketAddress;
    unsigned char *szBuffer = (unsigned char *)malloc(65536);

    if ((iSockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("socket");
        return 1; // err!
    }

    memset(&ifIdx, 0, sizeof(struct ifreq));
    strncpy(ifIdx.ifr_name, szInterface, IFNAMSIZ - 1);
    if (ioctl(iSockfd, SIOCGIFINDEX, &ifIdx) < 0) {
        perror("SIOCGIFINDEX");
        return 1; // err!
    }

    memset(&socketAddress, 0, sizeof(struct sockaddr_ll));
    socketAddress.sll_family = PF_PACKET;
    socketAddress.sll_protocol = htons(ETH_P_ALL);
    socketAddress.sll_ifindex = ifIdx.ifr_ifindex;

    if (bind(iSockfd, (struct sockaddr *)&socketAddress, sizeof(socketAddress)) < 0) {
        perror("bind");
        return 1; // err!
    }

    while (1) {
        int data_size = recvfrom(iSockfd, szBuffer, 65536, 0, NULL, NULL);
        if (data_size < 0) {
            perror("recvfrom");
            return 1; // err!
        }
        PacketHandler(szBuffer, szHighlight);
    }

    close(iSockfd);
    free(szBuffer);
    return 0;
}


