#ifndef TCP_BLOCK_PACKET_H
#define TCP_BLOCK_PACKET_H

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <vector>

struct ForwardPacket {
    ether_header eth;
    iphdr ip;
    tcphdr tcp;
} __attribute((__packed__));

struct BackwardPacket {
    ether_header eth;
    iphdr ip;
    tcphdr tcp;
    char data[10];
} __attribute((__packed__));

struct PseudoHeader {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_len;
} __attribute((__packed__));

ForwardPacket make_fwd_packet(const ether_header *eth,
                              const iphdr* ip,
                              const tcphdr *tcp,
                              const uint8_t my_mac[6]);

BackwardPacket make_bwd_packet(const ether_header *eth,
                               const iphdr *ip,
                               const tcphdr *tcp,
                               const uint8_t my_mac[6]);

#endif //TCP_BLOCK_PACKET_H
