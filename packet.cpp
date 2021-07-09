#include <cstring>
#include "packet.h"
#include "util.h"

using namespace std;

ForwardPacket make_fwd_packet(const ether_header *eth,
                              const iphdr *ip,
                              const tcphdr *tcp,
                              const uint8_t my_mac[6]) {
    ForwardPacket pk{};
    ::memcpy(&pk.eth, eth, sizeof(ether_header));
    ::memcpy(&pk.eth.ether_shost, my_mac, 6);
    ::memcpy(&pk.ip, ip, sizeof(iphdr));
    ::memcpy(&pk.tcp, tcp, sizeof(tcphdr));

    pk.ip.tot_len = htons(sizeof(iphdr) + sizeof(tcphdr));
    pk.ip.ttl = 64;
    pk.ip.check = 0;
    pk.ip.check = checksum(reinterpret_cast<uint16_t *>(&pk.ip), sizeof(iphdr) / 2);

    uint hl = (ip->ihl << 2) + (tcp->doff << 2);
    uint pl = ip->tot_len - hl;
    pk.tcp.th_seq = htonl(ntohl(tcp->th_seq) + pl);
    pk.tcp.th_off = sizeof(tcphdr) >> 2;
    pk.tcp.th_flags = TH_RST | TH_ACK;
    pk.tcp.th_sum = 0;

    PseudoHeader pseudoHeader{
            pk.ip.saddr,
            pk.ip.daddr,
            0,
            pk.ip.protocol,
            ntohs(sizeof(tcphdr))
    };
    size_t size = sizeof(PseudoHeader) + sizeof(tcphdr);

    auto forChecksum = new uint8_t[size];
    ::memcpy(forChecksum, &pseudoHeader, sizeof(PseudoHeader));
    ::memcpy(forChecksum + sizeof(PseudoHeader), &pk.tcp, sizeof(tcphdr));

    pk.tcp.th_sum = checksum(reinterpret_cast<uint16_t *>(forChecksum), size / 2);

    delete []forChecksum;
    return pk;
}

BackwardPacket make_bwd_packet(const ether_header *eth,
                               const iphdr *ip,
                               const tcphdr *tcp,
                               const uint8_t my_mac[6]) {
    BackwardPacket pk{};
    ::memcpy(&pk.eth, eth, sizeof(ether_header));
    ::memcpy(&pk.eth.ether_dhost, &pk.eth.ether_shost, 6);
    ::memcpy(&pk.eth.ether_shost, my_mac, 6);

    ::memcpy(&pk.ip, ip, sizeof(iphdr));
    ::memcpy(&pk.ip.saddr, &ip->daddr, 4);
    ::memcpy(&pk.ip.daddr, &ip->saddr, 4);
    pk.ip.tot_len = htons(sizeof(iphdr) + sizeof(tcphdr) + 10);
    pk.ip.ttl = 64;
    pk.ip.check = 0;
    pk.ip.check = checksum(reinterpret_cast<uint16_t *>(&pk.ip), sizeof(iphdr) / 2);

    ::memcpy(&pk.tcp, tcp, sizeof(tcphdr));
    ::memcpy(&pk.tcp.th_sport, &tcp->th_dport, 2);
    ::memcpy(&pk.tcp.th_dport, &tcp->th_sport, 2);

    uint hl = (ip->ihl << 2) + (tcp->doff << 2);
    uint pl = ntohs(ip->tot_len) - hl;
    pk.tcp.th_seq = tcp->th_ack;
    pk.tcp.th_ack = htonl(ntohl(tcp->th_seq) + pl);
    pk.tcp.th_off = sizeof(tcphdr) >> 2;
    pk.tcp.th_flags = TH_FIN | TH_ACK | TH_PUSH;
    pk.tcp.th_sum = 0;

    PseudoHeader pseudoHeader{
            pk.ip.saddr,
            pk.ip.daddr,
            0,
            pk.ip.protocol,
            ntohs(sizeof(tcphdr) + 10)
    };
    size_t size = sizeof(PseudoHeader) + sizeof(tcphdr) + 10;

    auto forChecksum = new uint8_t[size];
    ::memcpy(forChecksum, &pseudoHeader, sizeof(PseudoHeader));
    ::memcpy(forChecksum + sizeof(PseudoHeader), &pk.tcp, sizeof(tcphdr));
    ::memcpy(forChecksum + sizeof(PseudoHeader) + sizeof(tcphdr), "blocked!!!", 10);

    pk.tcp.th_sum = checksum(reinterpret_cast<uint16_t *>(forChecksum), size / 2);
    ::memcpy(pk.data, "blocked!!!", 10);

    delete []forChecksum;
    return pk;
}

