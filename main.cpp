#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

#include "packet.h"
#include "util.h"

#define MAX_PACKET_SIZE 8192

using namespace std;

char *pattern;
uint8_t my_mac[6];

void handle_packet(pcap_t *handle, const pcap_pkthdr *header, const uint8_t *packet) {
    const uint8_t *ptr = packet;

    auto eth = reinterpret_cast<const ether_header *>(ptr);

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        ptr += sizeof(ether_header);
        auto ip = reinterpret_cast<const iphdr *>(ptr);

        if (ip->protocol == IPPROTO_TCP) {
            uint ihl = ip->ihl * 4;
            ptr += ihl;

            auto tcp = reinterpret_cast<const tcphdr *>(ptr);
            uint thl = tcp->doff * 4;
            uint data_length = header->caplen - (sizeof(ether_header) + ihl + thl);

            if (data_length == 0) {
                return;
            }

            ptr += thl;
            auto data = reinterpret_cast<const char *>(ptr);

            if (strnstr(data, pattern, data_length) != nullptr) {
                cout << pattern << endl;
                ForwardPacket fwd = make_fwd_packet(eth, ip, tcp, my_mac);
                BackwardPacket bwd = make_bwd_packet(eth, ip, tcp, my_mac);

                if (pcap_sendpacket(handle, reinterpret_cast<uint8_t*>(&fwd), sizeof(fwd))) {
                    cerr << "Error sending the packet : " << pcap_geterr(handle) << endl;
                }
                if (pcap_sendpacket(handle, reinterpret_cast<uint8_t*>(&bwd), sizeof(bwd))) {
                    cerr << "Error sending the packet : " << pcap_geterr(handle) << endl;
                }
            }
        }
    }
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        cout << "syntax: " << argv[0] << " <interface> <pattern>" << endl;
        cout << "example: " << argv[0] << " wlan0 \"test.gilgil.net\"" << endl;
    }
    pattern = argv[2];
    get_dev_mac(argv[1], my_mac);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], MAX_PACKET_SIZE, 0, 512, errbuf);

    if (handle == nullptr) {
        cerr << errbuf << endl;
        return -1;
    }

    int res;
    pcap_pkthdr *header;
    const uint8_t *packet;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue;
        handle_packet(handle, header, packet);
    }

    return 0;
}
