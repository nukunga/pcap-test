#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h> 
#include<libnet.h>

#define PAYLOAD_SIZE 20

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        struct libnet_ethernet_hdr* eth_h;
        struct libnet_ipv4_hdr* ip_h;
        struct libnet_tcp_hdr* tcp_h;
        const u_char* payload;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        eth_h = (struct libnet_ethernet_hdr *)packet;
        ip_h = (struct libnet_ipv4_hdr *)(packet + sizeof(*eth_h));
        tcp_h = (struct libnet_tcp_hdr *)(packet + sizeof(*eth_h) + (ip_h->ip_hl * 4)); // 헤더 길이, 워드 단위 이므로 *4
        payload = (packet + sizeof(*eth_h) + (ip_h->ip_hl * 4) + (tcp_h->th_off * 4)); // 헤더 길이, 워드 단위 이므로 *4

        
        uint16_t ether_type = ntohs(eth_h->ether_type);

        if (ether_type == 0x0800) {  // 0x0800 IP 패킷인지 확인
            uint8_t ip_protocol = ip_h->ip_p;

            if (ip_protocol == 0x06) {  // TCP 프로토콜인지 확인 
                printf("=====Ethernet=====\n");
                printf("[Source MAC]\n");
                for (int i = 0; i < ETHER_ADDR_LEN; i++) {
                    if (i == ETHER_ADDR_LEN - 1) {
                        printf("%02x\n", eth_h->ether_shost[i]);
                    } else {
                        printf("%02x:", eth_h->ether_shost[i]);
                    }
                }
                printf("[Destination MAC]\n");
                for (int i = 0; i < ETHER_ADDR_LEN; i++) {
                    if (i == ETHER_ADDR_LEN - 1) {
                        printf("%02x\n", eth_h->ether_dhost[i]);
                    } else {
                        printf("%02x:", eth_h->ether_dhost[i]);
                    }
                }

                printf("=====IP=====\n");
                printf("[Source IP]\n");
                printf("%s\n", inet_ntoa(ip_h->ip_src));
                printf("[Destination IP]\n");
                printf("%s\n", inet_ntoa(ip_h->ip_dst));

                printf("=====TCP=====\n");
                printf("[Source Port]\n");
                printf("%d\n", ntohs(tcp_h->th_sport));
                printf("[Destination Port]\n");
                printf("%d\n", ntohs(tcp_h->th_dport));

                printf("=====TCP Payload=====\n");
                for (int i = 0; i < PAYLOAD_SIZE; i++) {
                    printf("%02x ", payload[i]);
                }
                printf("\n");
            }
        }
    }

    pcap_close(pcap);
    return 0;
}
