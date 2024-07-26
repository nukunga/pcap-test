#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "eth_ip_tcp.h"

#define ETHER_ADDR_LEN 6

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

		struct ether_header* eth_h;
		struct ip_header* ip_h;
		struct tcp_header* tcp_h;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		eth_h = (struct ether_header *)packet;
		ip_h = (struct ip_header *)(packet + sizeof(*eth_h));
		tcp_h = (struct tcp_header *)(packet + sizeof(*eth_h) + sizeof(ip_h));
		
		printf("=====Ehternet=====\n");
		printf("[Source]\n");
		for(int i=0;i<= ETHER_ADDR_LEN -1; i++){
			if(i ==  ETHER_ADDR_LEN -1){
				printf("%02x\n" ,eth_h->ether_shost.ether_addr_octet[i]);
			}
			else{
				printf("%02x:" ,eth_h->ether_shost.ether_addr_octet[i]);
			}
		}
		printf("[Destination]\n");
		for(int i=0;i<= ETHER_ADDR_LEN -1; i++){
			if(i ==  ETHER_ADDR_LEN -1){
				printf("%02x\n" ,eth_h->ether_dhost.ether_addr_octet[i]);
			}
			else{
				printf("%02x:" ,eth_h->ether_dhost.ether_addr_octet[i]);
			}
		}

		printf("=====IP=====\n");
		printf("[Source IP]\n");
		printf("%d\n", ip_h->ip_srcaddr.s_addr);
		printf("[Destination IP]\n");
	}

	pcap_close(pcap);
}
