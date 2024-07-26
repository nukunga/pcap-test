#include <netinet/in.h>

struct ether_addr {
    unsigned char ether_addr_octet[6];
};

struct ether_header {
    struct ether_addr ether_dhost; // Destination MAC address
    struct ether_addr ether_shost; // Source MAC address
    unsigned short ether_type;     // Protocol type (IP, ARP, etc.)
};

struct ip_header {
    unsigned char ip_version:4;       // IP version (typically 4 for IPv4)
    unsigned char ip_header_len:4;    // Header length (in 32-bit words)
    unsigned char ip_tos;             // Type of service
    unsigned short ip_total_length;   // Total length
    unsigned short ip_id;             // Identification
    unsigned short ip_frag_offset:13; // Fragment offset field
    unsigned char ip_more_fragment:1; // More fragments flag
    unsigned char ip_dont_fragment:1; // Don't fragment flag
    unsigned char ip_reserved_zero:1; // Reserved zero bit
    unsigned char ip_frag_offset1;    // Fragment offset field (continuation)
    unsigned char ip_ttl;             // Time to live
    unsigned char ip_protocol;        // Protocol (TCP, UDP, etc.)
    unsigned short ip_checksum;       // Header checksum
    struct in_addr ip_srcaddr;        // Source address
    struct in_addr ip_destaddr;       // Destination address
};

struct tcp_header {
    unsigned short source_port;       // Source port
    unsigned short dest_port;         // Destination port
    unsigned int sequence;            // Sequence number
    unsigned int acknowledge;         // Acknowledgement number
    unsigned char data_offset:4;      // Data offset (in 32-bit words)
    unsigned char reserved_part1:3;   // Reserved
    unsigned char ns:1;               // ECN-nonce concealment protection
    unsigned char fin:1;              // FIN flag
    unsigned char syn:1;              // SYN flag
    unsigned char rst:1;              // RST flag
    unsigned char psh:1;              // PSH flag
    unsigned char ack:1;              // ACK flag
    unsigned char urg:1;              // URG flag
    unsigned char ecn:1;              // ECN flag
    unsigned char cwr:1;              // Congestion window reduced flag
    unsigned short window;            // Window size
    unsigned short checksum;          // Checksum
    unsigned short urgent_pointer;    // Urgent pointer
};

