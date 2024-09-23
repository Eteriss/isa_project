#include <cstdint>
#include <stdio.h>
#include <stdlib.h>

 //dns header
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount; //number of records in question section
    uint16_t ancount; //number of records in answer section
    uint16_t nscount; //number of records in authority section
    uint16_t arcount; //number of records in additional section
};

void get_all_devices();

void print_dns_packet(const u_char *packet, struct pcap_pkthdr p_header);

void interface_capture(const char *interface, char *errbuf);