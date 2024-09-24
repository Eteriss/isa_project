#include <cstdint>
#include <stdio.h>
#include <stdlib.h>

void get_all_devices();

void print_dns_packet(const u_char *packet, const struct pcap_pkthdr &header);

void interface_capture(const char *interface, char *errbuf);