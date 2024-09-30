#ifndef DNS_MONITOR_HPP
#define DNS_MONITOR_HPP

#include <string>
#include <unistd.h>
#include <iostream>
#include <pcap.h>
#include "arg_parser.hpp"

class DnsMonitor
{
public:
    DnsMonitor();

    void process_packets(ArgParser parser);
    static void print_dns_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

private:
    char errBuf[PCAP_ERRBUF_SIZE];
    static const u_char *print_dns_question(const u_char *dnsPacket, int qdCount);
    static void print_dns_answer(const u_char *dnsPacket, int anCount, const u_char *startOfAnswer);
    static void print_dns_authority(const u_char *dnsPacket, int nsCount);
    static void print_dns_additional(const u_char *dnsPacket, int arCount);

    static void print_dns_packet_raw(const u_char *packet, size_t length);

    static std::pair<std::string, int> parse_domain(const u_char *dns_packet, const u_char *packet);
    static int get_domain_length(const u_char *dns_packet);
};

#endif