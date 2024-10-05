#ifndef DNS_MONITOR_HPP
#define DNS_MONITOR_HPP

#include <string>
#include <unistd.h>
#include <iostream>
#include <pcap.h>
#include <list>
#include "section.hpp"
#include "arg_parser.hpp"

struct dns_header
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdCount;
    uint16_t anCount;
    uint16_t nsCount;
    uint16_t arCount;
};

class DnsMonitor
{
public:
    DnsMonitor();

    void process_packets(ArgParser parser);
    static void print_dns_packet(const struct udphdr *udpHeader, const u_char *dnsPacket, const struct pcap_pkthdr *header, const char *srcIp, const char *dstIp);

private:
    char errBuf[PCAP_ERRBUF_SIZE];
    static bool verboseFlag;
    static std::list<std::string> domainNames;
    static std::list<std::string> translations;

    static void get_ip_version(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
    static void add_to_domain_list(std::string domain);
    static void add_to_translations(std::string domain, std::string translation);

    static const u_char *print_dns_question(const u_char *dnsPacket, int qdCount);
    static const u_char *print_dns_answer(const u_char *dnsPacket, int anCount, const u_char *startOfAnswer);
    static const u_char *print_dns_authority(const u_char *dnsPacket, int nsCount, const u_char *startOfAuthority);
    static void print_dns_additional(const u_char *dnsPacket, int arCount, const u_char *startOfAdditional);
    static const u_char *print_soa_record(Section currentSection, const u_char *headerPtr, std::string domain, uint32_t ttl);

    static void print_dns_packet_raw(const u_char *packet, size_t length);
};

#endif