/**
 * @file dns_monitor.cpp
 * @brief Implementation file for the DNS monitor class.
 * @author Adam Pastierik
 * login: xpasti00
 */

#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <unordered_map>
#include <string.h>
#include <fstream>
#include "dns_monitor.hpp"
#include "section.hpp"

using namespace std;

list<string> DnsMonitor::domainNames;
list<string> DnsMonitor::translations;
bool DnsMonitor::verboseFlag = false;
pcap_t *DnsMonitor::handle = nullptr;
struct bpf_program DnsMonitor::fp;

DnsMonitor::DnsMonitor() {}

void DnsMonitor::process_packets(ArgParser parser)
{
    // dns filter
    char filterExp[] = "udp port 53";
    bpf_u_int32 net;

    verboseFlag = parser.verbose;

    // if interface is set, open live capture, otherwise open pcap file
    if (!parser.interface.empty())
    {
        const char *interface = parser.interface.c_str();
        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errBuf);
        if (handle == nullptr)
        {
            cerr << "Could not open device " << interface << ": " << errBuf << endl;
            exit(1);
        }

        if (pcap_lookupnet(interface, &net, &net, errBuf) == -1)
        {
            fprintf(stderr, "Can't get netmask for device %s\n", interface);
            net = 0;
            exit(1);
        }
    }
    else
    {
        const char *pcapfile = parser.pcapfile.c_str();
        handle = pcap_open_offline(pcapfile, errBuf);
        if (handle == nullptr)
        {
            cerr << "Could not open pcap file " << pcapfile << ": " << errBuf << endl;
            exit(1);
        }
    }

    if (pcap_compile(handle, &fp, filterExp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filterExp, pcap_geterr(handle));
        exit(2);
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filterExp, pcap_geterr(handle));
        exit(2);
    }

    // start packet processing
    pcap_loop(handle, 0, DnsMonitor::get_ip_version, NULL);

    // write domain names and translations to files
    if (!parser.domainsfile.empty())
    {
        ofstream file(parser.domainsfile);
        for (auto &domain : domainNames)
            file << domain << endl;

        file.close();
    }

    if (!parser.translationsfile.empty())
    {
        ofstream file(parser.translationsfile);
        for (auto &translation : translations)
            file << translation << endl;

        file.close();
    }

    pcap_freecode(&fp);
    pcap_close(handle);
}

void DnsMonitor::get_ip_version(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ether_header *ethHeader;
    const struct sll_header *sllHeader;
    int headerLength = 0;
    uint16_t ethType;

    int dltType = pcap_datalink(handle);

    if (dltType == DLT_LINUX_SLL)
    {
        headerLength = 16;
        sllHeader = reinterpret_cast<const struct sll_header *>(packet);
        ethType = ntohs(sllHeader->sll_proto);
    }
    else if (dltType == DLT_EN10MB)
    {
        headerLength = 14;
        ethHeader = reinterpret_cast<const struct ether_header *>(packet);
        ethType = ntohs(ethHeader->ether_type);
    }

    const struct ip *ipHeader;
    const struct ip6_hdr *ip6Header;

    const struct udphdr *udpHeader;
    const u_char *dnsPacket;

    string srcIp4;
    string dstIp4;
    char srcIp6[INET6_ADDRSTRLEN];
    char dstIp6[INET6_ADDRSTRLEN];

    // determine IP version and call print function with appropriate arguments
    switch (ethType)
    {
    case ETHERTYPE_IP:
        ipHeader = (struct ip *)(packet + headerLength);
        srcIp4 = inet_ntoa(ipHeader->ip_src);
        dstIp4 = inet_ntoa(ipHeader->ip_dst);

        udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        dnsPacket = packet + headerLength + sizeof(struct ip) + sizeof(struct udphdr);

        print_dns_packet(udpHeader, dnsPacket, header, srcIp4.c_str(), dstIp4.c_str());
        break;
    case ETHERTYPE_IPV6:
        ip6Header = (struct ip6_hdr *)(packet + headerLength);

        inet_ntop(AF_INET6, &(ip6Header->ip6_src), srcIp6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6Header->ip6_dst), dstIp6, INET6_ADDRSTRLEN);

        udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        dnsPacket = packet + headerLength + sizeof(struct ip6_hdr) + sizeof(struct udphdr);

        print_dns_packet(udpHeader, dnsPacket, header, srcIp6, dstIp6);
        break;
    default:
        cout << "Unknown packet" << endl;
    }
}

void DnsMonitor::print_dns_packet(const struct udphdr *udpHeader, const u_char *dnsPacket, const struct pcap_pkthdr *header, const char *srcIp, const char *dstIp)
{
    // get timestamp of packet
    time_t rawTime = header->ts.tv_sec;
    tm *timeInfo = localtime(&rawTime);
    char timeBuffer[80];
    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", timeInfo);

    uint16_t srcPort = ntohs(udpHeader->uh_sport);
    uint16_t dstPort = ntohs(udpHeader->uh_dport);

    const dns_header *dns = (dns_header *)dnsPacket;
    uint16_t flags = ntohs(dns->flags);

    // number of records in each section
    int qdCount = ntohs(dns->qdCount);
    int anCount = ntohs(dns->anCount);
    int nsCount = ntohs(dns->nsCount);
    int arCount = ntohs(dns->arCount);

    if (verboseFlag)
    {
        cout << "Timestamp: " << timeBuffer << endl;
        cout << "SrcIP: " << srcIp << endl;
        cout << "DstIP: " << dstIp << endl;
        cout << "SrcPort: UDP/" << srcPort << endl;
        cout << "DstPort: UDP/" << dstPort << endl;
        cout << "Identifier: 0x" << hex << ntohs(dns->id) << dec << endl;
        cout << "Flags: ";
        cout << "QR=" << ((flags & 0x8000) >> 15) << ", ";
        cout << "OPCODE=" << ((flags & 0x7800) >> 11) << ", ";
        cout << "AA=" << ((flags & 0x0400) >> 10) << ", ";
        cout << "TC=" << ((flags & 0x0200) >> 9) << ", ";
        cout << "RD=" << ((flags & 0x0100) >> 8) << ", ";
        cout << "RA=" << ((flags & 0x0080) >> 7) << ", ";
        cout << "Z=" << ((flags & 0x0070) >> 4) << ", ";
        cout << "RCODE=" << (flags & 0x000F) << endl;

        const u_char *nextSection; // pointer to the next section in the DNS packet

        cout << endl
             << "[Question Section]" << endl;
        nextSection = print_dns_question(dnsPacket + sizeof(struct dns_header), qdCount);

        if (anCount > 0)
        {
            cout << endl
                 << "[Answer Section]" << endl;
            nextSection = print_section(dnsPacket, anCount, nextSection);
        }

        if (nsCount > 0)
        {
            cout << endl
                 << "[Authority Section]" << endl;
            nextSection = print_section(dnsPacket, nsCount, nextSection);
        }

        if (arCount > 0)
        {
            cout << endl
                 << "[Additional Section]" << endl;
            print_section(dnsPacket, arCount, nextSection);
        }

        cout << "====================" << endl;
    }
    else
    {
        char qr = ntohs(dns->flags) & 0x8000 ? 'R' : 'Q'; // Q = query, R = response

        cout << timeBuffer << " " << srcIp << " -> " << dstIp
             << " (" << qr << " " << qdCount << "/" << anCount << "/"
             << nsCount << "/" << arCount << ")" << endl;
    }
}

const u_char *DnsMonitor::print_dns_question(const u_char *dnsPacket, int qdCount)
{
    const u_char *currentPtr = dnsPacket; // pointer to the current position in the DNS packet
    // mapping of QTYPE and QCLASS values to strings
    unordered_map<uint16_t, string> qTypeMap = {
        {1, "A"}, {28, "AAAA"}, {5, "CNAME"}, {15, "MX"}, {2, "NS"}, {6, "SOA"}, {33, "SRV"}};
    unordered_map<uint16_t, string> qClassMap = {
        {1, "IN"}};

    for (int i = 0; i < qdCount; ++i)
    {
        Section questionSection(currentPtr, dnsPacket, true);
        uint16_t qtype = questionSection.type;
        uint16_t qclass = questionSection.dnsClass;
        string domain = questionSection.domain;
        currentPtr = questionSection.currentPtr;

        // ignore unknown query types
        if (qTypeMap.find(qtype) == qTypeMap.end() || qClassMap.find(qclass) == qClassMap.end())
            continue;

        add_to_domain_list(domain);

        string qTypeStr = qTypeMap[qtype];
        string qClassStr = qClassMap[qclass];

        cout << domain << " " << qClassStr << " " << qTypeStr << endl;
    }

    return currentPtr;
}

const u_char *DnsMonitor::print_section(const u_char *headerPtr, int recordCount, const u_char *startOfSection)
{
    const u_char *recordPtr = startOfSection;

    for (int i = 0; i < recordCount; i++)
    {
        Section section(recordPtr, headerPtr, false);
        recordPtr = print_record(section, headerPtr);
    }

    return recordPtr;
}

const u_char *DnsMonitor::print_record(Section currentSection, const u_char *headerPtr)
{
    uint16_t type = currentSection.type;
    uint32_t ttl = currentSection.ttl;
    uint16_t dataLen = currentSection.dataLen;
    string domain = currentSection.domain;

    // print corresponding record based on the type
    switch (type)
    {
    case 1:
    { // A record
        struct in_addr addr;
        memcpy(&addr, currentSection.currentPtr, sizeof(struct in_addr));
        cout << domain << " " << ttl << " " << "IN " << "A " << inet_ntoa(addr) << endl;
        add_to_domain_list(domain);
        add_to_translations(domain, inet_ntoa(addr));
        currentSection.currentPtr += dataLen;
        break;
    }
    case 28:
    { // AAAA record
        char addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, currentSection.currentPtr, addr, sizeof(addr));
        cout << domain << " " << ttl << " " << "IN " << "AAAA " << addr << endl;
        add_to_domain_list(domain);
        add_to_translations(domain, addr);
        currentSection.currentPtr += dataLen;
        break;
    }
    case 2:
    { // NS record
        string nsName = currentSection.parse_domain(currentSection.currentPtr, headerPtr);
        cout << domain << " " << ttl << " " << "IN " << "NS " << nsName << endl;
        add_to_domain_list(domain);
        add_to_domain_list(nsName);
        break;
    }
    case 15:
    { // MX record
        uint16_t preference = ntohs(*(uint16_t *)currentSection.currentPtr);
        currentSection.currentPtr += 2;
        string exchange = currentSection.parse_domain(currentSection.currentPtr, headerPtr);
        if (exchange == "")
            exchange = "<Root>";
        cout << domain << " " << ttl << " " << "IN " << "MX " << preference << " " << exchange << endl;
        add_to_domain_list(domain);
        break;
    }
    case 6:
    { // SOA record
        string mname = currentSection.parse_domain(currentSection.currentPtr, headerPtr);
        string rname = currentSection.parse_domain(currentSection.currentPtr, headerPtr);
        add_to_domain_list(domain);
        add_to_domain_list(mname);

        uint32_t serial = ntohl(*(uint32_t *)currentSection.currentPtr);
        currentSection.currentPtr += 4;
        uint32_t refresh = ntohl(*(uint32_t *)currentSection.currentPtr);
        currentSection.currentPtr += 4;
        uint32_t retry = ntohl(*(uint32_t *)currentSection.currentPtr);
        currentSection.currentPtr += 4;
        uint32_t expire = ntohl(*(uint32_t *)currentSection.currentPtr);
        currentSection.currentPtr += 4;
        uint32_t minimumTTL = ntohl(*(uint32_t *)currentSection.currentPtr);
        currentSection.currentPtr += 4;

        cout << domain << " " << ttl << " IN SOA " << mname << " " << rname << " (" << endl;
        cout << "   " << serial << " ; Serial" << endl;
        cout << "   " << refresh << " ; Refresh" << endl;
        cout << "   " << retry << " ; Retry" << endl;
        cout << "   " << expire << " ; Expire" << endl;
        cout << "   " << minimumTTL << " ; Minimum TTL" << endl;
        cout << ")" << endl;
        break;
    }
    case 5:
    { // CNAME record
        string cname = currentSection.parse_domain(currentSection.currentPtr, headerPtr);
        cout << domain << " " << ttl << " " << "IN " << "CNAME " << cname << endl;
        add_to_domain_list(domain);
        add_to_domain_list(cname);
        break;
    }
    case 33:
    { // SRV record
        uint16_t priority = ntohs(*(uint16_t *)currentSection.currentPtr);
        currentSection.currentPtr += 2;
        uint16_t weight = ntohs(*(uint16_t *)currentSection.currentPtr);
        currentSection.currentPtr += 2;
        uint16_t port = ntohs(*(uint16_t *)currentSection.currentPtr);
        currentSection.currentPtr += 2;
        string target = currentSection.parse_domain(currentSection.currentPtr, headerPtr);
        cout << domain << " " << ttl << " " << "IN " << "SRV " << priority << " " << weight << " " << port << " " << target << endl;
        add_to_domain_list(domain);
        add_to_domain_list(target);
        break;
    }
    default:
        currentSection.currentPtr += dataLen;
    }

    return currentSection.currentPtr;
}

void DnsMonitor::add_to_domain_list(string domain)
{
    domain.pop_back(); // remove trailing dot
    bool found = false;

    for (const auto &item : domainNames)
    {
        if (item == domain)
        {
            found = true;
            break;
        }
    }

    // add domain to list if not already present
    if (!found)
        domainNames.push_back(domain);
}

void DnsMonitor::add_to_translations(string domain, string translation)
{
    bool found = false;
    domain.pop_back();
    string domainTranslation = domain + " " + translation;
    for (const auto &item : translations)
    {
        if (item == domainTranslation)
        {
            found = true;
            break;
        }
    }

    // add domain with its translation to list if not already present
    if (!found)
        translations.push_back(domainTranslation);
}

void DnsMonitor::handle_interrupt(int signum)
{
    if (handle != nullptr)
    {
        pcap_breakloop(handle);
        pcap_freecode(&fp);
        pcap_close(handle);
    }
    exit(0);
}

void DnsMonitor::print_dns_packet_raw(const u_char *packet, size_t length)
{
    std::cout << "DNS Packet (Hex):" << std::endl;
    for (size_t i = 0; i < length; ++i)
    {
        // Vypíše každý bajt ako dvojciferné hexa číslo
        printf("%02x ", packet[i]);

        // Pre lepší prehľad vloží zalomenie riadku každých 16 bajtov
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }

    // Ak posledný riadok neobsahoval presne 16 bajtov, ukonči riadok
    if (length % 16 != 0)
        std::cout << std::endl;
}
