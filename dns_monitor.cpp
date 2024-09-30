#include <stdlib.h>
#include <ctime>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <unordered_map>
#include <string.h>
#include "dns_header.hpp"
#include "dns_monitor.hpp"

using namespace std;

DnsMonitor::DnsMonitor() {}

void DnsMonitor::process_packets(ArgParser parser)
{
    pcap_t *handle;

    // dns filter
    struct bpf_program fp;
    char filterExp[] = "udp port 53";
    bpf_u_int32 net;

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

    pcap_loop(handle, 0, DnsMonitor::print_dns_packet, reinterpret_cast<u_char *>(&parser.verbose));

    pcap_freecode(&fp);
    pcap_close(handle);
}

void DnsMonitor::print_dns_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    bool verboseFlag = *reinterpret_cast<bool *>(args);

    // timestamp
    time_t rawTime = header->ts.tv_sec;
    tm *timeInfo = localtime(&rawTime);
    char timeBuffer[80];
    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", timeInfo);

    // get ip header
    const struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
    string srcIp = inet_ntoa(ipHeader->ip_src);
    string dstIp = inet_ntoa(ipHeader->ip_dst);

    if (ipHeader->ip_p == IPPROTO_UDP)
    {
        const struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        uint16_t srcPort = ntohs(udpHeader->uh_sport);
        uint16_t dstPort = ntohs(udpHeader->uh_dport);

        const u_char *dnsPacket = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
        const DnsHeader *dns = (DnsHeader *)dnsPacket;
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

            cout << endl
                 << "[Question Section]" << endl;
            const u_char *nextSection = print_dns_question(dnsPacket + sizeof(DnsHeader), qdCount);

            if (anCount > 0)
            {
                cout << endl
                     << "[Answer Section]" << endl;
                print_dns_answer(dnsPacket, anCount, nextSection);
            }

            if (nsCount > 0)
            {
                cout << endl
                     << "[Authority Section]" << endl;
                // Tu pridaj funkciu na výpis záznamov z Authority sekcie
            }

            if (arCount > 0)
            {
                cout << endl
                     << "[Additional Section]" << endl;
                // Tu pridaj funkciu na výpis záznamov z Additional sekcie
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
}

const u_char *DnsMonitor::print_dns_question(const u_char *dnsPacket, int qdCount)
{
    const u_char *currentPtr = dnsPacket;

    // mapping of QTYPE and QCLASS values to strings
    unordered_map<uint16_t, string> qTypeMap = {
        {1, "A"}, {28, "AAAA"}, {5, "cName"}, {15, "MX"}, {2, "NS"}, {6, "SOA"}, {33, "SRV"}};
    unordered_map<uint16_t, string> qClassMap = {
        {1, "IN"}};

    for (int i = 0; i < qdCount; ++i)
    {
        pair<string, int> domainPair = parse_domain(currentPtr, dnsPacket);
        string domain = domainPair.first;
        currentPtr += domainPair.second;

        // QTYPE 2 bytes
        uint16_t qtype = ntohs(*((uint16_t *)currentPtr));
        currentPtr += 2;

        // QCLASS 2 bytes
        uint16_t qclass = ntohs(*((uint16_t *)currentPtr));
        currentPtr += 2;

        // ignore unknown QTYPEs
        if (qTypeMap.find(qtype) == qTypeMap.end())
            continue;

        string qTypeStr = qTypeMap[qtype];
        string qClassStr = qClassMap.count(qclass) ? qClassMap[qclass] : to_string(qclass);

        cout << domain << " " << qClassStr << " " << qTypeStr << endl;
    }

    return currentPtr;
}

void DnsMonitor::print_dns_answer(const u_char *headerPtr, int ancount, const u_char *startOfAnswer)
{
    const u_char *currentPtr = startOfAnswer;

    for (int i = 0; i < ancount; i++)
    {

        pair<string, int> domainPair = parse_domain(currentPtr, headerPtr);
        currentPtr += domainPair.second;

        uint16_t type = ntohs(*(uint16_t *)currentPtr);
        currentPtr += 2;

        uint16_t dnsClass = ntohs(*(uint16_t *)currentPtr);
        currentPtr += 2;

        uint32_t ttl = ntohl(*(uint32_t *)currentPtr);
        currentPtr += 4;

        uint16_t dataLen = ntohs(*(uint16_t *)currentPtr);
        currentPtr += 2;

        cout << domainPair.first << " " << ttl << " " << "IN ";

        switch (type)
        {
        case 1:
        { // A record
            struct in_addr addr;
            memcpy(&addr, currentPtr, sizeof(struct in_addr));
            cout << "A " << inet_ntoa(addr) << endl;
            break;
        }
        case 28:
        { // AAAA record
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, currentPtr, addr, sizeof(addr));
            cout << "AAAA " << addr << endl;
            break;
        }
        case 2:
        { // NS record
            string nsName = parse_domain(currentPtr, headerPtr).first;
            cout << "NS " << nsName << endl;
            break;
        }
        case 15:
        { // MX record
            uint16_t preference = ntohs(*(uint16_t *)currentPtr);
            currentPtr += 2;
            string exchange = parse_domain(currentPtr, headerPtr).first;
            cout << "MX " << preference << " " << exchange << endl;
            break;
        }
        case 6:
        { // SOA record
            string mname = parse_domain(currentPtr, headerPtr).first;
            currentPtr += mname.size() + 1;
            string rname = parse_domain(currentPtr, headerPtr).first;
            currentPtr += rname.size() + 1;
            uint32_t serial = ntohl(*(uint32_t *)currentPtr);
            currentPtr += 20;
            cout << "SOA " << mname << " " << rname << " Serial=" << serial << endl;
            break;
        }
        case 5:
        { // CNAME record
            string cname = parse_domain(currentPtr, headerPtr).first;
            cout << "CNAME " << cname << endl;
            break;
        }
        case 33:
        { // SRV record
            uint16_t priority = ntohs(*(uint16_t *)currentPtr);
            currentPtr += 2;
            uint16_t weight = ntohs(*(uint16_t *)currentPtr);
            currentPtr += 2;
            uint16_t port = ntohs(*(uint16_t *)currentPtr);
            currentPtr += 2;
            string target = parse_domain(currentPtr, headerPtr).first;
            cout << "SRV " << priority << " " << weight << " " << port << " " << target << endl;
            break;
        }
        default:
            cout << "UNKNOWN TYPE" << endl;
            break;
        }

        currentPtr += dataLen;
    }
}

pair<string, int> DnsMonitor::parse_domain(const u_char *dnsPacket, const u_char *headerPtr)
{
    string domainName;
    int offset = 0;
    int length = get_domain_length(dnsPacket);
    const u_char *currentPtr = dnsPacket;

    while (*currentPtr != 0)
    {
        if ((*currentPtr & 0xC0) == 0xC0)
        {
            currentPtr += 1;
            offset = *currentPtr;
            currentPtr = headerPtr + offset;
        }
        else
        {
            int labelLength = *currentPtr;
            currentPtr += 1;
            domainName.append((const char *)(currentPtr), labelLength);
            currentPtr += labelLength;
            domainName.append(".");
        }
    }

    if (domainName.back() == '.')
        domainName.pop_back();

    return {domainName, length};
}

int DnsMonitor::get_domain_length(const u_char *dnsPacket)
{
    // const u_char *currentPtr = dnsPacket;
    // int length = 0;

    // while (*currentPtr != 0)
    // {
    //     if ((*currentPtr & 0xC0) == 0xC0)
    //     {
    //         length += 2;
    //         currentPtr += 2;
    //     }
    //     else
    //     {
    //         length += 1;
    //         currentPtr += 1;
    //     }
    // }

    // return length + 1;

    const u_char *current_ptr = dnsPacket;
    int length = 0;

    while (*current_ptr != 0)
    {
        if ((*current_ptr & 0xC0) == 0xC0)
        {
            length += 2;
            break;
        }
        else
        {
            int labelLength = *current_ptr;
            length += labelLength + 1;
            current_ptr += labelLength + 1;
        }
    }

    if ((*current_ptr & 0xC0) != 0xC0)
    {
        length += 1;
    }

    return length;
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
