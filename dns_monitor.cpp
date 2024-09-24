#include <pcap.h>
#include "arg_parser.hpp"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ctime>
#include <netinet/if_ether.h>
#include "dns_monitor.hpp"
#include "dns_header.hpp"

bool verboseFlag = false;

int main(int argc, char *argv[]) {
   
    ArgParser parser(argc, argv);
    verboseFlag = parser.verbose;
    char errBuf[PCAP_ERRBUF_SIZE];

    if (!parser.interface.empty()) {
        interface_capture(parser.interface.c_str(), errBuf);
    }

    return 0;
}

void interface_capture(const char *interface, char *errBuf){
    pcap_t *handle;

    //dns filter
    struct bpf_program fp;
    char filterExp[] = "udp port 53";
    bpf_u_int32 net; 

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errBuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << interface << ": " << errBuf << std::endl;
        exit(1);
    }

    if (pcap_lookupnet(interface, &net, &net, errBuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", interface);
        net = 0;
    }
    
    if (pcap_compile(handle, &fp, filterExp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filterExp, pcap_geterr(handle));
        exit(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filterExp, pcap_geterr(handle));
        exit(2);
    }

    pcap_loop(handle, 10, [](u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        print_dns_packet(packet, *header);
        }, NULL);


    pcap_freecode(&fp);
    pcap_close(handle);
}

void print_dns_packet(const u_char *packet, const struct pcap_pkthdr &header) {
    
    //timestamp
    std::time_t rawTime = header.ts.tv_sec;
    std::tm *timeInfo = std::localtime(&rawTime);
    char timeBuffer[80];
    std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", timeInfo);

    //get ip header
    const struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
    std::string srcIp = inet_ntoa(ipHeader->ip_src);
    std::string dstIp = inet_ntoa(ipHeader->ip_dst);

    if (ipHeader->ip_p == IPPROTO_UDP) {
        const struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        uint16_t srcPort = ntohs(udpHeader->uh_sport);
        uint16_t dstPort = ntohs(udpHeader->uh_dport);

        const u_char *dnsPacket = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
        const DnsHeader *dns = (DnsHeader *)dnsPacket;
        uint16_t flags = ntohs(dns->flags);

        //number of records in each section
        int qdCount = ntohs(dns->qdCount);
        int anCount = ntohs(dns->anCount);
        int nsCount = ntohs(dns->nsCount);
        int arCount = ntohs(dns->arCount);

        if (verboseFlag) {
            std::cout << "Timestamp: " << timeBuffer << std::endl;
            std::cout << "SrcIP: " << srcIp << std::endl;
            std::cout << "DstIP: " << dstIp << std::endl;
            std::cout << "SrcPort: UDP/" << srcPort << std::endl;
            std::cout << "DstPort: UDP/" << dstPort << std::endl;
            std::cout << "Identifier: " << ntohs(dns->id) << std::endl;
            std::cout << "Flags: ";
            std::cout << "QR=" << ((flags & 0x8000) >> 15) << ", ";
            std::cout << "OPCODE=" << ((flags & 0x7800) >> 11) << ", ";
            std::cout << "AA=" << ((flags & 0x0400) >> 10) << ", ";
            std::cout << "TC=" << ((flags & 0x0200) >> 9) << ", ";
            std::cout << "RD=" << ((flags & 0x0100) >> 8) << ", ";
            std::cout << "RA=" << ((flags & 0x0080) >> 7) << ", ";
            std::cout << "Z=" << ((flags & 0x0070) >> 4) << ", ";
            std::cout << "RCODE=" << (flags & 0x000F) << std::endl;

            std::cout << std::endl << "[Question Section]" << std::endl;
            // Tu pridaj funkciu na výpis záznamov z Question sekcie (prejdi DNS záznamy)

            if (anCount > 0) {
                std::cout << std::endl << "[Answer Section]" << std::endl;
                // Tu pridaj funkciu na výpis záznamov z Answer sekcie
            }

            if (nsCount > 0) {
                std::cout << std::endl << "[Authority Section]" << std::endl;
                // Tu pridaj funkciu na výpis záznamov z Authority sekcie
            }

            if (arCount > 0) {
                std::cout << std::endl << "[Additional Section]" << std::endl;
                // Tu pridaj funkciu na výpis záznamov z Additional sekcie
            }

            std::cout << "====================" << std::endl;


        } else {
            char qr = ntohs(dns->flags) & 0x8000 ? 'R' : 'Q';  //Q = query, R = response


            std::cout << timeBuffer << " " << srcIp << " -> " << dstIp
                      << " (" << qr << " " << qdCount << "/" << anCount << "/"
                      << nsCount << "/" << arCount << ")" << std::endl;
        }
    }
}

// void print_dns_packet(const u_char *packet, struct pcap_pkthdr p_header){
//     const struct ether_header *ethHeader;
//     ethHeader = (struct ether_header *) packet;

//     if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {

//         //move to IP header
//         const struct ip *ipHeader;
//         ipHeader = (struct ip *)(packet + sizeof(struct ether_header));

//         //extract ip addresses
//         std::string srcIp = inet_ntoa(ipHeader->ip_src);
//         std::string dstIp = inet_ntoa(ipHeader->ip_dst);

//         //if its udp packet
//         if (ipHeader->ip_p == IPPROTO_UDP) {

//             //move to dns part
//             const u_char *dnsPacket = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);

//             const DnsHeader *dns = reinterpret_cast<const DnsHeader *>(dnsPacket);

//             //get time
//             std::time_t rawTime = p_header.ts.tv_sec;
//             std::tm *timeInfo = std::localtime(&rawTime);
//             char timeBuffer[80];
//             std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", timeInfo);

//             char qr = ntohs(dns->flags) & 0x8000 ? 'R' : 'Q';  //Q = query, R = response

//             int qdCount = ntohs(dns->qdCount);
//             int anCount = ntohs(dns->anCount);
//             int nsCount = ntohs(dns->nsCount);
//             int arCount = ntohs(dns->arCount);

//             std::cout << timeBuffer << " " << srcIp << " -> " << dstIp
//                       << " (" << qr << " " << qdCount << "/" << anCount << "/"
//                       << nsCount << "/" << arCount << ")" << std::endl;
//         }
//     }
// }

void get_all_devices(){
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *dev;

    if (pcap_findalldevs(&alldevs, errBuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errBuf);
        exit(1);
    }

    int i = 1;
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        printf("%d. Device: %s\n", i, dev->name);
        i++;
    }

    pcap_freealldevs(alldevs);
}