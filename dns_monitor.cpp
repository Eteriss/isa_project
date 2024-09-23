#include <pcap.h>
#include "arg_parser.hpp"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ctime>
#include <netinet/if_ether.h>
#include "dns_monitor.hpp"


int main(int argc, char *argv[]) {
   
    ArgParser parser(argc, argv);
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!parser.interface.empty()) {
        interface_capture(parser.interface.c_str(), errbuf);
    }

    return 0;
}

void interface_capture(const char *interface, char *errbuf){
    pcap_t *handle;

    //dns filter
    struct bpf_program fp;
    char filter_exp[] = "udp port 53";
    bpf_u_int32 net; 

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << interface << ": " << errbuf << std::endl;
        exit(1);
    }

    if (pcap_lookupnet(interface, &net, &net, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", interface);
        net = 0;
    }
    
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }

    pcap_loop(handle, 10, [](u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        print_dns_packet(packet, *header);
        }, NULL);

    pcap_close(handle);
}

void print_dns_packet(const u_char *packet, struct pcap_pkthdr p_header){
    const struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        //move to IP header
        const struct ip *ip_header;
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        //extract ip addresses
        std::string src_ip = inet_ntoa(ip_header->ip_src);
        std::string dst_ip = inet_ntoa(ip_header->ip_dst);

        // Ak je to UDP paket
        if (ip_header->ip_p == IPPROTO_UDP) {

            //move to dns part
            const u_char *dns_packet = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);

            const dns_header *dns = (dns_header *)dns_packet;

            //get current time
            std::time_t rawtime = p_header.ts.tv_sec;
            std::tm *timeinfo = std::localtime(&rawtime);
            char time_buffer[80];
            std::strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

            // Extrakcia DNS informácií
            char qr = ntohs(dns->flags) & 0x8000 ? 'R' : 'Q';  //Q = query, R = response

            // Počet záznamov v sekciách
            int qdcount = ntohs(dns->qdcount);
            int ancount = ntohs(dns->ancount);
            int nscount = ntohs(dns->nscount);
            int arcount = ntohs(dns->arcount);

            // Výpis výsledkov v požadovanom formáte
            std::cout << time_buffer << " " << src_ip << " -> " << dst_ip
                      << " (" << qr << " " << qdcount << "/" << ancount << "/"
                      << nscount << "/" << arcount << ")" << std::endl;
        }
    }
}

void get_all_devices(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *dev;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        exit(1);
    }

    int i = 1;
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        printf("%d. Device: %s\n", i, dev->name);
        i++;
    }

    pcap_freealldevs(alldevs);
}