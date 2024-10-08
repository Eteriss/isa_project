/**
 * @file dns_monitor.hpp
 * @brief Header file for the DNS monitor class.
 * @author Adam Pastierik
 *
 * This file contains the declaration of the DNS monitor class.
 * The class is used to process DNS packets from a network interface or PCAP file.
 * The class also contains static functions for printing DNS packets.
 */

#ifndef DNS_MONITOR_HPP
#define DNS_MONITOR_HPP

#include <string>
#include <unistd.h>
#include <iostream>
#include <pcap.h>
#include <list>
#include "section.hpp"
#include "arg_parser.hpp"

/**
 * @brief Struct representing the DNS header.
 */
struct dns_header
{
    uint16_t id;      // DNS transaction ID.
    uint16_t flags;   // DNS flags for response, opcode, and response code.
    uint16_t qdCount; // Number of entries in the question section.
    uint16_t anCount; // Number of resource records in the answer section.
    uint16_t nsCount; // Number of name server records in the authority section.
    uint16_t arCount; // Number of resource records in the additional records section.
};

/**
 * @brief Class for monitoring DNS packets.
 */
class DnsMonitor
{
public:
    /**
     * @brief Constructor for the DnsMonitor class.
     */
    DnsMonitor();

    /**
     * @brief Processes packets from a network interface or PCAP file.
     *
     * @param parser Parsed command line arguments.
     */
    void process_packets(ArgParser parser);

    /**
     * @brief Prints a DNS packet.
     *
     * @param udpHeader The UDP header of the packet.
     * @param dnsPacket The DNS packet data.
     * @param header The pcap header for the packet.
     * @param srcIp The source IP address.
     * @param dstIp The destination IP address.
     */
    static void print_dns_packet(const struct udphdr *udpHeader, const u_char *dnsPacket, const struct pcap_pkthdr *header, const char *srcIp, const char *dstIp);

private:
    char errBuf[PCAP_ERRBUF_SIZE]; // Buffer for storing error messages from pcap functions.

    static bool verboseFlag;                    // Flag to determine if verbose output is enabled.
    static std::list<std::string> domainNames;  // List of domain names found in DNS packets.
    static std::list<std::string> translations; // List of domain nameand their translations (A/AAAA records).

    /**
     * @brief Determines the IP version of the packet.
     *
     * @param args Argument passed to the callback function.
     * @param header Pcap packet header.
     * @param packet The packet data.
     */
    static void get_ip_version(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

    /**
     * @brief Adds a domain to the list of domains if not already present.
     *
     * @param domain The domain name to add.
     */
    static void add_to_domain_list(std::string domain);

    /**
     * @brief Adds a domain name with its corresponding translation (IP address) to the list.
     *
     * @param domain The domain name.
     * @param translation The translation for the domain.
     */
    static void add_to_translations(std::string domain, std::string translation);

    /**
     * @brief Prints the DNS question section of the packet.
     *
     * @param dnsPacket Pointer to the DNS packet.
     * @param qdCount The number of questions in the question section.
     * @return Pointer to the next section in the packet.
     */
    static const u_char *print_dns_question(const u_char *dnsPacket, int qdCount);

    /**
     * @brief Prints a section of DNS records (Answer, Authority, or Additional sections).
     *
     * @param dnsPacket Pointer to the DNS packet.
     * @param recordCount The number of records in the section.
     * @param startOfSection Pointer to the start of the section in the packet.
     * @return Pointer to the next section in the packet.
     */
    static const u_char *print_section(const u_char *dnsPacket, int recordCount, const u_char *startOfSection);

    /**
     * @brief Prints a single DNS record of a section.
     *
     * @param currentSection A Section object representing the current DNS record.
     * @param headerPtr Pointer to the start of the DNS header.
     * @return Pointer to the next record or section in the packet.
     */
    static const u_char *print_record(Section currentSection, const u_char *headerPtr);

    /**
     * @brief Prints the raw DNS packet for debugging purposes.
     *
     * @param packet Pointer to the DNS packet.
     * @param length Length of the packet.
     */
    static void print_dns_packet_raw(const u_char *packet, size_t length);
};

#endif
