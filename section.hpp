/**
 * @file section.hpp
 * @brief Header file for the Section class.
 * @author Adam Pastierik
 *
 * This file contains the declaration of the Section class.
 * The class is used to represent a section of a DNS packet.
 * The class contains functions for parsing the domain name from the packet.
 */

#ifndef SECTION_HPP
#define SECTION_HPP

#include <string>
#include <unistd.h>
#include <iostream>
#include <utility>

/**
 * @brief Class representing a DNS section.
 */
class Section
{
public:
    /**
     * @brief Constructor for the Section class.
     *
     * @param dnsPacket Pointer to the start of the section in the DNS packet.
     * @param headerPtr Pointer to the start of the DNS header.
     * @param isQuestion True if the section is a question section, false otherwise.
     */
    Section(const u_char *startOfSection, const u_char *headerPtr, bool isQuestion);

    uint16_t type;
    uint16_t dnsClass;
    uint32_t ttl;
    uint16_t dataLen;
    std::string domain;
    const u_char *currentPtr;

    /**
     * @brief Parses the domain name from the DNS packet.
     *
     * @param dnsPacket Pointer to the DNS packet.
     * @param headerPtr Pointer to the start of the DNS header.
     * @return The parsed domain name.
     */
    std::string parse_domain(const u_char *dnsPacket, const u_char *headerPtr);

private:
    /**
     * @brief Determines the length of the domain name in the DNS packet.
     *
     * @param dnsPacket Pointer to the DNS packet.
     * @return The length of the domain name.
     */
    int get_domain_length(const u_char *dnsPacket);
};

#endif