/**
 * @file section.cpp
 * @brief Implementation file for the Section class.
 * @author Adam Pastierik
 * login: xpasti00
 */

#include <arpa/inet.h>
#include "section.hpp"

Section::Section(const u_char *startOfSection, const u_char *headerPtr, bool isQuestion)
{
    currentPtr = startOfSection;
    domain = parse_domain(currentPtr, headerPtr);

    type = ntohs(*(uint16_t *)currentPtr);
    currentPtr += 2;

    dnsClass = ntohs(*(uint16_t *)currentPtr);
    currentPtr += 2;

    if (!isQuestion)
    {
        ttl = ntohl(*(uint32_t *)currentPtr);
        currentPtr += 4;

        dataLen = ntohs(*(uint16_t *)currentPtr);
        currentPtr += 2;
    }
}

std::string Section::parse_domain(const u_char *dnsPacket, const u_char *headerPtr)
{
    std::string domainName;
    int length = get_domain_length(dnsPacket);
    const u_char *currentPtr = dnsPacket;

    while (*currentPtr != 0)
    {
        // check if the domain name is compressed
        if ((*currentPtr & 0xC0) == 0xC0)
        {
            int offset = ((*currentPtr & 0x3F) << 8); // get first number after C in the pointer
            currentPtr += 1;
            offset |= *currentPtr;           // add the next byte to the offset
            currentPtr = headerPtr + offset; // move the pointer to the offset
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

    Section::currentPtr += length;
    return domainName;
}

int Section::get_domain_length(const u_char *dnsPacket)
{
    const u_char *currentPtr = dnsPacket;
    int labelLen;
    int len = 0;

    while (*currentPtr != 0)
    {
        // check if the domain name is compressed
        if ((*currentPtr & 0xC0) == 0xC0)
            return len + 2;

        labelLen = *currentPtr;
        len += labelLen + 1;
        currentPtr += labelLen + 1;
    }

    return len + 1;
}