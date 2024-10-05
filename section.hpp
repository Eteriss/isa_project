#ifndef SECTION_HPP
#define SECTION_HPP

#include <string>
#include <unistd.h>
#include <iostream>
#include <utility>

class Section
{
public:
    Section(const u_char *dnsPacket, const u_char *headerPtr);

    uint16_t type;
    uint16_t dnsClass;
    uint32_t ttl;
    uint16_t dataLen;
    std::string domain;
    const u_char *currentPtr;

    std::pair<std::string, int> parse_domain(const u_char *dnsPacket, const u_char *headerPtr);

private:
    int get_domain_length(const u_char *dnsPacket);
};

#endif