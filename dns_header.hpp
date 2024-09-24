#ifndef DNS_HEADER_HPP
#define DNS_HEADER_HPP

#include <string>
#include <unistd.h>
#include <iostream>

class DnsHeader {
public:
    DnsHeader() : id(0), flags(0), qdCount(0), anCount(0), nsCount(0), arCount(0) {}

    uint16_t id;
    uint16_t flags;
    uint16_t qdCount; //number of records in question section
    uint16_t anCount; //number of records in answer section
    uint16_t nsCount; //number of records in authority section
    uint16_t arCount; //number of records in additional section
};


#endif