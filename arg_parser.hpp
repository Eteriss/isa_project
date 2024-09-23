#ifndef ARG_PARSER_HPP
#define ARG_PARSER_HPP

#include <string>
#include <unistd.h>
#include <iostream>

class ArgParser {
public:
    ArgParser(int argc, char* argv[]);
    std::string interface;
    std::string pcapfile;
    std::string domainsfile;
    std::string translationsfile;
    bool verbose = false;
private:
    void parse_args(int argc, char* argv[]);
    
};

#endif