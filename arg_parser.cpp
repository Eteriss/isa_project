/**
 * @file arg_parser.cpp
 * @brief Implementation file for the argument parser class.
 * @author Adam Pastierik
 */

#include "arg_parser.hpp"

ArgParser::ArgParser(int argc, char *argv[])
{
    parse_args(argc, argv);
}

void ArgParser::parse_args(int argc, char *argv[])
{
    int opt;

    // process command line options using getopt
    while ((opt = getopt(argc, argv, "i:p:vd:t:")) != -1)
    {
        switch (opt)
        {
        case 'i':
            interface = optarg; // set the network interface
            break;
        case 'p':
            pcapfile = optarg; // set the PCAP file path
            break;
        case 'v':
            verbose = true; // enable verbose mode
            break;
        case 'd':
            domainsfile = optarg; // set the domains file path
            break;
        case 't':
            translationsfile = optarg; // set the translations file path
            break;
        default:
            exit(1); // exit with error if an invalid option is provided
        }
    }

    // ensure that either interface or pcapfile is provided, but not both
    if (interface.empty() && pcapfile.empty())
    {
        std::cerr << "Error: Either an interface (-i) or a pcap file (-p) must be provided.\n";
        exit(1);
    }
    else if (!interface.empty() && !pcapfile.empty())
    {
        std::cerr << "Error: Cannot provide both an interface (-i) and a pcap file (-p).\n";
        exit(1);
    }
}
