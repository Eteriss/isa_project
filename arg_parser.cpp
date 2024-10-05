#include "arg_parser.hpp"

ArgParser::ArgParser(int argc, char *argv[])
{
    parse_args(argc, argv);
}

void ArgParser::parse_args(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "i:p:vd:t:")) != -1)
    {
        switch (opt)
        {
        case 'i':
            interface = optarg;
            break;
        case 'p':
            pcapfile = optarg;
            break;
        case 'v':
            verbose = true;
            break;
        case 'd':
            domainsfile = optarg;
            break;
        case 't':
            translationsfile = optarg;
            break;
        default:
            exit(1);
        }
    }

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
