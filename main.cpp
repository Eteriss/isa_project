/**
 * @file main.cpp
 * @brief Main file for the DNS monitor program.
 * @author Adam Pastierik
 * login: xpasti00
 */

#include "arg_parser.hpp"
#include "dns_monitor.hpp"
#include <csignal>

bool verboseFlag = false;

void get_all_devices()
{
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *dev;

    if (pcap_findalldevs(&alldevs, errBuf) == -1)
    {
        fprintf(stderr, "Error finding devices: %s\n", errBuf);
        exit(1);
    }

    int i = 1;
    for (dev = alldevs; dev != NULL; dev = dev->next)
    {
        printf("%d. Device: %s\n", i, dev->name);
        i++;
    }

    pcap_freealldevs(alldevs);
}

int main(int argc, char *argv[])
{
    // get_all_devices();
    ArgParser parser(argc, argv);
    DnsMonitor monitor;

    signal(SIGINT, DnsMonitor::handle_interrupt);
    signal(SIGQUIT, DnsMonitor::handle_interrupt);
    signal(SIGTERM, DnsMonitor::handle_interrupt);

    monitor.process_packets(parser);

    return 0;
}
