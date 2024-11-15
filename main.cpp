/**
 * @file main.cpp
 * @brief Main file for the DNS monitor program.
 * @author Adam Pastierik
 * login: xpasti00
 */

#include "arg_parser.hpp"
#include "dns_monitor.hpp"
#include <csignal>

int main(int argc, char *argv[])
{
    ArgParser parser(argc, argv);
    DnsMonitor monitor;

    signal(SIGINT, DnsMonitor::handle_interrupt);
    signal(SIGQUIT, DnsMonitor::handle_interrupt);
    signal(SIGTERM, DnsMonitor::handle_interrupt);

    monitor.process_packets(parser);

    return 0;
}
