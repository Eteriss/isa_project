/**
 * @file arg_parser.hpp
 * @brief Header file for the argument parser class.
 * @author Adam Pastierik
 * login: xpasti00
 *
 * This file contains the declaration of the argument parser class.
 * The class is used to parse command line arguments and set the appropriate fields.
 */

#ifndef ARG_PARSER_HPP
#define ARG_PARSER_HPP

#include <string>
#include <unistd.h>
#include <iostream>
#include <sys/types.h>

/**
 * @brief Argument parser class for processing command line arguments.
 */
class ArgParser
{
public:
    /**
     * @brief Constructs the argument parser and processes the command line arguments.
     *
     * @param argc Number of arguments.
     * @param argv Array of argument strings.
     */
    ArgParser(int argc, char *argv[]);

    std::string interface;        // Network interface to capture from.
    std::string pcapfile;         // PCAP file to read packets from.
    std::string domainsfile;      // File containing domain names to be translated.
    std::string translationsfile; // File to store domain name translations.
    bool verbose = false;         // Enable verbose output if true.

private:
    /**
     * @brief Parses the command line arguments.
     *
     * This function processes the provided arguments and sets the appropriate fields.
     *
     * @param argc Number of arguments.
     * @param argv Array of argument strings.
     */
    void parse_args(int argc, char *argv[]);
};

#endif
