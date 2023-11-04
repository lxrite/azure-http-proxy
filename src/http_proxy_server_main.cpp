/*
 *    http_proxy_server_main.cpp:
 *
 *    Copyright (C) 2013-2023 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#include <experimental/net>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "http_proxy_server_config.hpp"
#include "http_proxy_server.hpp"
#include "version.hpp"

#ifdef _WIN32
#include <codecvt>
#include <shellapi.h>
#endif

namespace net = std::experimental::net;

struct ServerArgs {
    std::string config_file = "server.json";
};

void print_usage() {
#ifdef _WIN32
    const char *prog = "ahps.exe";
#else
    const char *prog = "ahps";
#endif
    std::cout << "Usage: " << prog << " [options]\n\n"
              << "options:\n"
              << "  -h, --help              Show this help message and exit\n"
              << "  -v, --version           Print the program version and exit\n"
              << "  -c, --config PATH       Configuration file path (default: server.json)\n";
}

static ServerArgs parse_args(const std::vector<std::string>& argv) {
    std::string arg;
    bool invalid_param = false;
    ServerArgs args;

    for (std::size_t i = 1; i < argv.size(); ++i) {
        arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage();
            std::exit(EXIT_SUCCESS);
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "Version: " << AHP_VERSION_STRING << std::endl;
            std::exit(EXIT_SUCCESS);
        } else if (arg == "-c" || arg == "--config") {
            if (++i >= argv.size()) {
                invalid_param = true;
                break;
            }
            args.config_file = argv[i];
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            print_usage();
            std::exit(EXIT_FAILURE);
        }
    }

    if (invalid_param) {
        std::cerr << "Invalid parameter for argument: " << arg << std::endl;
        std::exit(EXIT_FAILURE);
    }

    return args;
}

static ServerArgs parse_args(int argc, char** argv) {
    std::vector<std::string> argv_vec;
    argv_vec.reserve(argc);

#ifdef _WIN32
    LPWSTR *wargs = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (wargs == nullptr) {
        std::cerr << "Failed to retrieve command line arguments" << std::endl;
        std::exit(EXIT_FAILURE);
    }

    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    for (std::size_t i = 0; i < argc; ++i) {
        argv_vec.emplace_back(converter.to_bytes(wargs[i]));
    }

    LocalFree(wargs);
#else
    for (std::size_t i = 0; i < argc; ++i) {
        argv_vec.emplace_back(argv[i]);
    }
#endif

    return parse_args(argv_vec);
}

int main(int argc, char** argv)
{
    using namespace azure_proxy;
    auto args = parse_args(argc, argv);
    try {
        auto& config = http_proxy_server_config::get_instance();
        if (config.load_config(args.config_file)) {
            std::cout << "AHP server version " << AHP_VERSION_STRING << std::endl;
            std::cout << "bind address: " << config.get_bind_address() << ':' << config.get_listen_port() << std::endl;
            net::io_context io_ctx;
            http_proxy_server server(io_ctx);
            server.run();
        }
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    return 0;
}
