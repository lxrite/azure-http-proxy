/*
 *    http_proxy_client_main.cpp:
 *
 *    Copyright (C) 2013-2023 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#include <experimental/net>
#include <iostream>

#include "http_proxy_client.hpp"
#include "http_proxy_client_config.hpp"

namespace net = std::experimental::net;

int main()
{
    using namespace azure_proxy;
    try {
        auto& config = http_proxy_client_config::get_instance();
        if (config.load_config()) {
            std::cout << "Azure Http Proxy Client" << std::endl;
            std::cout << "server address: " << config.get_proxy_server_address() << ':' << config.get_proxy_server_port() << std::endl;
            std::cout << "local address: " << config.get_bind_address() << ':' << config.get_listen_port() << std::endl;
            std::cout << "cipher: " << config.get_cipher() << std::endl;
            net::io_context io_ctx;
            http_proxy_client client(io_ctx);
            client.run();
        }
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
}
