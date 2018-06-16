/*
 *    http_proxy_server_main.cpp:
 *
 *    Copyright (C) 2013-2018 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <experimental/net>
#include <iostream>

#include "http_proxy_server_config.hpp"
#include "http_proxy_server.hpp"

namespace net = std::experimental::net;

int main()
{
    using namespace azure_proxy;
    try {
        auto& config = http_proxy_server_config::get_instance();
        if (config.load_config()) {
            std::cout << "Azure Http Proxy Server" << std::endl;
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
