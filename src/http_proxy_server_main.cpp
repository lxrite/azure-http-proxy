/*
 *    http_proxy_server_main.cpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <iostream>

#include "http_proxy_server_config.hpp"
#include "http_proxy_server.hpp"

int main()
{
    using namespace azure_proxy;
    try {
        auto& config = http_proxy_server_config::get_instance();
        if (config.load_config()) {
            std::cout << "Azure Http Proxy Server" << std::endl;
            std::cout << "bind address: " << config.get_bind_address() << ':' << config.get_listen_port() << std::endl;
            boost::asio::io_service io_service;
            http_proxy_server server(io_service);
            server.run();
        }
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    return 0;
}
