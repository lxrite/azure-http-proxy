/*
 *    http_proxy_client_main.cpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <iostream>

#include <boost/asio.hpp>

#include "http_proxy_client.hpp"
#include "http_proxy_client_stat.hpp"
#include "http_proxy_client_config.hpp"

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
            boost::asio::io_service io_service;
            http_proxy_client_stat::get_instance().start_stat(io_service);
            http_proxy_client client(io_service);
            client.run();
        }
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
}
