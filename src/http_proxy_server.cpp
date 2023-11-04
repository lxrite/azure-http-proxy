/*
 *    http_proxy_server.cpp:
 *
 *    Copyright (C) 2013-2023 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#include <iostream>
#include <memory>
#include <thread>
#include <vector>

#include "http_proxy_server.hpp"
#include "http_proxy_server_config.hpp"
#include "http_proxy_server_connection.hpp"

namespace azure_proxy {

http_proxy_server::http_proxy_server(net::io_context& io_ctx) :
    io_ctx(io_ctx),
    acceptor(io_ctx)
{
}

void http_proxy_server::run()
{
    const auto& config = http_proxy_server_config::get_instance();
    net::ip::tcp::endpoint endpoint(net::ip::make_address(config.get_bind_address()), config.get_listen_port());
    this->acceptor.open(endpoint.protocol());
#ifndef _WIN32
    this->acceptor.set_option(net::ip::tcp::acceptor::reuse_address(true));
#endif
    this->acceptor.bind(endpoint);
    this->acceptor.listen(net::socket_base::max_listen_connections);
    this->start_accept();

    std::vector<std::thread> td_vec;

    for (auto i = 0u; i < config.get_workers(); ++i) {
        td_vec.emplace_back([this]() {
            try {
                this->io_ctx.run();
            }
            catch (const std::exception& e) {
                std::cerr << e.what() << std::endl;
            }
        });
    }

    for (auto& td : td_vec) {
        td.join();
    }
}

void http_proxy_server::start_accept()
{
    this->acceptor.async_accept([this](const std::error_code& error, net::ip::tcp::socket socket) {
        if (!error) {
            auto connection = http_proxy_server_connection::create(this->io_ctx, std::move(socket));
            connection->start();
        }
        this->start_accept();
    });
}

} //namespace azure_proxy
