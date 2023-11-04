/*
 *    http_proxy_server.hpp:
 *
 *    Copyright (C) 2013-2023 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#ifndef AZURE_HTTP_PROXY_SERVER_HPP
#define AZURE_HTTP_PROXY_SERVER_HPP

#include <experimental/net>

namespace net = std::experimental::net;

namespace azure_proxy {

    class http_proxy_server {
        net::io_context& io_ctx;
        net::ip::tcp::acceptor acceptor;
    public:
        http_proxy_server(net::io_context& io_ctx);
        void run();
    private:
        void start_accept();
    };

} // namespace azure_proxy

#endif
