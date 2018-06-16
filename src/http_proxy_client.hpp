/*
 *    http_proxy_client.hpp:
 *
 *    Copyright (C) 2013-2018 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_HTTP_PROXY_CLIENT_HPP
#define AZURE_HTTP_PROXY_CLIENT_HPP

#include <experimental/net>

namespace net = std::experimental::net;

namespace azure_proxy {

class http_proxy_client {
    net::io_context& io_ctx;
    net::ip::tcp::acceptor acceptor;
public:
    http_proxy_client(net::io_context& io_ctx);
    void run();
private:
    void start_accept();
};

} // namespace azure_proxy

#endif
