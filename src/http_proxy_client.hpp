/*
 *    http_proxy_client.hpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_HTTP_PROXY_CLIENT_HPP
#define AZURE_HTTP_PROXY_CLIENT_HPP

#include <boost/asio.hpp>

namespace azure_proxy {

class http_proxy_client {
    boost::asio::io_service& io_service;
    boost::asio::ip::tcp::acceptor acceptor;
public:
    http_proxy_client(boost::asio::io_service& io_service);
    void run();
private:
    void start_accept();
};

} // namespace azure_proxy

#endif
