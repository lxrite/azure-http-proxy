/*
 *    http_proxy_client_connection.hpp:
 *
 *    Copyright (C) 2013-2018 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_HTTP_PROXY_CLIENT_CONNECTION_HPP
#define AZURE_HTTP_PROXY_CLIENT_CONNECTION_HPP

#include <array>
#include <chrono>
#include <experimental/net>
#include <memory>
#include <vector>

#include "encrypt.hpp"

const std::size_t BUFFER_LENGTH = 2048;

namespace net = std::experimental::net;

namespace azure_proxy {

class http_proxy_client_connection : public std::enable_shared_from_this<http_proxy_client_connection> {
    enum class proxy_connection_state {
        ready,
        resolve_proxy_server_address,
        connecte_to_proxy_server,
        tunnel_transfer
    };
private:
    net::strand<net::io_context::executor_type> strand;
    net::ip::tcp::socket user_agent_socket;
    net::ip::tcp::socket proxy_server_socket;
    net::ip::tcp::resolver resolver;
    proxy_connection_state connection_state;
    net::basic_waitable_timer<std::chrono::steady_clock> timer;
    std::vector<unsigned char> encrypted_cipher_info;
    std::array<char, BUFFER_LENGTH> upgoing_buffer_read;
    std::array<char, BUFFER_LENGTH> upgoing_buffer_write;
    std::array<char, BUFFER_LENGTH> downgoing_buffer_read;
    std::array<char, BUFFER_LENGTH> downgoing_buffer_write;
    std::unique_ptr<stream_encryptor> encryptor;
    std::unique_ptr<stream_decryptor> decryptor;
    std::chrono::seconds timeout;
private:
    http_proxy_client_connection(net::io_context& io_ctx, net::ip::tcp::socket&& ua_socket);
public:
    ~http_proxy_client_connection();
    static std::shared_ptr<http_proxy_client_connection> create(net::io_context& io_ctx, net::ip::tcp::socket&& ua_socket);
    void start();
private:
    void async_read_data_from_user_agent();
    void async_read_data_from_proxy_server(bool set_timer = true);
    void async_write_data_to_user_agent(const char* write_buffer, std::size_t offset, std::size_t size);
    void async_write_data_to_proxy_server(const char* write_buffer, std::size_t offset, std::size_t size);

    void set_timer();
    bool cancel_timer();

    void on_connection_established();
    void on_error(const std::error_code& error);
    void on_timeout();
};

} // namespace azure_proxy

#endif
