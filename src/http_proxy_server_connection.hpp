﻿/*
 *    http_proxy_server_connection.hpp:
 *
 *    Copyright (C) 2013-2023 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#ifndef AZURE_HTTP_PROXY_SERVER_CONNECTION_HPP
#define AZURE_HTTP_PROXY_SERVER_CONNECTION_HPP

#include <array>
#include <chrono>
#include <experimental/net>
#include <optional>

#include "encrypt.hpp"
#include "http_header_parser.hpp"
#include "http_proxy_server_connection_context.hpp"

namespace net = std::experimental::net;

namespace azure_proxy {

const std::size_t BUFFER_LENGTH = 2048;

class http_proxy_server_connection : public std::enable_shared_from_this<http_proxy_server_connection> {
    net::strand<net::io_context::executor_type> strand;
    net::ip::tcp::socket proxy_client_socket;
    net::ip::tcp::socket origin_server_socket;
    net::ip::tcp::resolver resolver;
    net::ip::tcp::resolver::results_type resolve_results;
    net::basic_waitable_timer<std::chrono::steady_clock> timer;
    std::array<char, BUFFER_LENGTH> upgoing_buffer_read;
    std::array<char, BUFFER_LENGTH> upgoing_buffer_write;
    std::array<char, BUFFER_LENGTH> downgoing_buffer_read;
    std::array<char, BUFFER_LENGTH> downgoing_buffer_write;
    rsa rsa_pri;
    std::vector<unsigned char> encrypted_cipher_info;
    std::unique_ptr<stream_encryptor> encryptor;
    std::unique_ptr<stream_decryptor> decryptor;
    std::string request_data;
    std::string modified_request_data;
    std::string response_data;
    std::string modified_response_data;
    std::optional<http_request_header> request_header;
    std::optional<http_response_header> response_header;
    http_proxy_server_connection_context connection_context;
    http_proxy_server_connection_read_request_context read_request_context;
    http_proxy_server_connection_read_response_context read_response_context;
private:
    http_proxy_server_connection(net::io_context& io_ctx, net::ip::tcp::socket&& proxy_client_socket);
public:
    ~http_proxy_server_connection();
    static std::shared_ptr<http_proxy_server_connection> create(net::io_context& io_ctx, net::ip::tcp::socket&& client_socket);
    void start();
private:
    void async_read_data_from_proxy_client(std::size_t at_least_size = 1, std::size_t at_most_size = BUFFER_LENGTH);
    void async_read_data_from_origin_server(bool set_timer = true, std::size_t at_least_size = 1, std::size_t at_most_size = BUFFER_LENGTH);
    void async_connect_to_origin_server();
    void async_write_request_header_to_origin_server();
    void async_write_response_header_to_proxy_client();
    void async_write_data_to_origin_server(const char* write_buffer, std::size_t offset, std::size_t size);
    void async_write_data_to_proxy_client(const char* write_buffer, std::size_t offset, std::size_t size);
    void start_tunnel_transfer();
    void report_error(const std::string& status_code, const std::string& status_description, const std::string& error_message);
    void report_authentication_failed();

    void set_timer();
    bool cancel_timer();

    void on_resolved(net::ip::tcp::resolver::results_type::const_iterator endpoint_iterator);
    void on_connect();
    void on_proxy_client_data_arrived(std::size_t bytes_transferred);
    void on_origin_server_data_arrived(std::size_t bytes_transferred);
    void on_proxy_client_data_written();
    void on_origin_server_data_written();
    void on_error(const std::error_code& error);
    void on_timeout();
};

} // namespace azure_proxy

#endif
