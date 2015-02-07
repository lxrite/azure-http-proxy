/*
 *    http_proxy_client_connection.cpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <algorithm>
#include <cstring>
#include <utility>
#include <vector>

extern "C" {
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/md5.h>
}

#include "http_proxy_client_config.hpp"
#include "http_proxy_client_connection.hpp"
#include "http_proxy_client_stat.hpp"
#include "key_generator.hpp"

namespace azure_proxy {

http_proxy_client_connection::http_proxy_client_connection(boost::asio::ip::tcp::socket&& ua_socket) :
    strand(ua_socket.get_io_service()),
    user_agent_socket(std::move(ua_socket)),
    proxy_server_socket(this->user_agent_socket.get_io_service()),
    resolver(this->user_agent_socket.get_io_service()),
    connection_state(proxy_connection_state::ready),
    timer(this->user_agent_socket.get_io_service()),
    timeout(std::chrono::seconds(http_proxy_client_config::get_instance().get_timeout()))
{
    http_proxy_client_stat::get_instance().increase_current_connections();
}

http_proxy_client_connection::~http_proxy_client_connection()
{
    http_proxy_client_stat::get_instance().decrease_current_connections();
}

std::shared_ptr<http_proxy_client_connection> http_proxy_client_connection::create(boost::asio::ip::tcp::socket&& ua_socket)
{
    return std::shared_ptr<http_proxy_client_connection>(new http_proxy_client_connection(std::move(ua_socket)));
}

void http_proxy_client_connection::start()
{
    auto self(this->shared_from_this());
    boost::asio::ip::tcp::resolver::query query(http_proxy_client_config::get_instance().get_proxy_server_address(), std::to_string(http_proxy_client_config::get_instance().get_proxy_server_port()));
    this->connection_state = proxy_connection_state::resolve_proxy_server_address;
    this->set_timer();
    this->resolver.async_resolve(query, [this, self](const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator iterator) {
        if (this->cancel_timer()) {
            if (!error) {
                this->connection_state = proxy_connection_state::connecte_to_proxy_server;
                this->set_timer();
                this->proxy_server_socket.async_connect(*iterator, this->strand.wrap([this, self](const boost::system::error_code& error) {
                    if (this->cancel_timer()) {
                        if (!error) {
                            this->on_connection_established();
                        }
                        else {
                            this->on_error(error);
                        }
                    }
                }));
            }
            else {
                this->on_error(error);
            }
        }
    });
}

void http_proxy_client_connection::async_read_data_from_user_agent()
{
    auto self(this->shared_from_this());
    this->set_timer();
    this->user_agent_socket.async_read_some(boost::asio::buffer(this->upgoing_buffer_read), this->strand.wrap([this, self](const boost::system::error_code& error, std::size_t bytes_transferred) {
        if (this->cancel_timer()) {
            if (!error) {
                http_proxy_client_stat::get_instance().on_upgoing_recv(static_cast<std::uint32_t>(bytes_transferred));
                this->encryptor->encrypt(reinterpret_cast<const unsigned char*>(&this->upgoing_buffer_read[0]), reinterpret_cast<unsigned char*>(&this->upgoing_buffer_write[0]), bytes_transferred);
                this->async_write_data_to_proxy_server(0, bytes_transferred);
            }
            else {
                this->on_error(error);
            }
        }
    }));
}

void http_proxy_client_connection::async_read_data_from_proxy_server(bool set_timer)
{
    auto self(this->shared_from_this());
    if (set_timer) {
        this->set_timer();
    }
    this->proxy_server_socket.async_read_some(boost::asio::buffer(this->downgoing_buffer_read), this->strand.wrap([this, self](const boost::system::error_code& error, std::size_t bytes_transferred) {
        if (this->cancel_timer()) {
            if (!error) {
                http_proxy_client_stat::get_instance().on_downgoing_recv(static_cast<std::uint32_t>(bytes_transferred));
                this->decryptor->decrypt(reinterpret_cast<const unsigned char*>(&this->downgoing_buffer_read[0]), reinterpret_cast<unsigned char*>(&this->downgoing_buffer_write[0]), bytes_transferred);
                this->async_write_data_to_user_agent(0, bytes_transferred);
            }
            else {
                this->on_error(error);
            }
        }
    }));
}

void http_proxy_client_connection::async_write_data_to_user_agent(std::size_t offset, std::size_t size)
{
    auto self(this->shared_from_this());
    this->set_timer();
    this->user_agent_socket.async_write_some(boost::asio::buffer(&this->downgoing_buffer_write[offset], size), this->strand.wrap([this, self, offset, size](const boost::system::error_code& error, std::size_t bytes_transferred) {
        if (this->cancel_timer()) {
            if (!error) {
                http_proxy_client_stat::get_instance().on_downgoing_send(static_cast<std::uint32_t>(bytes_transferred));
                if (bytes_transferred < size) {
                    this->async_write_data_to_user_agent(offset + bytes_transferred, size - bytes_transferred);
                }
                else {
                    this->async_read_data_from_proxy_server();
                }
            }
            else {
                this->on_error(error);
            }
        }
    }));
}

void http_proxy_client_connection::async_write_data_to_proxy_server(std::size_t offset, std::size_t size)
{
    auto self(this->shared_from_this());
    this->set_timer();
    this->proxy_server_socket.async_write_some(boost::asio::buffer(&this->upgoing_buffer_write[offset], size), this->strand.wrap([this, self, offset, size](const boost::system::error_code& error, std::size_t bytes_transferred) {
        if (this->cancel_timer()) {
            if (!error) {
                http_proxy_client_stat::get_instance().on_upgoing_send(static_cast<std::uint32_t>(bytes_transferred));
                if (bytes_transferred < size) {
                    this->async_write_data_to_proxy_server(offset + bytes_transferred, size - bytes_transferred);
                }
                else {
                    this->async_read_data_from_user_agent();
                }
            }
            else {
                if (error != boost::asio::error::eof) {
                }
                this->on_error(error);
            }
        }
    }));
}

void http_proxy_client_connection::set_timer()
{
    if (this->timer.expires_from_now(this->timeout) != 0) {
        assert(false);
    }
    auto self(this->shared_from_this());
    this->timer.async_wait(this->strand.wrap([this, self](const boost::system::error_code& error) {
        if (error != boost::asio::error::operation_aborted) {
            this->on_timeout();
        }
    }));
}

bool http_proxy_client_connection::cancel_timer()
{
    std::size_t ret = this->timer.cancel();
    assert(ret <= 1);
    return ret == 1;
}

void http_proxy_client_connection::on_connection_established()
{
    std::memset(&this->upgoing_buffer_read[0], 0, 256);
    // 1 ~ 3
    this->upgoing_buffer_read[0] = 'A';
    this->upgoing_buffer_read[1] = 'H';
    this->upgoing_buffer_read[2] = 'P';

    // 3 zero
    // 4 zero

    // 5 cipher code
    // 0x00 aes-128-cfb
    // 0x01 aes-128-cfb8
    // 0x02 aes-128-cfb1
    // 0x03 aes-128-ofb
    // 0x04 aes-128-ctr
    // 0x05 aes-192-cfb
    // 0x06 aes-192-cfb8
    // 0x07 aes-192-cfb1
    // 0x08 aes-192-ofb
    // 0x09 aes-192-ctr
    // 0x0A aes-256-cfb
    // 0x0B aes-256-cfb8
    // 0x0C aes-256-cfb1
    // 0x0D aes-256-ofb
    // 0x0E aes-256-ctr
   
    unsigned char cipher_code = 0;
    const auto& cipher_name = http_proxy_client_config::get_instance().get_cipher();
    if (cipher_name.size() > 7 && std::equal(cipher_name.begin(), cipher_name.begin() + 3, "aes")) {
        // aes
        std::vector<unsigned char> ivec(16);
        std::vector<unsigned char> key_vec;
        assert(cipher_name[3] == '-' && cipher_name[7] == '-');
        if (std::strcmp(cipher_name.c_str() + 8, "cfb") == 0 || std::strcmp(cipher_name.c_str() + 8, "cfb128") == 0) {
            // aes-xxx-cfb
            if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128")) {
                cipher_code = 0x00;
                key_vec.resize(128 / 8);
            }
            else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192")) {
                cipher_code = 0x05;
                key_vec.resize(192 / 8);
            }
            else {
                cipher_code = 0x0A;
                key_vec.resize(256 / 8);
            }
            key_generator::get_instance().generate(ivec.data(), ivec.size());
            key_generator::get_instance().generate(key_vec.data(), key_vec.size());
            this->encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb128_encryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
            this->decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb128_decryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
        }
        else if (std::strcmp(cipher_name.c_str() + 8, "cfb8") == 0) {
            // aes-xxx-cfb8
            if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128")) {
                cipher_code = 0x01;
                key_vec.resize(128 / 8);
            }
            else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192")) {
                cipher_code = 0x06;
                key_vec.resize(192 / 8);
            }
            else {
                cipher_code = 0x0B;
                key_vec.resize(256 / 8);
            }
            key_generator::get_instance().generate(ivec.data(), ivec.size());
            key_generator::get_instance().generate(key_vec.data(), key_vec.size());
            this->encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb8_encryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
            this->decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb8_decryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
        }
        else if (std::strcmp(cipher_name.c_str() + 8, "cfb1") == 0) {
            // aes-xxx-cfb1
            if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128")) {
                cipher_code = 0x02;
                key_vec.resize(128 / 8);
            }
            else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192")) {
                cipher_code = 0x07;
                key_vec.resize(192 / 8);
            }
            else {
                cipher_code = 0x0C;
                key_vec.resize(256 / 8);
            }
            key_generator::get_instance().generate(ivec.data(), ivec.size());
            key_generator::get_instance().generate(key_vec.data(), key_vec.size());
            this->encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb1_encryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
            this->decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb1_decryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
        }
        else if (std::strcmp(cipher_name.c_str() + 8, "ofb")) {
            // aes-xxx-ofb
            if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128")) {
                cipher_code = 0x03;
                key_vec.resize(128 / 8);
            }
            else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192")) {
                cipher_code = 0x08;
                key_vec.resize(192 / 8);
            }
            else {
                cipher_code = 0x0D;
                key_vec.resize(256 / 8);
            }
            key_generator::get_instance().generate(ivec.data(), ivec.size());
            key_generator::get_instance().generate(key_vec.data(), key_vec.size());
            this->encryptor = std::unique_ptr<stream_encryptor>(new aes_ofb128_encryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
            this->decryptor = std::unique_ptr<stream_decryptor>(new aes_ofb128_decryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
        }
        else if (std::strcmp(cipher_name.c_str() + 8, "ctr")) {
            // aes-xxx-ctr
            if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128")) {
                cipher_code = 0x04;
                key_vec.resize(128 / 8);
            }
            else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192")) {
                cipher_code = 0x09;
                key_vec.resize(192 / 8);
            }
            else {
                cipher_code = 0x0E;
                key_vec.resize(256 / 8);
            }
            std::fill(ivec.begin(), ivec.end(), 0);
            key_generator::get_instance().generate(key_vec.data(), key_vec.size());
            this->encryptor = std::unique_ptr<stream_encryptor>(new aes_ctr128_encryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
            this->decryptor = std::unique_ptr<stream_decryptor>(new aes_ctr128_decryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
        }
        // 7 ~ 23 ivec
        std::copy(ivec.cbegin(), ivec.cend(), reinterpret_cast<unsigned char*>(&this->upgoing_buffer_read[7]));
        std::copy(key_vec.cbegin(), key_vec.cend(), reinterpret_cast<unsigned char*>(&this->upgoing_buffer_read[24]));
    }

    bool close = true;
    std::shared_ptr<bool> auto_close(&close, [this](bool* close) {
        if (*close) {
            boost::system::error_code ec;
            if (this->proxy_server_socket.is_open()) {
                this->proxy_server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                this->proxy_server_socket.close(ec);
            }
            if (this->user_agent_socket.is_open()) {
                this->user_agent_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                this->user_agent_socket.close(ec);
            }
        }
    });

    if (!this->encryptor || !this->decryptor) {
        return;
    }

    this->upgoing_buffer_read[5] = static_cast<char>(cipher_code); 
    // 6 zero

    // 240 ~ 255 md5 check sum
    if (NULL == MD5(reinterpret_cast<unsigned char*>(&this->upgoing_buffer_read[0]), 240, reinterpret_cast<unsigned char*>(&this->upgoing_buffer_read[240]))) {
        return;
    }

    std::string public_key = http_proxy_client_config::get_instance().get_rsa_2048_public_key();
    std::shared_ptr<BIO> bio_handle(BIO_new_mem_buf(const_cast<char*>(public_key.data()), public_key.size()), BIO_free);
    if (!bio_handle) {
        return;
    }
    std::shared_ptr<RSA> rsa_handle(PEM_read_bio_RSA_PUBKEY(bio_handle.get(), NULL, NULL, NULL), RSA_free);
    if (!rsa_handle || RSA_size(rsa_handle.get()) != 256) {
        return;
    }
    RSA_public_encrypt(256, reinterpret_cast<unsigned char*>(&this->upgoing_buffer_read[0]), reinterpret_cast<unsigned char*>(&this->upgoing_buffer_write[0]), rsa_handle.get(), RSA_NO_PADDING);
    close = false;

    this->async_write_data_to_proxy_server(0, 256);
    this->async_read_data_from_proxy_server(false);
}

void http_proxy_client_connection::on_error(const boost::system::error_code& error)
{
    this->cancel_timer();
    boost::system::error_code ec;
    if (this->proxy_server_socket.is_open()) {
        this->proxy_server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        this->proxy_server_socket.close(ec);
    }
    if (this->user_agent_socket.is_open()) {
        this->user_agent_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        this->user_agent_socket.close(ec);
    }
}

void http_proxy_client_connection::on_timeout()
{
    if (this->connection_state == proxy_connection_state::resolve_proxy_server_address) {
        this->resolver.cancel();
    }
    else {
        boost::system::error_code ec;
        if (this->proxy_server_socket.is_open()) {
            this->proxy_server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            this->proxy_server_socket.close(ec);
        }
        if (this->user_agent_socket.is_open()) {
            this->user_agent_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            this->user_agent_socket.close(ec);
        }
    }
}

} // namespace azure_proxy
