/*
 *    http_proxy_server_connection.cpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <cctype>
#include <algorithm>
#include <cassert>
#include <cstring>

#include "authentication.hpp"
#include "http_proxy_server_config.hpp"
#include "http_proxy_server_connection.hpp"

static const std::size_t MAX_REQUEST_HEADER_LENGTH = 10240;
static const std::size_t MAX_RESPONSE_HEADER_LENGTH = 10240;

namespace azure_proxy {

http_proxy_server_connection::http_proxy_server_connection(boost::asio::ip::tcp::socket&& proxy_client_socket) :
    strand(proxy_client_socket.get_io_service()),
    proxy_client_socket(std::move(proxy_client_socket)),
    origin_server_socket(this->proxy_client_socket.get_io_service()),
    resolver(this->proxy_client_socket.get_io_service()),
    timer(this->proxy_client_socket.get_io_service()),
    rsa_pri(http_proxy_server_config::get_instance().get_rsa_private_key())
{
    this->connection_context.connection_state = proxy_connection_state::read_cipher_data;
}

http_proxy_server_connection::~http_proxy_server_connection()
{
}

std::shared_ptr<http_proxy_server_connection> http_proxy_server_connection::create(boost::asio::ip::tcp::socket&& client_socket)
{
    return std::shared_ptr<http_proxy_server_connection>(new http_proxy_server_connection(std::move(client_socket)));
}

void http_proxy_server_connection::start()
{
    this->connection_context.connection_state = proxy_connection_state::read_cipher_data;
    this->async_read_data_from_proxy_client(1, std::min<std::size_t>(this->rsa_pri.modulus_size(), BUFFER_LENGTH));
}

void http_proxy_server_connection::async_read_data_from_proxy_client(std::size_t at_least_size, std::size_t at_most_size)
{
    assert(at_least_size <= at_most_size && at_most_size <= BUFFER_LENGTH);
    auto self(this->shared_from_this());
    this->set_timer();
    boost::asio::async_read(this->proxy_client_socket,
        boost::asio::buffer(&this->upgoing_buffer_read[0], at_most_size),
        boost::asio::transfer_at_least(at_least_size),
        this->strand.wrap([this, self](const boost::system::error_code& error, std::size_t bytes_transferred) {
            if (this->cancel_timer()) {
                if (!error) {
                    this->on_proxy_client_data_arrived(bytes_transferred);
                }
                else {
                    this->on_error(error);
                }
            }
        })
    );
}

void http_proxy_server_connection::async_read_data_from_origin_server(bool set_timer, std::size_t at_least_size, std::size_t at_most_size)
{
    auto self(this->shared_from_this());
    if (set_timer) {
        this->set_timer();
    }
    boost::asio::async_read(this->origin_server_socket,
        boost::asio::buffer(&this->downgoing_buffer_read[0], at_most_size),
        boost::asio::transfer_at_least(at_least_size),
        this->strand.wrap([this, self](const boost::system::error_code& error, std::size_t bytes_transferred) {
            if (this->cancel_timer()) {
                if (!error) {
                    this->on_origin_server_data_arrived(bytes_transferred);
                }
                else {
                    this->on_error(error);
                }
            }
        })
    );
}

void http_proxy_server_connection::async_connect_to_origin_server()
{
    this->connection_context.reconnect_on_error = false;
    if (this->origin_server_socket.is_open()) {
        if (this->request_header->method() == "CONNECT") {
            boost::system::error_code ec;
            this->origin_server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            this->origin_server_socket.close(ec);
        }
    }

    if (this->origin_server_socket.is_open() &&
        this->request_header->host() == this->connection_context.origin_server_name &&
        this->request_header->port() == this->connection_context.origin_server_port) {
        this->connection_context.reconnect_on_error = true;
        this->on_connect();
    }
    else {
        this->connection_context.origin_server_name = this->request_header->host();
        this->connection_context.origin_server_port = this->request_header->port();
        boost::asio::ip::tcp::resolver::query query(this->request_header->host(), std::to_string(this->request_header->port()));
        auto self(this->shared_from_this());
        this->connection_context.connection_state = proxy_connection_state::resolve_origin_server_address;
        this->set_timer();
        this->resolver.async_resolve(query,
            this->strand.wrap([this, self](const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator iterator) {
                if (this->cancel_timer()) {
                    if (!error) {
                        this->on_resolved(iterator);
                    }
                    else {
                        this->on_error(error);
                    }
                }
            })
        );
    }
}

void http_proxy_server_connection::async_write_request_header_to_origin_server()
{
    auto request_content_begin = this->request_data.begin() + this->request_data.find("\r\n\r\n") + 4;
    this->modified_request_data = this->request_header->method();
    this->modified_request_data.push_back(' ');
    this->modified_request_data += this->request_header->path_and_query();
    this->modified_request_data += " HTTP/";
    this->modified_request_data += this->request_header->http_version();
    this->modified_request_data += "\r\n"; 

    this->request_header->erase_header("Proxy-Connection");
    this->request_header->erase_header("Proxy-Authorization");

    for (const auto& header: this->request_header->get_headers_map()) {
        this->modified_request_data += std::get<0>(header);
        this->modified_request_data += ": ";
        this->modified_request_data += std::get<1>(header);
        this->modified_request_data += "\r\n";
    }
    this->modified_request_data += "\r\n";
    this->modified_request_data.append(request_content_begin, this->request_data.end());
    this->connection_context.connection_state = proxy_connection_state::write_http_request_header;
    this->async_write_data_to_origin_server(this->modified_request_data.data(), 0, this->modified_request_data.size());
}

void http_proxy_server_connection::async_write_response_header_to_proxy_client()
{
    auto response_content_begin = this->response_data.begin() + this->response_data.find("\r\n\r\n") + 4;

    this->modified_response_data = "HTTP/";
    this->modified_response_data += this->response_header->http_version();
    this->modified_response_data.push_back(' ');
    this->modified_response_data += std::to_string(this->response_header->status_code());
    if (!this->response_header->status_description().empty()) {
        this->modified_response_data.push_back(' ');
        this->modified_response_data += this->response_header->status_description();
    }
    this->modified_response_data += "\r\n";

    for (const auto& header: this->response_header->get_headers_map()) {
        this->modified_response_data += std::get<0>(header);
        this->modified_response_data += ": ";
        this->modified_response_data += std::get<1>(header);
        this->modified_response_data += "\r\n";
    }
    this->modified_response_data += "\r\n";
    this->modified_response_data.append(response_content_begin, this->response_data.end());
    unsigned char temp_buffer[256];
    std::size_t blocks = this->modified_response_data.size() / 256;
    if (this->modified_response_data.size() % 256 != 0) {
        blocks += 1;
    }
    for (std::size_t i = 0; i < blocks; ++i) {
        std::size_t block_length = 256;
        if ((i + 1) * 256 > this->modified_response_data.size()) {
            block_length = this->modified_response_data.size() % 256;
        }
        std::copy(reinterpret_cast<const unsigned char*>(&this->modified_response_data[i * 256]), reinterpret_cast<const unsigned char*>(&this->modified_response_data[i * 256 + block_length]), temp_buffer);
        this->encryptor->encrypt(temp_buffer, reinterpret_cast<unsigned char*>(&this->modified_response_data[i * 256]), block_length);
    }
    this->connection_context.connection_state = proxy_connection_state::write_http_response_header;
    this->async_write_data_to_proxy_client(this->modified_response_data.data(), 0, this->modified_response_data.size());
}

void http_proxy_server_connection::async_write_data_to_origin_server(const char* write_buffer, std::size_t offset, std::size_t size)
{
    auto self(this->shared_from_this());
    this->set_timer();
    this->origin_server_socket.async_write_some(boost::asio::buffer(write_buffer + offset, size),
        this->strand.wrap([this, self, write_buffer, offset, size](const boost::system::error_code& error, std::size_t bytes_transferred) {
            if (this->cancel_timer()) {
                if (!error) { 
                    this->connection_context.reconnect_on_error = false;
                    if (bytes_transferred < size) {
                        this->async_write_data_to_origin_server(write_buffer, offset + bytes_transferred, size - bytes_transferred);
                    }
                    else {
                        this->on_origin_server_data_written();
                    }
                }
                else {
                    this->on_error(error);
                }
            }
        })
    );
}

void http_proxy_server_connection::async_write_data_to_proxy_client(const char* write_buffer, std::size_t offset, std::size_t size)
{
    auto self(this->shared_from_this());
    this->set_timer();
    this->proxy_client_socket.async_write_some(boost::asio::buffer(write_buffer + offset, size),
        this->strand.wrap([this, self, write_buffer, offset, size](const boost::system::error_code& error, std::size_t bytes_transferred) {
            if (this->cancel_timer()) {
                if (!error) {
                    if (bytes_transferred < size) {
                        this->async_write_data_to_proxy_client(write_buffer, offset + bytes_transferred, size - bytes_transferred);
                    }
                    else {
                        this->on_proxy_client_data_written();
                    }
                }
                else {
                    this->on_error(error);
                }
            }
        })
    );
}

void http_proxy_server_connection::start_tunnel_transfer()
{
    this->connection_context.connection_state = proxy_connection_state::tunnel_transfer;
    this->async_read_data_from_proxy_client();
    this->async_read_data_from_origin_server(false);
}

void http_proxy_server_connection::report_error(const std::string& status_code, const std::string& status_description, const std::string& error_message)
{
    this->modified_response_data.clear();
    this->modified_response_data += "HTTP/1.1 ";
    this->modified_response_data += status_code;
    if (!status_description.empty()) {
        this->modified_response_data.push_back(' ');
        this->modified_response_data += status_description;
    }
    this->modified_response_data += "\r\n";
    this->modified_response_data += "Content-Type: text/html\r\n";
    this->modified_response_data += "Server: AzureHttpProxy\r\n";
    this->modified_response_data += "Content-Length: ";

    std::string response_content;
    response_content = "<!DOCTYPE html><html><head><title>";
    response_content += status_code;
    response_content += ' ';
    response_content += status_description;
    response_content += "</title></head><body bgcolor=\"white\"><center><h1>";
    response_content += status_code;
    response_content += ' ';
    response_content += status_description;
    response_content += "</h1>";
    if (!error_message.empty()) {
        response_content += "<br/>";
        response_content += error_message;
        response_content += "</center>";
    }
    response_content += "<hr><center>";
    response_content += "azure http proxy server";
    response_content += "</center></body></html>";
    this->modified_response_data += std::to_string(response_content.size());
    this->modified_response_data += "\r\n";
    this->modified_response_data += "Proxy-Connection: close\r\n";
    this->modified_response_data += "\r\n";
    if (!this->request_header || this->request_header->method() != "HEAD") {
        this->modified_response_data += response_content;
    }
    
    unsigned char temp_buffer[16];
    for (std::size_t i = 0; i * 16 < this->modified_response_data.size(); ++i) {
        std::size_t block_length = 16;
        if (this->modified_response_data.size() - i * 16 < 16) {
            block_length = this->modified_response_data.size() % 16;
        }
        this->encryptor->encrypt(reinterpret_cast<const unsigned char*>(&this->modified_response_data[i * 16]), temp_buffer, block_length);
        std::copy(temp_buffer, temp_buffer + block_length, reinterpret_cast<unsigned char*>(&this->modified_response_data[i * 16]));
    }
    this->connection_context.connection_state = proxy_connection_state::report_error;
    auto self(this->shared_from_this());
    this->async_write_data_to_proxy_client(this->modified_response_data.data(), 0 ,this->modified_response_data.size());
}

void http_proxy_server_connection::report_authentication_failed()
{
    std::string content = "<!DOCTYPE html><html><head><title>407 Proxy Authentication Required</title></head>";
    content += "<body bgcolor=\"white\"><center><h1>407 Proxy Authentication Required</h1></center><hr><center>azure http proxy server</center></body></html>";
    this->modified_response_data = "HTTP/1.1 407 Proxy Authentication Required\r\n";
    this->modified_response_data += "Server: AzureHttpProxy\r\n";
    this->modified_response_data += "Proxy-Authenticate: Basic realm=\"AzureHttpProxy\"\r\n";
    this->modified_response_data += "Content-Type: text/html\r\n";
    this->modified_response_data += "Connection: Close\r\n";
    this->modified_response_data += "Content-Length: ";
    this->modified_response_data += std::to_string(content.size());
    this->modified_response_data += "\r\n\r\n";
    this->modified_response_data += content;
    unsigned char temp_buffer[16];
    for (std::size_t i = 0; i * 16 < this->modified_response_data.size(); ++i) {
        std::size_t block_length = 16;
        if (this->modified_response_data.size() - i * 16 < 16) {
            block_length = this->modified_response_data.size() % 16;
        }
        this->encryptor->encrypt(reinterpret_cast<const unsigned char*>(&this->modified_response_data[i * 16]), temp_buffer, block_length);
        std::copy(temp_buffer, temp_buffer + block_length, reinterpret_cast<unsigned char*>(&this->modified_response_data[i * 16]));
    }
    this->connection_context.connection_state = proxy_connection_state::report_error;
    this->async_write_data_to_proxy_client(this->modified_response_data.data(), 0, this->modified_response_data.size());
}

void http_proxy_server_connection::set_timer()
{
    if (this->timer.expires_from_now(std::chrono::seconds(http_proxy_server_config::get_instance().get_timeout())) != 0) {
        assert(false);
    }
    auto self(this->shared_from_this());
    this->timer.async_wait(this->strand.wrap([this, self](const boost::system::error_code& error) {
        if (error != boost::asio::error::operation_aborted) {
            this->on_timeout();
        }
    }));
}

bool http_proxy_server_connection::cancel_timer()
{
    std::size_t ret = this->timer.cancel();
    assert(ret <= 1);
    return ret == 1;
}

void http_proxy_server_connection::on_resolved(boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
{
    if (this->origin_server_socket.is_open()) {
        for (auto iter = endpoint_iterator; iter != boost::asio::ip::tcp::resolver::iterator(); ++iter) {
            if (this->connection_context.origin_server_endpoint == iter->endpoint()) {
                this->connection_context.reconnect_on_error = true;
                this->on_connect();
                return;
            }
            boost::system::error_code ec;
            this->origin_server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            this->origin_server_socket.close(ec);
        }
    }
    this->connection_context.origin_server_endpoint = endpoint_iterator->endpoint();
    auto self(this->shared_from_this());
    this->connection_context.connection_state = proxy_connection_state::connect_to_origin_server;
    this->set_timer();
    this->origin_server_socket.async_connect(endpoint_iterator->endpoint(),
        this->strand.wrap([this, self, endpoint_iterator](const boost::system::error_code& error) mutable {
            if (this->cancel_timer()) {
                if (!error) {
                    this->on_connect();
                }
                else {
                    boost::system::error_code ec;
                    this->origin_server_socket.close(ec);
                    if (++endpoint_iterator != boost::asio::ip::tcp::resolver::iterator()) {
                        this->on_resolved(endpoint_iterator);
                    }
                    else {
                        this->on_error(error);
                    }
                }
            }
        })
    );
}

void http_proxy_server_connection::on_connect()
{
    if (this->request_header->method() == "CONNECT") {
        const unsigned char response_message[] = "HTTP/1.1 200 Connection Established\r\nConnection: Close\r\n\r\n";
        this->modified_response_data.resize(sizeof(response_message) - 1);
        this->encryptor->encrypt(response_message, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(&this->modified_response_data[0])), this->modified_response_data.size());
        this->connection_context.connection_state = proxy_connection_state::report_connection_established;
        this->async_write_data_to_proxy_client(&this->modified_response_data[0], 0, this->modified_response_data.size());
    }
    else {
        this->async_write_request_header_to_origin_server();
    }
}

void http_proxy_server_connection::on_proxy_client_data_arrived(std::size_t bytes_transferred)
{
    if (this->connection_context.connection_state == proxy_connection_state::read_cipher_data) {
        std::copy(this->upgoing_buffer_read.begin(), this->upgoing_buffer_read.begin() + bytes_transferred, std::back_inserter(this->encrypted_cipher_info));
        if (this->encrypted_cipher_info.size() < this->rsa_pri.modulus_size()) {
            this->async_read_data_from_proxy_client(1, std::min(static_cast<std::size_t>(this->rsa_pri.modulus_size()) - this->encrypted_cipher_info.size(), BUFFER_LENGTH));
            return;
        }
        assert(this->encrypted_cipher_info.size() == this->rsa_pri.modulus_size());
        std::vector<unsigned char> decrypted_cipher_info(this->rsa_pri.modulus_size());

        if (86 != this->rsa_pri.decrypt(this->rsa_pri.modulus_size(), this->encrypted_cipher_info.data(), decrypted_cipher_info.data(), rsa_padding::pkcs1_oaep_padding)) {
            return;
        }

        if (decrypted_cipher_info[0] != 'A' ||
            decrypted_cipher_info[1] != 'H' ||
            decrypted_cipher_info[2] != 'P' ||
            decrypted_cipher_info[3] != 0 ||
            decrypted_cipher_info[4] != 0 ||
            decrypted_cipher_info[6] != 0
            ) {
            return;
        }

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
        unsigned char cipher_code = decrypted_cipher_info[5];
        if (cipher_code == '\x00' || cipher_code == '\x05' || cipher_code == '\x0A') {
            // aes-xxx-cfb
            std::size_t ivec_size = 16;
            std::size_t key_bits = 256; // aes-256-cfb
            if (cipher_code == '\x00') {
                // aes-128-cfb
                key_bits = 128;
            }
            else if (cipher_code == '\x05') {
                // aes-192-cfb
                key_bits = 192;
            }
            this->encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb128_encryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
            this->decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb128_decryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
        }
        else if (cipher_code == '\x01' || cipher_code == '\x06' || cipher_code == '\x0B') {
            // ase-xxx-cfb8
            std::size_t ivec_size = 16;
            std::size_t key_bits = 256; // aes-256-cfb8
            if (cipher_code == '\x01') {
                // aes-128-cfb8
                key_bits = 128;
            }
            else if (cipher_code == '\x06') {
                // aes-192-cfb8
                key_bits = 192;
            }
            this->encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb8_encryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
            this->decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb8_decryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
        }
        else if (cipher_code == '\x02' || cipher_code == '\x07' || cipher_code == '\x0C') {
            // ase-xxx-cfb1
            std::size_t ivec_size = 16;
            std::size_t key_bits = 256; // aes-256-cfb1
            if (cipher_code == '\x02') {
                // aes-128-cfb1
                key_bits = 128;
            }
            else if (cipher_code == '\x07') {
                // aes-192-cfb1
                key_bits = 192;
            }
            this->encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb1_encryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
            this->decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb1_decryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
        }
        else if (cipher_code == '\x03' || cipher_code == '\x08' || cipher_code == '\x0D') {
            // ase-xxx-ofb
            std::size_t ivec_size = 16;
            std::size_t key_bits = 256; // aes-256-ofb
            if (cipher_code == '\x03') {
                // aes-128-ofb
                key_bits = 128;
            }
            else if (cipher_code == '\x08') {
                // aes-192-ofb
                key_bits = 192;
            }
            this->encryptor = std::unique_ptr<stream_encryptor>(new aes_ofb128_encryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
            this->decryptor = std::unique_ptr<stream_decryptor>(new aes_ofb128_decryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
        }
        else if (cipher_code == '\x04' || cipher_code == '\x09' || cipher_code == '\x0E') {
            // ase-xxx-ctr
            std::size_t ivec_size = 16;
            std::size_t key_bits = 256; // aes-256-ctr
            if (cipher_code == '\x04') {
                // aes-128-ctr
                key_bits = 128;
            }
            else if (cipher_code == '\x09') {
                // aes-192-ctr
                key_bits = 192;
            }
            std::vector<unsigned char> ivec(ivec_size, 0);
            this->encryptor = std::unique_ptr<stream_encryptor>(new aes_ctr128_encryptor(&decrypted_cipher_info[23], key_bits, ivec.data()));
            this->decryptor = std::unique_ptr<stream_decryptor>(new aes_ctr128_decryptor(&decrypted_cipher_info[23], key_bits, ivec.data()));
        }
        if (this->encryptor == nullptr || this->decryptor == nullptr) {
            return;
        }
        this->connection_context.connection_state = proxy_connection_state::read_http_request_header;
        this->async_read_data_from_proxy_client();
        return;
    }
    assert(this->encryptor != nullptr && this->decryptor != nullptr);
    this->decryptor->decrypt(reinterpret_cast<const unsigned char*>(&this->upgoing_buffer_read[0]), reinterpret_cast<unsigned char*>(&this->upgoing_buffer_write[0]), bytes_transferred);
    if (this->connection_context.connection_state == proxy_connection_state::read_http_request_header) {
        const auto& decripted_data_buffer = this->upgoing_buffer_write;
        this->request_data.append(decripted_data_buffer.begin(), decripted_data_buffer.begin() + bytes_transferred);
        auto double_crlf_pos = this->request_data.find("\r\n\r\n");
        if (double_crlf_pos == std::string::npos) {
            if (this->request_data.size() < MAX_REQUEST_HEADER_LENGTH) {
                this->async_read_data_from_proxy_client();
            }
            else {
                this->report_error("400", "Bad Request", "Request header too long");
            }
            return;
        }

        this->request_header = http_header_parser::parse_request_header(this->request_data.begin(), this->request_data.begin() + double_crlf_pos + 4);
        if (!this->request_header) {
            this->report_error("400", "Bad Request", "Failed to parse the http request header");
            return;
        }

        if (this->request_header->method() != "GET"
            // && this->request_header->method() != "OPTIONS"
            && this->request_header->method() != "HEAD"
            && this->request_header->method() != "POST"
            && this->request_header->method() != "PUT"
            && this->request_header->method() != "DELETE"
            // && this->request_header->method() != "TRACE"
            && this->request_header->method() != "CONNECT") {
            this->report_error("405", "Method Not Allowed", std::string());
            return;
        }
        if (this->request_header->http_version() != "1.1"
            && this->request_header->http_version() != "1.0") {
            this->report_error("505", "HTTP Version Not Supported", std::string());
            return;
        }

        if (http_proxy_server_config::get_instance().enable_auth()) {
            auto proxy_authorization_value = this->request_header->get_header_value("Proxy-Authorization");
            bool auth_success = false;
            if (proxy_authorization_value) {
                if (authentication::get_instance().auth(*proxy_authorization_value) == auth_result::ok) {
                    auth_success = true;
                }
            }
            if (!auth_success) {
                this->report_authentication_failed();
                return;
            }
        }

        if (this->request_header->method() == "CONNECT") {
            this->async_connect_to_origin_server();
            return;
        }
        else {
            if (this->request_header->scheme() != "http") {
                this->report_error("400", "Bad Request", "Unsupported scheme");
                return;
            }
            auto proxy_connection_value = this->request_header->get_header_value("Proxy-Connection");
            auto connection_value = this->request_header->get_header_value("Connection");
            auto string_to_lower_case = [](std::string& str) {
                for (auto iter = str.begin(); iter != str.end(); ++iter) {
                    *iter = std::tolower(static_cast<unsigned char>(*iter));
                }
            };
            if (proxy_connection_value) {
                string_to_lower_case(*proxy_connection_value);
                if (this->request_header->http_version() == "1.1") {
                    this->read_request_context.is_proxy_client_keep_alive = true;
                    if (*proxy_connection_value == "close") {
                        this->read_request_context.is_proxy_client_keep_alive = false;
                    }
                }
                else {
                    assert(this->request_header->http_version() == "1.0");
                    this->read_request_context.is_proxy_client_keep_alive = false;
                    if (*proxy_connection_value == "keep-alive") {
                        this->read_request_context.is_proxy_client_keep_alive = true;
                    }
                }
            }
            else {
                if (this->request_header->http_version() == "1.1") {
                    this->read_request_context.is_proxy_client_keep_alive = true;
                }
                else {
                    this->read_request_context.is_proxy_client_keep_alive = false;
                }
                if (connection_value) {
                    string_to_lower_case(*connection_value);
                    if (this->request_header->http_version() == "1.1" && *connection_value == "close") {
                        this->read_request_context.is_proxy_client_keep_alive = false;
                    }
                    else if (this->request_header->http_version() == "1.0" && *connection_value == "keep-alive") {
                        this->read_request_context.is_proxy_client_keep_alive = true;
                    }
                }
            }

            this->read_request_context.content_length = boost::optional<std::uint64_t>();
            this->read_request_context.content_length_has_read = 0;
            this->read_request_context.chunk_checker = boost::optional<http_chunk_checker>();

            if (this->request_header->method() == "GET" || this->request_header->method() == "HEAD" || this->request_header->method() == "DELETE") {
                this->read_request_context.content_length = boost::optional<std::uint64_t>(0);
            }
            else if (this->request_header->method() == "POST" || this->request_header->method() == "PUT") {
                auto content_length_value = this->request_header->get_header_value("Content-Length");
                auto transfer_encoding_value = this->request_header->get_header_value("Transfer-Encoding");
                if (content_length_value) {
                    try {
                        this->read_request_context.content_length = boost::optional<std::uint64_t>(std::stoull(*content_length_value));
                    }
                    catch (const std::exception&) {
                        this->report_error("400", "Bad Request", "Invalid Content-Length in request");
                        return;
                    }
                    this->read_request_context.content_length_has_read = this->request_data.size() - (double_crlf_pos + 4);
                }
                else if (transfer_encoding_value) {
                    string_to_lower_case(*transfer_encoding_value);
                    if (*transfer_encoding_value == "chunked") {
                        if (!this->read_request_context.chunk_checker->check(this->request_data.begin() + double_crlf_pos + 4, this->request_data.end())) {
                            this->report_error("400", "Bad Request", "Failed to check chunked response");
                            return;
                        }
                        return;
                    }
                    else {
                        this->report_error("400", "Bad Request", "Unsupported Transfer-Encoding");
                        return;
                    }
                }
                else {
                    this->report_error("411", "Length Required", std::string());
                    return;
                }
            }
            else {
                assert(false);
                return;
            }
        }
        this->async_connect_to_origin_server();
    }
    else if (this->connection_context.connection_state == proxy_connection_state::read_http_request_content) {
        if (this->read_request_context.content_length) {
            this->read_request_context.content_length_has_read += bytes_transferred;
        }
        else {
            assert(this->read_request_context.chunk_checker);
            if (!this->read_request_context.chunk_checker->check(this->upgoing_buffer_write.begin(), this->upgoing_buffer_write.begin() + bytes_transferred)) {
                return;
            }
        }
        this->connection_context.connection_state = proxy_connection_state::write_http_request_content;
        this->async_write_data_to_origin_server(this->upgoing_buffer_write.data(), 0, this->upgoing_buffer_write.size());
    }
    else if (this->connection_context.connection_state == proxy_connection_state::tunnel_transfer) {
        this->async_write_data_to_origin_server(this->upgoing_buffer_write.data(), 0, bytes_transferred);
    }
}

void http_proxy_server_connection::on_origin_server_data_arrived(std::size_t bytes_transferred)
{
    if (this->connection_context.connection_state == proxy_connection_state::read_http_response_header) {
        this->response_data.append(this->downgoing_buffer_read.begin(), this->downgoing_buffer_read.begin() + bytes_transferred);
        auto double_crlf_pos = this->response_data.find("\r\n\r\n");
        if (double_crlf_pos == std::string::npos) {
            if (this->response_data.size() < MAX_RESPONSE_HEADER_LENGTH) {
                this->async_read_data_from_origin_server();
            }
            else {
                this->report_error("502", "Bad Gateway", "Response header too long");
            }
            return;
        }

        this->response_header = http_header_parser::parse_response_header(this->response_data.begin(), this->response_data.begin() + double_crlf_pos + 4);
        if (!this->response_header) {
            this->report_error("502", "Bad Gateway", "Failed to parse response header");
            return;
        }
        if (this->response_header->http_version() != "1.1" && this->response_header->http_version() != "1.0") {
            this->report_error("502", "Bad Gateway", "HTTP version not supported");
            return;
        }
        if (this->response_header->status_code() < 100 || this->response_header->status_code() > 700) {
            this->report_error("502", "Bad Gateway", "Unexpected status code");
            return;
        }
        this->read_response_context.content_length = boost::optional<std::uint64_t>();
        this->read_response_context.content_length_has_read = 0;
        this->read_response_context.is_origin_server_keep_alive = false;
        this->read_response_context.chunk_checker = boost::optional<http_chunk_checker>();

        auto connection_value = this->response_header->get_header_value("Connection");
        
        if (this->response_header->http_version() == "1.1") {
            this->read_response_context.is_origin_server_keep_alive = true;
        }
        else {
            this->read_response_context.is_origin_server_keep_alive = false;
        }
        auto string_to_lower_case = [](std::string& str) {
            for (auto iter = str.begin(); iter != str.end(); ++iter) {
                *iter = std::tolower(static_cast<unsigned char>(*iter));
            }
        };
        if (connection_value) {
            string_to_lower_case(*connection_value);
            if (*connection_value == "close") {
                this->read_response_context.is_origin_server_keep_alive = false;
            }
            else if (*connection_value == "keep-alive") {
                this->read_response_context.is_origin_server_keep_alive = true;
            }
            else {
                this->report_error("502", "Bad Gateway", std::string());
                return;
            }
        }

        if (this->request_header->method() == "HEAD") {
            this->read_response_context.content_length = boost::optional<std::uint64_t>(0);
        }
        else if (this->response_header->status_code() == 204 || this->response_header->status_code() == 304) {
            // 204 No Content
            // 304 Not Modified
            this->read_response_context.content_length = boost::optional<std::uint64_t>(0);
        }
        else {
            auto content_length_value = this->response_header->get_header_value("Content-Length");
            auto transfer_encoding_value = this->response_header->get_header_value("Transfer-Encoding");
            if (content_length_value) {
                try {
                    this->read_response_context.content_length = boost::optional<std::uint64_t>(std::stoull(*content_length_value));
                }
                catch(const std::exception&) {
                    this->report_error("502", "Bad Gateway", "Invalid Content-Length in response");
                    return;
                }
                this->read_response_context.content_length_has_read = this->response_data.size() - (double_crlf_pos + 4);
            }
            else if (transfer_encoding_value) {
                string_to_lower_case(*transfer_encoding_value);
                if (*transfer_encoding_value == "chunked") {
                    this->read_response_context.chunk_checker = boost::optional<http_chunk_checker>(http_chunk_checker());
                    if (!this->read_response_context.chunk_checker->check(this->response_data.begin() + double_crlf_pos + 4, this->response_data.end())) {
                        this->report_error("502", "Bad Gateway", "Failed to check chunked response");
                        return;
                    }
                }
                else {
                    this->report_error("502", "Bad Gateway", "Unsupported Transfer-Encoding");
                    return;
                }
            }
            else if (this->read_response_context.is_origin_server_keep_alive) {
                this->report_error("502", "Bad Gateway", "Miss response length info");
                return;
            }
        }
        this->async_write_response_header_to_proxy_client();
    }
    else if (this->connection_context.connection_state == proxy_connection_state::read_http_response_content) {
        if (this->read_response_context.content_length) {
            this->read_response_context.content_length_has_read += bytes_transferred;
        }
        else if (this->read_response_context.chunk_checker) {
            if (!this->read_response_context.chunk_checker->check(this->downgoing_buffer_read.begin(), this->downgoing_buffer_read.begin() + bytes_transferred)) {
                return;
            }
        }
        this->connection_context.connection_state = proxy_connection_state::write_http_response_content;
        this->encryptor->encrypt(reinterpret_cast<const unsigned char*>(&this->downgoing_buffer_read[0]), reinterpret_cast<unsigned char*>(&this->downgoing_buffer_write[0]), bytes_transferred);
        this->async_write_data_to_proxy_client(this->downgoing_buffer_write.data(), 0, bytes_transferred);
    }
    else if (this->connection_context.connection_state == proxy_connection_state::tunnel_transfer) {
        this->encryptor->encrypt(reinterpret_cast<const unsigned char*>(&this->downgoing_buffer_read[0]), reinterpret_cast<unsigned char*>(&this->downgoing_buffer_write[0]), bytes_transferred);
        this->async_write_data_to_proxy_client(this->downgoing_buffer_write.data(), 0, bytes_transferred);
    }
}

void http_proxy_server_connection::on_proxy_client_data_written()
{
    if (this->connection_context.connection_state == proxy_connection_state::tunnel_transfer) {
        this->async_read_data_from_origin_server();
    }
    else if (this->connection_context.connection_state == proxy_connection_state::write_http_response_header
        || this->connection_context.connection_state == proxy_connection_state::write_http_response_content) {
        if ((this->read_response_context.content_length && this->read_response_context.content_length_has_read >= *this->read_response_context.content_length)
            || (this->read_response_context.chunk_checker && this->read_response_context.chunk_checker->is_complete())) {
            boost::system::error_code ec;
            if (!this->read_response_context.is_origin_server_keep_alive) {
                this->origin_server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                this->origin_server_socket.close(ec);
            }
            if (this->read_request_context.is_proxy_client_keep_alive) {
                this->request_data.clear();
                this->response_data.clear();
                this->request_header = boost::optional<http_request_header>();
                this->response_header = boost::optional<http_response_header>();
                this->read_request_context.content_length = boost::optional<std::uint64_t>();
                this->read_request_context.chunk_checker = boost::optional<http_chunk_checker>();
                this->read_response_context.content_length = boost::optional<std::uint64_t>();
                this->read_response_context.chunk_checker = boost::optional<http_chunk_checker>();
                this->connection_context.connection_state = proxy_connection_state::read_http_request_header;
                this->async_read_data_from_proxy_client();
            }
            else {
                this->proxy_client_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                this->proxy_client_socket.close(ec);
            }
        }
        else {
            this->connection_context.connection_state = proxy_connection_state::read_http_response_content;
            this->async_read_data_from_origin_server();
        }
    }
    else if (this->connection_context.connection_state == proxy_connection_state::report_connection_established) {
        this->start_tunnel_transfer();
    }
    else if (this->connection_context.connection_state == proxy_connection_state::report_error) {
        boost::system::error_code ec;
        if (this->origin_server_socket.is_open()) {
            this->origin_server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            this->origin_server_socket.close(ec);
        }
        if (this->proxy_client_socket.is_open()) {
            this->proxy_client_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            this->proxy_client_socket.close(ec);
        }
    }
}

void http_proxy_server_connection::on_origin_server_data_written()
{
    if (this->connection_context.connection_state == proxy_connection_state::tunnel_transfer) {
        this->async_read_data_from_proxy_client();
    }
    else if (this->connection_context.connection_state == proxy_connection_state::write_http_request_header
        || this->connection_context.connection_state == proxy_connection_state::write_http_request_content) {
        if (this->read_request_context.content_length) {
            if (this->read_request_context.content_length_has_read < *this->read_request_context.content_length) {
                this->connection_context.connection_state = proxy_connection_state::read_http_request_content;
                this->async_read_data_from_proxy_client();
            }
            else {
                this->connection_context.connection_state = proxy_connection_state::read_http_response_header;
                this->async_read_data_from_origin_server();
            }
        }
        else {
            assert(this->read_request_context.chunk_checker);
            if (!this->read_request_context.chunk_checker->is_complete()) {
                this->connection_context.connection_state = proxy_connection_state::read_http_request_content;
                this->async_read_data_from_proxy_client();
            }
            else {
                this->connection_context.connection_state = proxy_connection_state::read_http_response_header;
                this->async_read_data_from_origin_server();
            }
        }
    }
}

void http_proxy_server_connection::on_error(const boost::system::error_code& error)
{
    if (this->connection_context.connection_state == proxy_connection_state::resolve_origin_server_address) {
        this->report_error("504", "Gateway Timeout", "Failed to resolve the hostname");
    }
    else if (this->connection_context.connection_state == proxy_connection_state::connect_to_origin_server) {
        this->report_error("502", "Bad Gateway", "Failed to connect to origin server");
    }
    else if (this->connection_context.connection_state == proxy_connection_state::write_http_request_header && this->connection_context.reconnect_on_error) {
        boost::system::error_code ec;
        this->origin_server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        this->origin_server_socket.close(ec);
        this->async_connect_to_origin_server();
    }
    else {
        boost::system::error_code ec;
        if (this->origin_server_socket.is_open()) {
            this->origin_server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            this->origin_server_socket.close(ec);
        }
        if (this->proxy_client_socket.is_open()) {
            this->proxy_client_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            this->proxy_client_socket.close(ec);
        }
    }
}

void http_proxy_server_connection::on_timeout()
{
    boost::system::error_code ec;
    if (this->origin_server_socket.is_open()) {
        this->origin_server_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        this->origin_server_socket.close(ec);
    }
    if (this->proxy_client_socket.is_open()) {
        this->proxy_client_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        this->proxy_client_socket.close(ec);
    }
}

} // namespace azure_proxy
