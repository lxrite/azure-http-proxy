/*
 *    http_proxy_client_config.hpp:
 *
 *    Copyright (C) 2013-2023 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#ifndef AZURE_HTTP_PROXY_CLIENT_CONFIG_HPP
#define AZURE_HTTP_PROXY_CLIENT_CONFIG_HPP

#include <any>
#include <cassert>
#include <map>
#include <stdexcept>
#include <string>

namespace azure_proxy {

class http_proxy_client_config {
    std::map<std::string, std::any> config_map;
private:
    template<typename T>
    T get_config_value(const std::string& key) const {
        assert(!this->config_map.empty());
        auto iter = this->config_map.find(key);
        if (iter == this->config_map.end()) {
            throw std::invalid_argument("invalid argument");
        }
        return std::any_cast<T>(iter->second);
    }
    http_proxy_client_config();
    bool load_config_data(const std::string& config_data);
public:
    bool load_config(const std::string& config_path);
    const std::string& get_proxy_server_address() const;
    unsigned short get_proxy_server_port() const;
    const std::string& get_bind_address() const;
    unsigned short get_listen_port() const;
    const std::string& get_rsa_public_key() const;
    const std::string& get_cipher() const;
    unsigned int get_timeout() const;
    unsigned int get_workers() const;
    const std::string& get_auth_key() const;

    static http_proxy_client_config& get_instance();
};

} // namespace azure_proxy

#endif
