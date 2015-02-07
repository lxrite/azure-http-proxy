/*
 *    http_proxy_client_config.cpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <algorithm>
#include <cctype>
#include <fstream>
#include <memory>

extern "C" {
#include <openssl/rsa.h>
#include <openssl/pem.h>
}

#ifdef _WIN32
#include <Windows.h>
#else
extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
}
#endif

#include "http_proxy_client_config.hpp"
#include "jsonxx/jsonxx.h"

namespace azure_proxy {

http_proxy_client_config::http_proxy_client_config()
{}

bool http_proxy_client_config::load_config(const std::string& config_data)
{
    bool rollback = true;
    std::shared_ptr<bool> auto_rollback(&rollback, [this](bool* rollback) {
        if (*rollback) {
            this->config_map.clear();
        }
    });

    jsonxx::Object json_obj;
    if (!json_obj.parse(config_data)) {
        std::cerr << "Failed to parse config" << std::endl;
        return false;
    }
    if (!json_obj.has<jsonxx::String>("proxy_server_address")) {
        std::cerr << "Could not find \"proxy_server_address\" in config or it's value is not a string" << std::endl;
        return false;
    }
    this->config_map["proxy_server_address"] = std::string(json_obj.get<jsonxx::String>("proxy_server_address"));
    if (!json_obj.has<jsonxx::Number>("proxy_server_port")) {
        std::cerr << "Could not find \"proxy_server_port\" in config or it's value is not a number" << std::endl;
        return false;
    }
    this->config_map["proxy_server_port"] = static_cast<unsigned short>(json_obj.get<jsonxx::Number>("proxy_server_port"));
    if (json_obj.has<jsonxx::String>("bind_address")) {
        this->config_map["bind_address"] = std::string(json_obj.get<jsonxx::String>("bind_address"));
    }
    else {
        this->config_map["bind_address"] = std::string("127.0.0.1");
    }
    if (json_obj.has<jsonxx::Number>("listen_port")) {
        this->config_map["listen_port"] = static_cast<unsigned short>(json_obj.get<jsonxx::Number>("listen_port"));
    }
    else {
        this->config_map["listen_port"] = static_cast<unsigned short>(8089);
    }
    if (!json_obj.has<jsonxx::String>("rsa_2048_public_key")) {
        std::cerr << "Could not find \"rsa_2048_public_key\" in config or it's value is not a string" << std::endl;
        return false;
    }
    const std::string& rsa_2048_public_key_base64 = json_obj.get<jsonxx::String>("rsa_2048_public_key");
    std::string rsa_2048_public_key("-----BEGIN PUBLIC KEY-----\n");
    for (std::size_t i = 0; i * 64 < rsa_2048_public_key_base64.size(); ++i) {
        std::size_t length = rsa_2048_public_key_base64.size() - (i * 64) >= 64 ? 64 : rsa_2048_public_key_base64.size() % 64;
        rsa_2048_public_key.append(rsa_2048_public_key_base64.begin() + i * 64, rsa_2048_public_key_base64.begin() + i * 64 + length);
        rsa_2048_public_key.push_back('\n');
    }
    if (rsa_2048_public_key[rsa_2048_public_key.size() - 1] != '\n') {
        rsa_2048_public_key.push_back('\n');
    }
    rsa_2048_public_key.append("-----END PUBLIC KEY-----\n");
    std::shared_ptr<BIO> bio_handle(BIO_new_mem_buf(const_cast<char*>(rsa_2048_public_key.data()), rsa_2048_public_key.size()), BIO_free);
    if (!bio_handle) {
        std::cerr << "Out of memory" << std::endl;
        return false;
    }
    std::shared_ptr<RSA> rsa_handle(PEM_read_bio_RSA_PUBKEY(bio_handle.get(), NULL, NULL, NULL), RSA_free);
    if (!rsa_handle || RSA_size(rsa_handle.get()) != 256) {
        std::cerr << "The value of rsa_2048_public_key is bad" << std::endl;
        return false;
    }
    this->config_map["rsa_2048_public_key"] = rsa_2048_public_key;
    if (json_obj.has<jsonxx::String>("cipher")) {
        std::string cipher = std::string(json_obj.get<jsonxx::String>("cipher"));
        for (auto& ch : cipher) {
            ch = std::tolower(static_cast<unsigned char>(ch));
        }
        bool is_supported_cipher = false;
        if (cipher.size() > 3 && std::equal(cipher.begin(), cipher.begin() + 4, "aes-")) {
            if (cipher.size() > 8 && cipher[7] == '-'
                && (std::equal(cipher.begin() + 4, cipher.begin() + 7, "128")
                    || std::equal(cipher.begin() + 4, cipher.begin() + 7, "192")
                    || std::equal(cipher.begin() + 4, cipher.begin() + 7, "256")
                    )) {
                    if (std::equal(cipher.begin() + 8, cipher.end(), "cfb")
                        || std::equal(cipher.begin() + 8, cipher.end(), "cfb128")
                        || std::equal(cipher.begin() + 8, cipher.end(), "cfb8")
                        || std::equal(cipher.begin() + 8, cipher.end(), "cfb1")
                        || std::equal(cipher.begin() + 8, cipher.end(), "ofb")
                        || std::equal(cipher.begin() + 8, cipher.end(), "ofb128")
                        || std::equal(cipher.begin() + 8, cipher.end(), "ctr")
                        || std::equal(cipher.begin() + 8, cipher.end(), "ctr128")) {
                            is_supported_cipher = true;
                    }
            }
        }
        if (!is_supported_cipher) {
            std::cerr << "Unsupported cipher: " << cipher << std::endl;
            return false;
        }
        this->config_map["cipher"] = cipher;
    }
    else {
        this->config_map["cipher"] = std::string("aes-256-ofb");
    }
    if (json_obj.has<jsonxx::Number>("timeout")) {
        int timeout = static_cast<int>(json_obj.get<jsonxx::Number>("timeout"));
        this->config_map["timeout"] = static_cast<unsigned int>(timeout < 30 ? 30 : timeout);
    }
    else {
        this->config_map["timeout"] = 240ul;
    }
    if (json_obj.has<jsonxx::Number>("workers")) {
        int threads = static_cast<int>(json_obj.get<jsonxx::Number>("workers"));
        this->config_map["workers"] = static_cast<unsigned int>(threads < 1 ? 1 : (threads > 16 ? 16 : threads));
    }
    else {
        this->config_map["workers"] = 2ul;
    }

    rollback = false;
    return true;
}

bool http_proxy_client_config::load_config()
{
    std::string config_data;
#ifdef _WIN32
    wchar_t path_buffer[MAX_PATH];
    if (GetModuleFileNameW(NULL, path_buffer, MAX_PATH) == 0 || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get retrieve the path of the executable file" << std::endl;
    }
    std::wstring config_file_path(path_buffer);
    config_file_path.resize(config_file_path.find_last_of(L'\\') + 1);
    config_file_path += L"client.json";
    std::shared_ptr<std::remove_pointer<HANDLE>::type> config_file_handle(
        CreateFileW(config_file_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL),
        [](HANDLE native_handle) {
            if (native_handle != INVALID_HANDLE_VALUE) {
                CloseHandle(native_handle);
            }
    });
    if (config_file_handle.get() == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open config file \"client.json\"" << std::endl;
        return false;
    }
    char ch;
    DWORD size_read = 0;
    BOOL read_result =  ReadFile(config_file_handle.get(), &ch, 1, &size_read, NULL);
    while (read_result != FALSE && size_read != 0) {
        config_data.push_back(ch);
        read_result =  ReadFile(config_file_handle.get(), &ch, 1, &size_read, NULL);
    }
    if (read_result == FALSE) {
        std::cerr << "Failed to read data from config file" << std::endl;
        return false;
    }
#else
    auto bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) {
        bufsize = 16384;
    }
    std::unique_ptr<char[]> buf(new char[bufsize]);
    passwd pwd, *result = nullptr;
    getpwuid_r(getuid(), &pwd, buf.get(), bufsize, &result);
    if (result == nullptr) {
        return false;
    }
    std::string config_path = pwd.pw_dir;
    config_path += "/.ahpc/client.json";
    std::ifstream ifile(config_path.c_str());
    if (!ifile.is_open()) {
        std::cerr << "Failed to open \"" << config_path << "\"" << std::endl;
        return false;
    }
    char ch;
    while (ifile.get(ch)) {
        config_data.push_back(ch);
    }
#endif
    return this->load_config(config_data);
}

const std::string& http_proxy_client_config::get_proxy_server_address() const
{
    return this->get_config_value<const std::string&>("proxy_server_address");
}

unsigned short http_proxy_client_config::get_proxy_server_port() const
{
    return this->get_config_value<unsigned short>("proxy_server_port");
}

const std::string& http_proxy_client_config::get_bind_address() const
{
    return this->get_config_value<const std::string&>("bind_address");
}

unsigned short http_proxy_client_config::get_listen_port() const
{
    return this->get_config_value<unsigned short>("listen_port");
}

const std::string& http_proxy_client_config::get_rsa_2048_public_key() const
{
    return this->get_config_value<const std::string&>("rsa_2048_public_key");
}

const std::string& http_proxy_client_config::get_cipher() const
{
    return this->get_config_value<const std::string&>("cipher");
}

unsigned int http_proxy_client_config::get_timeout() const
{
    return this->get_config_value<unsigned int>("timeout");
}

unsigned int http_proxy_client_config::get_workers() const
{
    return this->get_config_value<unsigned int>("workers");
}

http_proxy_client_config& http_proxy_client_config::get_instance()
{
    static http_proxy_client_config instance;
    return instance;
}

} // namespace azure_proxy
