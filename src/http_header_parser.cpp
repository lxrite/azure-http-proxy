/*
 *    http_header_parser.cpp:
 *
 *    Copyright (C) 2013-2023 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#include <cassert>
#include <iterator>
#include <regex>

#include "http_header_parser.hpp"
#include <curi.h>

namespace azure_proxy {

http_request_header::http_request_header() : _port(80)
{
}

const std::string& http_request_header::method() const
{
    return this->_method;
}

const std::string& http_request_header::scheme() const
{
    return this->_scheme;
}

const std::string& http_request_header::host() const
{
    return this->_host;
}

unsigned short http_request_header::port() const
{
    return this->_port;
}

const std::string& http_request_header::path_and_query() const
{
    return this->_path_and_query;
}

const std::string& http_request_header::http_version() const
{
    return this->_http_version;
}

std::optional<std::string> http_request_header::get_header_value(const std::string& name) const
{
    auto iter = this->_headers_map.find(name);
    if (iter == this->_headers_map.end()) {
        return std::nullopt;
    }
    return std::get<1>(*iter);
}

std::size_t http_request_header::erase_header(const std::string& name)
{
    return this->_headers_map.erase(name);
}

const http_headers_container& http_request_header::get_headers_map() const
{
    return this->_headers_map;
}

http_response_header::http_response_header()
{
}

const std::string& http_response_header::http_version() const
{
    return this->_http_version;
}

unsigned int http_response_header::status_code() const
{
    return this->_status_code;
}

const std::string& http_response_header::status_description() const
{
    return this->_status_description;
}

std::optional<std::string> http_response_header::get_header_value(const std::string& name) const
{
    auto iter = this->_headers_map.find(name);
    if (iter == this->_headers_map.end()) {
        return std::nullopt;
    }
    return std::get<1>(*iter);
}

std::size_t http_response_header::erase_header(const std::string& name)
{
    return this->_headers_map.erase(name);
}

const http_headers_container& http_response_header::get_headers_map() const
{
    return this->_headers_map;
}

http_headers_container http_header_parser::parse_headers(std::string::const_iterator begin, std::string::const_iterator end)
{
    http_headers_container headers;

    auto is_digit = [](char ch) -> bool {
        return '0' <= ch && ch <= '9';
    };
    auto is_alpha = [](char ch) -> bool {
        return ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z');
    };
    auto is_token_char = [&is_alpha, &is_digit](char ch) -> bool {
        return is_alpha(ch) || is_digit(ch) || (
            ch == '!' || ch == '#' ||
            ch == '$' || ch == '%' ||
            ch == '&' || ch == '\'' ||
            ch == '`' || ch == '*' ||
            ch == '+' || ch == '-' ||
            ch == '.' || ch == '^' ||
            ch == '_' || ch == '|' ||
            ch == '~');
    };

    enum class parse_header_state {
        header_field_name_start,
        header_field_name,
        header_field_value_left_ows,
        header_field_value,
        header_field_cr,
        header_field_crlf,
        header_field_crlfcr,
        header_compelete,
        header_parse_failed
    };

    parse_header_state state = parse_header_state::header_field_name_start;
    std::string header_field_name;
    std::string header_field_value;
    for (std::string::const_iterator iter = begin; iter != end && state != parse_header_state::header_compelete && state != parse_header_state::header_parse_failed; ++iter) {
        switch (state) {
            case parse_header_state::header_field_name_start:
                if (is_token_char(*iter)) {
                    header_field_name.push_back(*iter);
                    state = parse_header_state::header_field_name;
                }
                else if (iter == begin && *iter == '\r') {
                    state = parse_header_state::header_field_crlfcr;
                }
                else {
                    state = parse_header_state::header_parse_failed;
                }
                break;
            case parse_header_state::header_field_name:
                if (is_token_char(*iter) || *iter == ' ') {
                    header_field_name.push_back(*iter);
                }
                else if (*iter == ':') {
                    state = parse_header_state::header_field_value_left_ows;
                }
                else {
                    state = parse_header_state::header_parse_failed;
                }
                break;
            case parse_header_state::header_field_value_left_ows:
                if (*iter == ' ' || *iter == '\t') {
                    continue;
                }
                else if (*iter == '\r') {
                    state = parse_header_state::header_field_cr;
                }
                else {
                    header_field_value.push_back(*iter);
                    state = parse_header_state::header_field_value;
                }
                break;
            case parse_header_state::header_field_value:
                if (*iter == '\r') {
                    state = parse_header_state::header_field_cr;
                }
                else {
                    header_field_value.push_back(*iter);
                }
                break;
            case parse_header_state::header_field_cr:
                if (*iter == '\n') {
                    state = parse_header_state::header_field_crlf;
                }
                else {
                    state = parse_header_state::header_parse_failed;
                }
                break;
            case parse_header_state::header_field_crlf:
                if (*iter == ' ' || *iter == '\t') {
                    header_field_value.push_back(*iter);
                    state = parse_header_state::header_field_value;
                }
                else {
                    while (!header_field_name.empty() && (header_field_name[header_field_name.size() - 1] == ' ')) {
                        header_field_name.resize(header_field_name.size() - 1);
                    }
                    assert(!header_field_name.empty());
                    while (!header_field_value.empty() && (header_field_value[header_field_value.size() - 1] == ' ' || (header_field_value[header_field_value.size() - 1] == '\t'))) {
                        header_field_value.resize(header_field_value.size() - 1);
                    }
                    headers.insert(std::make_pair(std::move(header_field_name), std::move(header_field_value)));
                    if (*iter == '\r') {
                        state = parse_header_state::header_field_crlfcr;
                    }
                    else if (is_token_char(*iter)) {
                        header_field_name.push_back(*iter);
                        state = parse_header_state::header_field_name;
                    }
                    else {
                        state = parse_header_state::header_parse_failed;
                    }
                }
                break;
            case parse_header_state::header_field_crlfcr:
                if (*iter == '\n') {
                    state = parse_header_state::header_compelete;
                }
                break;
            default:
                assert(false);
        }
    }
    if (state != parse_header_state::header_compelete) {
        throw std::runtime_error("failed to parse");
    }
    return headers;
}

std::optional<http_request_header> http_header_parser::parse_request_header(std::string::const_iterator begin, std::string::const_iterator end)
{
    auto iter = begin;
    auto tmp = iter;
    for (;iter != end && *iter != ' ' && *iter != '\r'; ++iter)
        ;
    if (iter == tmp || iter == end || *iter != ' ') return std::nullopt;
    http_request_header header;
    header._method = std::string(tmp, iter);
    tmp = ++iter;
    for (;iter != end && *iter != ' ' && *iter != '\r'; ++iter)
        ;
    if (iter == tmp || iter == end || *iter != ' ') return std::nullopt;
    auto request_uri = std::string(tmp, iter);
    if (header.method() == "CONNECT") {
        std::regex regex("(.+?):(\\d+)");
        std::match_results<std::string::iterator> match_results;
        if (!std::regex_match(request_uri.begin(), request_uri.end(), match_results, regex)) {
            return std::nullopt;
        }
        header._host = match_results[1];
        try {
            header._port = static_cast<unsigned short>(std::stoul(std::string(match_results[2])));
        }
        catch (const std::exception&) {
            return std::nullopt;
        }
    }
    else {
        struct parse_user_data {
            std::string scheme;
            std::string host;
            unsigned int port = 80;
            std::string path;
            std::string query;
        };
        auto user_data = parse_user_data{};

        curi_settings settings;
        curi_default_settings(&settings);
        settings.scheme_callback = [](void* user_data, const char* scheme, size_t scheme_len) -> int {
            reinterpret_cast<parse_user_data*>(user_data)->scheme = std::string(scheme, scheme_len);
            return 1;
        };
        settings.host_callback = [](void* user_data, const char* host, size_t host_len) -> int {
            reinterpret_cast<parse_user_data*>(user_data)->host = std::string(host, host_len);
            return 1;
        };
        settings.port_callback = [](void* user_data, unsigned int port) -> int {
            reinterpret_cast<parse_user_data*>(user_data)->port = port;
            return 1;
        };
        settings.path_callback = [](void* user_data, const char* path, size_t path_len) -> int {
            reinterpret_cast<parse_user_data*>(user_data)->path = std::string(path, path_len);
            return 1;
        };
        settings.query_callback = [](void* user_data, const char* query, size_t query_len) -> int {
            reinterpret_cast<parse_user_data*>(user_data)->query = std::string(query, query_len);
            return 1;
        };
        if (curi_status_success != curi_parse_full_uri(request_uri.c_str(), request_uri.size(), &settings, &user_data)) {
            return std::nullopt;
        }

        if (user_data.scheme.empty() || user_data.host.empty() || user_data.path.empty()) {
            return std::nullopt;
        }
        header._scheme = user_data.scheme;
        header._host = user_data.host;
        header._port = user_data.port;
        header._path_and_query = user_data.path;
        if (!user_data.query.empty()) {
            header._path_and_query.push_back('?');
            header._path_and_query += user_data.query;
        }
    }

    tmp = ++iter;
    for (;iter != end && *iter != '\r'; ++iter)
        ;
    // HTTP/x.y
    if (iter == end || std::distance(tmp, iter) < 6 || !std::equal(tmp, tmp + 5, "HTTP/")) return std::nullopt;

    header._http_version = std::string(tmp + 5, iter);

    ++iter;
    if (iter == end || *iter != '\n') return std::nullopt;

    ++iter;
    try {
        header._headers_map = parse_headers(iter, end);
    }
    catch (const std::exception&) {
        return std::nullopt;
    }

    return header;
}

std::optional<http_response_header> http_header_parser::parse_response_header(std::string::const_iterator begin, std::string::const_iterator end)
{
    auto iter = begin;
    auto tmp = iter;
    for (;iter != end && *iter != ' ' && *iter != '\r'; ++iter)
        ;
    if (std::distance(tmp, iter) < 6 || iter == end || *iter != ' ' || !std::equal(tmp, tmp + 5, "HTTP/")) return std::nullopt;
    http_response_header header;
    header._http_version = std::string(tmp + 5, iter);
    tmp = ++iter;
    for (;iter != end && *iter != ' ' && *iter != '\r'; ++iter)
        ;
    if (tmp == iter || iter == end) return std::nullopt;
    try {
        header._status_code = std::stoul(std::string(tmp, iter));
    }
    catch(const std::exception&) {
        return std::nullopt;
    }

    if (*iter == ' ') {
        tmp = ++iter;
        for (;iter != end && *iter != '\r'; ++iter)
            ;
        if (iter == end || *iter != '\r') return std::nullopt;
        header._status_description = std::string(tmp, iter);
    }

    if (*iter != '\r') return std::nullopt;

    if (iter == end || *(++iter) != '\n') return std::nullopt;

    ++iter;
    try {
        header._headers_map = parse_headers(iter, end);
    }
    catch (const std::exception&) {
        return std::nullopt;
    }

    return header;
}

}; // namespace azure_proxy
