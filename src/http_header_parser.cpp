/*
 *    http_header_parser.cpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <iterator>
#include <regex>

#include "http_header_parser.hpp"

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

boost::optional<std::string> http_request_header::get_header_value(const std::string& name) const
{
    auto iter = this->_headers_map.find(name);
    if (iter == this->_headers_map.end()) {
        return nullptr;
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

boost::optional<std::string> http_response_header::get_header_value(const std::string& name) const
{
    auto iter = this->_headers_map.find(name);
    if (iter == this->_headers_map.end()) {
        return nullptr;
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
        return 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z';
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
                else {
                    state = parse_header_state::header_parse_failed;
                }
                break;
            case parse_header_state::header_field_name:
                if (is_token_char(*iter)) {
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

boost::optional<http_request_header> http_header_parser::parse_request_header(std::string::const_iterator begin, std::string::const_iterator end)
{
    auto iter = begin;
    auto tmp = iter;
    for (;iter != end && *iter != ' ' && *iter != '\r'; ++iter)
        ;
    if (iter == tmp || iter == end || *iter != ' ') return nullptr;
    http_request_header header;
    header._method = std::string(tmp, iter);
    tmp = ++iter;
    for (;iter != end && *iter != ' ' && *iter != '\r'; ++iter)
        ;
    if (iter == tmp || iter == end || *iter != ' ') return nullptr;
    auto request_uri = std::string(tmp, iter);
    if (header.method() == "CONNECT") {
        std::regex regex("(.+?):(\\d+)");
        std::match_results<std::string::iterator> match_results;
        if (!std::regex_match(request_uri.begin(), request_uri.end(), match_results, regex)) {
            return nullptr;
        }
        header._host = match_results[1];
        try {
            header._port = static_cast<unsigned short>(std::stoul(std::string(match_results[2])));
        }
        catch (const std::exception&) {
            return nullptr;
        }
    }
    else {
        std::regex regex("(.+?)://(.+?)(:(\\d+))?(/.*)");
        std::match_results<std::string::iterator> match_results;
        if (!std::regex_match(request_uri.begin(), request_uri.end(), match_results, regex)) {
            return nullptr;
        }
        header._scheme = match_results[1];
        header._host = match_results[2];
        if (match_results[4].matched) {
            try {
                header._port = static_cast<unsigned short>(std::stoul(std::string(match_results[4])));
            }
            catch (const std::exception&) {
                return nullptr;
            }
        }
        header._path_and_query = match_results[5];
    }

    tmp = ++iter;
    for (;iter != end && *iter != '\r'; ++iter)
        ;
    // HTTP/x.y
    if (iter == end || std::distance(tmp, iter) < 6 || !std::equal(tmp, tmp + 5, "HTTP/")) return nullptr;

    header._http_version = std::string(tmp + 5, iter);

    ++iter;
    if (iter == end || *iter != '\n') return nullptr;

    ++iter;
    try {
        header._headers_map = parse_headers(iter, end);
    }
    catch (const std::exception&) {
        return nullptr;
    }

    return header;
}

boost::optional<http_response_header> http_header_parser::parse_response_header(std::string::const_iterator begin, std::string::const_iterator end)
{
    auto iter = begin;
    auto tmp = iter;
    for (;iter != end && *iter != ' ' && *iter != '\r'; ++iter)
        ;
    if (std::distance(tmp, iter) < 6 || iter == end || *iter != ' ' || !std::equal(tmp, tmp + 5, "HTTP/")) return nullptr;
    http_response_header header;
    header._http_version = std::string(tmp + 5, iter);
    tmp = ++iter;
    for (;iter != end && *iter != ' ' && *iter != '\r'; ++iter)
        ;
    if (tmp == iter || iter == end) return nullptr;
    try {
        header._status_code = std::stoul(std::string(tmp, iter));
    }
    catch(const std::exception&) {
        return nullptr;
    }

    if (*iter == ' ') {
        tmp = ++iter;
        for (;iter != end && *iter != '\r'; ++iter)
            ;
        if (iter == end || *iter != '\r') return nullptr;
        header._status_description = std::string(tmp, iter);
    }

    if (*iter != '\r') return nullptr;

    if (iter == end || *(++iter) != '\n') return nullptr;
    
    ++iter;
    try {
        header._headers_map = parse_headers(iter, end);
    }
    catch (const std::exception&) {
        return nullptr;
    }

    return header;
}

}; // namespace azure_proxy
