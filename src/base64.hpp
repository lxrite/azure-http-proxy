/*
 *    base64.hpp:
 *
 *    Copyright (C) 2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_ENCODING_BASE64_HPP
#define AZURE_ENCODING_BASE64_HPP
#include <exception>
#include <iterator>
#include <string>

namespace azure_proxy {
namespace encoding {

class decode_base64_error : public std::exception {
    const char* _msg;
public:
    explicit decode_base64_error(const char* msg) : _msg(msg) {}
    const char* what() const throw() {
        return this->_msg;
    }
    ~decode_base64_error() throw() {
    }
};

extern const char base64_encode_table[64];

template<typename InputIterator, typename OutputIterator>
OutputIterator base64_encode(InputIterator begin, InputIterator end, OutputIterator out)
{
    typedef unsigned char byte_t;
    static_assert(sizeof(typename std::iterator_traits<InputIterator>::value_type) == sizeof(byte_t), "error");
    auto iter = begin;
    while (iter != end) {
        byte_t byte0 = static_cast<byte_t>(*iter++);
        if (iter == end) {
            *out = base64_encode_table[byte0 >> 2];
            *out = base64_encode_table[static_cast<byte_t>(byte0 & 0x03) << 4];
            *out = '=';
            *out = '=';
            break;
        }
        byte_t byte1 = static_cast<byte_t>(*iter++);
        if (iter == end) {
            *out = base64_encode_table[byte0 >> 2];
            *out = base64_encode_table[static_cast<byte_t>(byte0 & 0x03) << 4 | static_cast<byte_t>(byte1 >> 4)];
            *out = base64_encode_table[static_cast<byte_t>(byte1 & 0x0f) << 2];
            *out = '=';
            break;
        }
        byte_t byte2 = *iter++;
        *out = base64_encode_table[byte0 >> 2];
        *out = base64_encode_table[static_cast<byte_t>(byte0 & 0x03) << 4 | static_cast<byte_t>(byte1 >> 4)];
        *out = base64_encode_table[static_cast<byte_t>(byte1 & 0x0f) << 2 | static_cast<byte_t>(byte2 >> 6)];
        *out = base64_encode_table[byte2 & 0x3f];
    }
    return out;
}

extern const int base64_decode_table[128];

template <class InputIterator, class OutputIterator>
OutputIterator base64_decode(InputIterator begin, InputIterator end, OutputIterator out) {
    static_assert(std::is_same<typename std::iterator_traits<InputIterator>::value_type, char>::value, "error");
    typedef unsigned char byte_t;
    auto iter = begin;
    while (iter != end) {
        char char0 = *iter++;
        char char1 = iter != end ? *iter++ : throw decode_base64_error("invalid length");
        char char2 = iter != end ? *iter++ : throw decode_base64_error("invalid length");
        char char3 = iter != end ? *iter++ : throw decode_base64_error("invalid length");
        byte_t _byte;
        if (char0 < '\0' || char0 == '=' || base64_decode_table[char0] == -1) {
            throw decode_base64_error("failed to decode");
        }
        _byte = static_cast<byte_t>(base64_decode_table[char0]) << 2;
        if (char1 < '\0' || char1 == '=' || base64_decode_table[char1] == -1) {
            throw decode_base64_error("failed to decode");
        }
        *out = static_cast<byte_t>(_byte | static_cast<byte_t>(base64_decode_table[char1]) >> 4);
        _byte = static_cast<byte_t>(static_cast<byte_t>(base64_decode_table[char1]) << 4);
        if (iter == end && char2 == '=' && char3 == '=') {
            break;
        }
        else if (char2 < '\0' || base64_decode_table[char2] == -1) {
            throw decode_base64_error("failed to decode");
        }
        *out = static_cast<byte_t>(_byte | static_cast<byte_t>(base64_decode_table[char2]) >> 2);
        _byte = static_cast<byte_t>(static_cast<byte_t>(base64_decode_table[char2]) << 6);
        if (iter == end && char3 == '=') {
            break;
        }
        else if (char3 < '\0' || base64_decode_table[char3] == -1) {
            throw decode_base64_error("failed to decode");
        }
        *out = static_cast<byte_t>(_byte | static_cast<byte_t>(base64_decode_table[char3]));
    }
    return out;
}

} // namespace encoding
} // namespace azure_proxy

#endif
