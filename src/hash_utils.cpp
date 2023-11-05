/*
 *    hash_utils.cpp:
 *
 *    Copyright (C) 2023 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#include "hash_utils.hpp"
#include <openssl/sha.h>

namespace azure_proxy {
namespace hash_utils {

std::array<unsigned char, 32> sha256(const unsigned char* data, std::size_t count) {
    std::array<unsigned char, 32> result;
    SHA256(data, count, result.data());
    return result;
}

} // namespace hash_utils
} // namespace azure_proxy
