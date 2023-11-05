/*
 *    hash_utils.hpp:
 *
 *    Copyright (C) 2023 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#ifndef AZURE_HASH_UTILS_HPP
#define AZURE_HASH_UTILS_HPP

#include <array>

namespace azure_proxy {
namespace hash_utils {

std::array<unsigned char, 32> sha256(const unsigned char* data, std::size_t count);

} // namespace hash_utils
} // namespace azure_proxy

#endif // AZURE_HASH_UTILS_HPP
