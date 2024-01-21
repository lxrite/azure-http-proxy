/*
 *    hash_utils.cpp:
 *
 *    Copyright (C) 2023-2024 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#include "hash_utils.hpp"
#include "mbedtls/sha256.h"

namespace azure_proxy {
namespace hash_utils {

std::array<unsigned char, 32> sha256(const unsigned char* data, std::size_t count) {
    std::array<unsigned char, 32> result;
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, data, count);
    mbedtls_sha256_finish(&ctx, result.data());
    mbedtls_sha256_free(&ctx);
    return result;
}

} // namespace hash_utils
} // namespace azure_proxy
