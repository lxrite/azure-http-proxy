/*
 *    authentication.cpp:
 *
 *    Copyright (C) 2015-2023 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#include <algorithm>
#include <iterator>

#include "authentication.hpp"
#include "hash_utils.hpp"

namespace azure_proxy {

authentication::authentication()
{
}

bool authentication::auth(const auth_key_hash_t& auth_key_hash) const
{
    return this->auth_keys_map.find(auth_key_hash) != this->auth_keys_map.end();
}

void authentication::add_auth_key(const std::string& auth_key)
{
    auto auth_key_hash = hash_utils::sha256(reinterpret_cast<const unsigned char*>(auth_key.data()), auth_key.size());
    this->auth_keys_map[auth_key_hash] = auth_key;
}

void authentication::remove_all_auth_keys()
{
    this->auth_keys_map.clear();
}

authentication& authentication::get_instance()
{
    static authentication instance;
    return instance;
}

} // namespace azure_proxy
