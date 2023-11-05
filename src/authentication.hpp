/*
 *    authentication.hpp:
 *
 *    Copyright (C) 2015-2023 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#ifndef AZURE_AUTHENTICATION_HPP
#define AZURE_AUTHENTICATION_HPP

#include <array>
#include <map>
#include <string>

namespace azure_proxy {

using auth_key_hash_t = std::array<unsigned char, 32>;

class authentication {
    std::map<auth_key_hash_t, std::string> auth_keys_map;
private:
    authentication();
public:
    bool auth(const auth_key_hash_t& auth_key_hash) const;
    void add_auth_key(const std::string& auth_key);
    void remove_all_auth_keys();

    static authentication& get_instance();
};

} // namespace azure_proxy

#endif
