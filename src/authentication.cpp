/*
 *    authentication.cpp:
 *
 *    Copyright (C) 2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <algorithm>
#include <iterator>

#include "authentication.hpp"
#include "base64.hpp"

namespace azure_proxy {

authentication::authentication()
{
}

auth_result authentication::auth_basic(const std::string::const_iterator begin, const std::string::const_iterator end) const
{
    std::string authorization;
    try {
        azure_proxy::encoding::base64_decode(begin, end, std::back_inserter(authorization));
    }
    catch (const azure_proxy::encoding::decode_base64_error&) {
        return auth_result::error;
    }
    auto colon_pos = authorization.find(':');
    if (colon_pos == std::string::npos) {
        return auth_result::error;
    }
    std::string username(authorization.begin(), authorization.begin() + colon_pos);
    std::string password(authorization.begin() + colon_pos + 1, authorization.end());
    auto iter = this->users_map.find(username);
    if (iter != this->users_map.end() && std::get<1>(*iter) == password) {
        return auth_result::ok;
    }
    return auth_result::incorrect;
}

auth_result authentication::auth(const std::string& value) const
{
    if (value.size() > 6 && std::equal(value.begin(), value.begin() + 6, "Basic ")) {
        return this->auth_basic(value.begin() + 6, value.end());
    }
    else {
        return auth_result::error;
    }
}

void authentication::add_user(const std::string& username, const std::string& password)
{
    this->users_map[username] = password;
}

void authentication::remove_all_users()
{
    this->users_map.clear();
}

authentication& authentication::get_instance()
{
    static authentication instance;
    return instance;
}

} // namespace azure_proxy
