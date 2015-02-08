/*
 *    authentication.hpp:
 *
 *    Copyright (C) 2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_AUTHENTICATION_HPP
#define AZURE_AUTHENTICATION_HPP

#include <map>
#include <string>

namespace azure_proxy {

enum class auth_result {
    ok,
    incorrect,
    error
};

class authentication {
    std::map<std::string, std::string> users_map;
private:
    authentication();
    auth_result auth_basic(const std::string::const_iterator begin, const std::string::const_iterator end) const;
public:
    auth_result auth(const std::string& value) const;
    void add_user(const std::string& username, const std::string& password);
    void remove_all_users();

    static authentication& get_instance();
};

} // namespace azure_proxy

#endif
