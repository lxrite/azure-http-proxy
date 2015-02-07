/*
 *    key_gennerator.hpp:
 *
 *    Copyright (C) 2014-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_KEY_GENERATOR_HPP
#define AZURE_KEY_GENERATOR_HPP

#include <random>
#include <memory>
#include <cassert>
#include <chrono>
#include <mutex>

namespace azure_proxy {

class key_generator {
    std::mt19937 gen;
    std::mutex mtx;
    key_generator() {
        std::uint64_t seed = reinterpret_cast<std::uint64_t>(std::unique_ptr<int>(new int(0)).get()) ^ static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count());
        this->gen.seed(seed);
    }
public:
    void generate(unsigned char* out, std::size_t length) {
        assert(out);
        std::uniform_int_distribution<unsigned short> dis(0, 255);
        std::lock_guard<std::mutex> lck(this->mtx);
        for (std::size_t i = 0; i < length; ++i) {
            out[i] = static_cast<unsigned char>(dis(this->gen));
        }
    }
    static key_generator& get_instance() {
        static key_generator instance;
        return instance;
    }
};

}

#endif
