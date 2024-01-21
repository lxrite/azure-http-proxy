/*
 *    encrypt.hpp:
 *
 *    Copyright (C) 2014-2024 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#ifndef AZURE_ENCRYPT_HPP
#define AZURE_ENCRYPT_HPP

#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>

#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

namespace azure_proxy {

class stream_encryptor {
public:
    virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length) = 0;
    virtual ~stream_encryptor() {}
};

class stream_decryptor {
public:
    virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length) = 0;
    virtual ~stream_decryptor() {}
};

class copy_encryptor : public stream_encryptor {
public:
    copy_encryptor() {};
    virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length) {
        assert(in && out);
        std::memcpy(out, in, length);
    }
    virtual ~copy_encryptor() {}
};

class copy_decryptor : public stream_decryptor {
public:
    copy_decryptor() {};
    virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length) {
        assert(in && out);
        std::memcpy(out, in, length);
    }
    virtual ~copy_decryptor() {}
};

class aes_stream_encryptor : public stream_encryptor {
    mbedtls_cipher_context_t aes_ctx_;
public:
    aes_stream_encryptor(const unsigned char* key, const mbedtls_cipher_info_t* cipher_info, unsigned char* ivec) {
        assert(key && cipher_info && ivec);
        mbedtls_cipher_init(&aes_ctx_);
        std::unique_ptr<mbedtls_cipher_context_t, decltype(&mbedtls_cipher_free)> auto_free(&aes_ctx_, mbedtls_cipher_free);
        int ret = mbedtls_cipher_setup(&aes_ctx_, cipher_info);
        if (ret != 0) {
            std::cerr << "mbedtls_cipher_setup error: " << ret << std::endl;
            throw std::runtime_error("mbedtls_cipher_setup error");
        }
        ret = mbedtls_cipher_setkey(&aes_ctx_, key, mbedtls_cipher_info_get_key_bitlen(cipher_info), MBEDTLS_ENCRYPT);
        if (ret != 0) {
            std::cerr << "mbedtls_cipher_setkey error: " << ret << std::endl;
            throw std::runtime_error("mbedtls_cipher_setkey error");
        }
        ret = mbedtls_cipher_set_iv(&aes_ctx_, ivec, mbedtls_cipher_info_get_iv_size(cipher_info));
        if (ret != 0) {
            std::cerr << "mbedtls_cipher_set_iv error: " << ret << std::endl;
            throw std::runtime_error("mbedtls_cipher_set_iv error");
        }
        auto_free.release();
    }

    virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length) override {
        assert(in && out);
        std::size_t out_len = 0;
        int ret = mbedtls_cipher_update(&aes_ctx_, in, length, out, &out_len);
        if (ret != 0) {
            std::cerr << "mbedtls_cipher_update error: " << ret << std::endl;
            throw std::runtime_error("mbedtls_cipher_update error");
        }
        assert(out_len == length);
    }

    virtual ~aes_stream_encryptor() override {
        mbedtls_cipher_free(&aes_ctx_);
    }
};

class aes_stream_decryptor : public stream_decryptor {
    mbedtls_cipher_context_t aes_ctx_;
public:
    aes_stream_decryptor(const unsigned char* key, const mbedtls_cipher_info_t* cipher_info, unsigned char* ivec) {
        assert(key && cipher_info && ivec);
        mbedtls_cipher_init(&aes_ctx_);
        std::unique_ptr<mbedtls_cipher_context_t, decltype(&mbedtls_cipher_free)> auto_free(&aes_ctx_, mbedtls_cipher_free);
        int ret = mbedtls_cipher_setup(&aes_ctx_, cipher_info);
        if (ret != 0) {
            std::cerr << "mbedtls_cipher_setup error: " << ret << std::endl;
            throw std::runtime_error("mbedtls_cipher_setup error");
        }
        ret = mbedtls_cipher_setkey(&aes_ctx_, key, mbedtls_cipher_info_get_key_bitlen(cipher_info), MBEDTLS_DECRYPT);
        if (ret != 0) {
            std::cerr << "mbedtls_cipher_setkey error: " << ret << std::endl;
            throw std::runtime_error("mbedtls_cipher_setkey error");
        }
        ret = mbedtls_cipher_set_iv(&aes_ctx_, ivec, mbedtls_cipher_info_get_iv_size(cipher_info));
        if (ret != 0) {
            std::cerr << "mbedtls_cipher_set_iv error: " << ret << std::endl;
            throw std::runtime_error("mbedtls_cipher_set_iv error");
        }
        auto_free.release();
    }

    virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length) override {
        assert(in && out);
        std::size_t out_len = 0;
        int ret = mbedtls_cipher_update(&aes_ctx_, in, length, out, &out_len);
        if (ret != 0) {
            std::cerr << "mbedtls_cipher_update error: " << ret << std::endl;
            throw std::runtime_error("mbedtls_cipher_update error");
        }
        assert(out_len == length);
    }

    virtual ~aes_stream_decryptor() override {
        mbedtls_cipher_free(&aes_ctx_);
    }
};

static const mbedtls_cipher_info_t* aes_cfb128_cipher(std::size_t key_bits) {
    assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
    mbedtls_cipher_type_t cipher_type;
    switch (key_bits) {
        case 128:
            cipher_type = mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_128_CFB128;
            break;
        case 192:
            cipher_type = mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_192_CFB128;
            break;
        default:
            cipher_type = mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_256_CFB128;
    }
    return mbedtls_cipher_info_from_type(cipher_type);
}

static const mbedtls_cipher_info_t* aes_ofb128_cipher(std::size_t key_bits) {
    assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
    mbedtls_cipher_type_t cipher_type;
    switch (key_bits) {
        case 128:
            cipher_type = mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_128_OFB;
            break;
        case 192:
            cipher_type = mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_192_OFB;
            break;
        default:
            cipher_type = mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_256_OFB;
    }
    return mbedtls_cipher_info_from_type(cipher_type);
}

static const mbedtls_cipher_info_t* aes_ctr128_cipher(std::size_t key_bits) {
    assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
    mbedtls_cipher_type_t cipher_type;
    switch (key_bits) {
        case 128:
            cipher_type = mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_128_CTR;
            break;
        case 192:
            cipher_type = mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_192_CTR;
            break;
        default:
            cipher_type = mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_256_CTR;
    }
    return mbedtls_cipher_info_from_type(cipher_type);
}

class aes_cfb128_encryptor : public aes_stream_encryptor {
public:
    aes_cfb128_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) :
        aes_stream_encryptor(key, aes_cfb128_cipher(key_bits), ivec) {
    }
};

class aes_cfb128_decryptor : public aes_stream_decryptor {
public:
    aes_cfb128_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) :
        aes_stream_decryptor(key, aes_cfb128_cipher(key_bits), ivec) {
    }
};

class aes_ofb128_encryptor : public aes_stream_encryptor {
public:
    aes_ofb128_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) :
        aes_stream_encryptor(key, aes_ofb128_cipher(key_bits), ivec) {
    }
};

class aes_ofb128_decryptor : public aes_stream_decryptor {
public:
    aes_ofb128_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) :
        aes_stream_decryptor(key, aes_ofb128_cipher(key_bits), ivec) {
    }
};

class aes_ctr128_encryptor : public aes_stream_encryptor {
public:
    aes_ctr128_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) :
        aes_stream_encryptor(key, aes_ctr128_cipher(key_bits), ivec) {
    }
};

class aes_ctr128_decryptor : public aes_stream_decryptor {
public:
    aes_ctr128_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) :
        aes_stream_decryptor(key, aes_ctr128_cipher(key_bits), ivec) {
    }
};

class rsa {
    bool is_pub_key_;
    mbedtls_pk_context pk_;
public:
    rsa(const std::string& key) {
        if (key.size() > 26 && std::equal(key.begin(), key.begin() + 26, "-----BEGIN PUBLIC KEY-----")) {
            is_pub_key_ = true;
        }
        else if (key.size() > 31 && std::equal(key.begin(), key.begin() + 31, "-----BEGIN RSA PRIVATE KEY-----")) {
            is_pub_key_ = false;
        }
        else {
            throw std::invalid_argument("invalid RSA key");
        }

        mbedtls_pk_init(&pk_);
        std::unique_ptr<mbedtls_pk_context, decltype(&mbedtls_pk_free)> auto_free_pk(&pk_, mbedtls_pk_free);
        int ret = 0;
        if (is_pub_key_) {
            ret = mbedtls_pk_parse_public_key(&pk_, reinterpret_cast<const unsigned char*>(key.c_str()), key.size() + 1);
        } else {
            mbedtls_entropy_context entropy;
            mbedtls_ctr_drbg_context ctr_drbg;
            mbedtls_entropy_init(&entropy);
            mbedtls_ctr_drbg_init(&ctr_drbg);
            std::unique_ptr<mbedtls_entropy_context, decltype(&mbedtls_entropy_free)> auto_free_entropy(&entropy, mbedtls_entropy_free);
            std::unique_ptr<mbedtls_ctr_drbg_context, decltype(&mbedtls_ctr_drbg_free)> auto_free_ctr_drbg(&ctr_drbg, mbedtls_ctr_drbg_free);
            int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
            if (ret != 0) {
                std::cerr << "mbedtls_ctr_drbg_seed error: " << ret << std::endl;
                throw std::runtime_error("mbedtls_ctr_drbg_seed error");
            }
            ret = mbedtls_pk_parse_key(&pk_, reinterpret_cast<const unsigned char*>(key.c_str()), key.size() + 1, nullptr, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
        }
        if (ret != 0) {
            if (is_pub_key_) {
                std::cerr << "mbedtls_pk_parse_public_key error: " << ret << std::endl;
            } else {
                std::cerr << "mbedtls_pk_parse_key error: " << ret << std::endl;
            }
            throw std::invalid_argument("invalid RSA key");
        }
        auto pk_type = mbedtls_pk_get_type(&pk_);
        if (pk_type != MBEDTLS_PK_RSA) {
            std::cerr << "mbedtls_pk_get_type: " << pk_type << std::endl;
            throw std::invalid_argument("invalid RSA key");
        }

        ret = mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk_), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
        if (ret != 0) {
            mbedtls_pk_free(&pk_);
            std::cerr << "mbedtls_rsa_set_padding error: " << ret << std::endl;
            throw std::runtime_error("mbedtls_rsa_set_padding error");
        }
        auto_free_pk.release();
    }

    ~rsa() {
        mbedtls_pk_free(&pk_);
    }

    int encrypt(int flen, unsigned char* from, unsigned char* to) {
        assert(from && to);
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;

        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        std::unique_ptr<mbedtls_entropy_context, decltype(&mbedtls_entropy_free)> auto_free_entropy(&entropy, mbedtls_entropy_free);
        std::unique_ptr<mbedtls_ctr_drbg_context, decltype(&mbedtls_ctr_drbg_free)> auto_free_ctr_drbg(&ctr_drbg, mbedtls_ctr_drbg_free);

        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
        if (ret != 0) {
            std::cerr << "mbedtls_ctr_drbg_seed error: " << ret << std::endl;
            return 0;
        }

        ret = mbedtls_rsa_pkcs1_encrypt(mbedtls_pk_rsa(pk_), mbedtls_ctr_drbg_random, &ctr_drbg, flen, from, to);
        if (ret != 0) {
            std::cerr << "mbedtls_rsa_pkcs1_encrypt error: " << ret << std::endl;
            return 0;
        }
        return modulus_size();
    }

    int decrypt(int flen, unsigned char* from, unsigned char* to) {
        assert(from && to);
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;

        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        std::unique_ptr<mbedtls_entropy_context, decltype(&mbedtls_entropy_free)> auto_free_entropy(&entropy, mbedtls_entropy_free);
        std::unique_ptr<mbedtls_ctr_drbg_context, decltype(&mbedtls_ctr_drbg_free)> auto_free_ctr_drbg(&ctr_drbg, mbedtls_ctr_drbg_free);

        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
        if (ret != 0) {
            std::cerr << "mbedtls_ctr_drbg_seed error: " << ret << std::endl;
            return 0;
        }

        std::size_t out_len = 0;
        ret = mbedtls_rsa_pkcs1_decrypt(mbedtls_pk_rsa(pk_), mbedtls_ctr_drbg_random, &ctr_drbg, &out_len, from, to, modulus_size());
        if (ret != 0) {
            std::cerr << "mbedtls_rsa_pkcs1_decrypt error: " << ret << std::endl;
            return 0;
        }
        return static_cast<int>(out_len);
    }

    int modulus_size() const {
        return mbedtls_pk_get_bitlen(&pk_) / 8;
    }
};

} // namespace azure_proxy

#endif
