/*
 *    encrypt.hpp:
 *
 *    Copyright (C) 2014-2023 Light Lin <lxrite@gmail.com> All Rights Reserved.
 *
 */

#ifndef AZURE_ENCRYPT_HPP
#define AZURE_ENCRYPT_HPP

#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>

extern "C" {
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/rsa.h>
}

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
    EVP_CIPHER_CTX* aes_ctx;
public:
    aes_stream_encryptor(const unsigned char* key, const EVP_CIPHER* cipher, unsigned char* ivec) {
        assert(key && cipher && ivec);
        this->aes_ctx = EVP_CIPHER_CTX_new();
        if (!this->aes_ctx) {
            throw std::runtime_error("Error: EVP_CIPHER_CTX_new failed.");
        }
        if (EVP_EncryptInit_ex(this->aes_ctx, cipher, nullptr, key, ivec) == 0) {
            throw std::runtime_error("Error: EVP_EncryptInit_ex failed.");
        }
    }

    virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length) override {
        assert(in && out);
        int outl = length;
        if (EVP_EncryptUpdate(this->aes_ctx, out, &outl, in, static_cast<int>(length)) == 0) {
            throw std::runtime_error("Error: EVP_EncryptUpdate failed.");
        }
        assert(outl == length);
    }

    virtual ~aes_stream_encryptor() override {
        EVP_CIPHER_CTX_free(this->aes_ctx);
    }
};

class aes_stream_decryptor : public stream_decryptor {
    EVP_CIPHER_CTX* aes_ctx;
public:
    aes_stream_decryptor(const unsigned char* key, const EVP_CIPHER* cipher, unsigned char* ivec) {
        assert(key && cipher && ivec);
        this->aes_ctx = EVP_CIPHER_CTX_new();
        if (!this->aes_ctx) {
            throw std::runtime_error("Error: EVP_CIPHER_CTX_new failed.");
        }
        if (EVP_DecryptInit_ex(this->aes_ctx, cipher, nullptr, key, ivec) == 0) {
            throw std::runtime_error("Error: EVP_DecryptInit_ex failed.");
        }
    }

    virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length) override {
        assert(in && out);
        int outl = length;
        if (EVP_DecryptUpdate(this->aes_ctx, out, &outl, in, static_cast<int>(length)) == 0) {
            throw std::runtime_error("Error: EVP_DecryptUpdate failed.");
        }
        assert(outl == length);
    }

    virtual ~aes_stream_decryptor() override {
        EVP_CIPHER_CTX_free(this->aes_ctx);
    }
};

static const EVP_CIPHER* aes_cfb128_cipher(std::size_t key_bits) {
    assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
    switch (key_bits) {
        case 128:
            return EVP_aes_128_cfb128();
        case 192:
            return EVP_aes_192_cfb128();
        default:
            return EVP_aes_256_cfb128();
    }
}

static const EVP_CIPHER* aes_cfb8_cipher(std::size_t key_bits) {
    assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
    switch (key_bits) {
        case 128:
            return EVP_aes_128_cfb8();
        case 192:
            return EVP_aes_192_cfb8();
        default:
            return EVP_aes_256_cfb8();
    }
}

static const EVP_CIPHER* aes_cfb1_cipher(std::size_t key_bits) {
    assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
    switch (key_bits) {
        case 128:
            return EVP_aes_128_cfb1();
        case 192:
            return EVP_aes_192_cfb1();
        default:
            return EVP_aes_256_cfb1();
    }
}

static const EVP_CIPHER* aes_ofb128_cipher(std::size_t key_bits) {
    assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
    switch (key_bits) {
        case 128:
            return EVP_aes_128_ofb();
        case 192:
            return EVP_aes_192_ofb();
        default:
            return EVP_aes_256_ofb();
    }
}

static const EVP_CIPHER* aes_ctr128_cipher(std::size_t key_bits) {
    assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
    switch (key_bits) {
        case 128:
            return EVP_aes_128_ctr();
        case 192:
            return EVP_aes_192_ctr();
        default:
            return EVP_aes_256_ctr();
    }
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

class aes_cfb8_encryptor : public aes_stream_encryptor {
public:
    aes_cfb8_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) :
        aes_stream_encryptor(key, aes_cfb8_cipher(key_bits), ivec) {
    }
};

class aes_cfb8_decryptor : public aes_stream_decryptor{
public:
    aes_cfb8_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : 
        aes_stream_decryptor(key, aes_cfb8_cipher(key_bits), ivec) {
    }
};

class aes_cfb1_encryptor : public aes_stream_encryptor {
public:
    aes_cfb1_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) :
        aes_stream_encryptor(key, aes_cfb1_cipher(key_bits), ivec) {
    }
};

class aes_cfb1_decryptor : public aes_stream_decryptor {
public:
    aes_cfb1_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) :
        aes_stream_decryptor(key, aes_cfb1_cipher(key_bits), ivec) {
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

enum class rsa_padding {
    pkcs1_padding,
    pkcs1_oaep_padding,
    no_padding
};

class rsa {
    bool is_pub;
    std::shared_ptr<EVP_PKEY> rsa_key;
public:
    rsa(const std::string& key) {
        if (key.size() > 26 && std::equal(key.begin(), key.begin() + 26, "-----BEGIN PUBLIC KEY-----")) {
            this->is_pub = true;
        }
        else if (key.size() > 31 && std::equal(key.begin(), key.begin() + 31, "-----BEGIN RSA PRIVATE KEY-----")) {
            this->is_pub = false;
        }
        else {
            throw std::invalid_argument("Invalid RSA Key.");
        }

        do {
            auto bio = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new_mem_buf(const_cast<char*>(key.data()), key.size()), &BIO_free);
            if (!bio) {
                std::cerr << "Error: BIO_new_mem_buf failed." << std::endl;
                break;
            }
            EVP_PKEY *rsa_key = nullptr;
            int key_selection = this->is_pub ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR;
            auto decoder = std::unique_ptr<OSSL_DECODER_CTX, decltype(&OSSL_DECODER_CTX_free)>(OSSL_DECODER_CTX_new_for_pkey(&rsa_key,
                "PEM", nullptr, "RSA", key_selection, nullptr, nullptr), &OSSL_DECODER_CTX_free);
            if (!decoder) {
                std::cerr << "Error: OSSL_DECODER_CTX_new_for_pkey failed." << std::endl;
                break;
            }
            if (OSSL_DECODER_from_bio(decoder.get(), bio.get()) == 0) {
                std::cerr << "Error: OSSL_DECODER_from_bio failed." << std::endl;
                break;
            }
            this->rsa_key = std::shared_ptr<EVP_PKEY>(rsa_key, &EVP_PKEY_free);
        } while (false);

        if (!this->rsa_key) {
            throw std::invalid_argument("Invalid RSA Key.");
        }
    }

    int encrypt(int flen, unsigned char* from, unsigned char* to, rsa_padding padding) {
        assert(from && to);
        auto rsa_ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(this->rsa_key.get(), nullptr), EVP_PKEY_CTX_free);
        if (!rsa_ctx) {
            std::cerr << "Error: EVP_PKEY_CTX_new failed." << std::endl;
            return 0;
        }
        if (EVP_PKEY_encrypt_init(rsa_ctx.get()) <= 0) {
            std::cerr << "Error: EVP_PKEY_encrypt_init failed." << std::endl;
            return 0;
        }
        int pad = this->rsa_padding2int(padding);
        if (EVP_PKEY_CTX_set_rsa_padding(rsa_ctx.get(), pad) <= 0) {
            std::cerr << "Error: EVP_PKEY_CTX_set_rsa_padding failed." << std::endl;
            return 0;
        }
        std::size_t out_len = this->modulus_size();
        if (EVP_PKEY_encrypt(rsa_ctx.get(), to, &out_len, from, flen) <= 0) {
            std::cerr << "Error: EVP_PKEY_encrypt failed." << std::endl;
            return 0;
        }
        return static_cast<int>(out_len);
    }

    int decrypt(int flen, unsigned char* from, unsigned char* to, rsa_padding padding) {
        assert(from && to);
        auto rsa_ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(this->rsa_key.get(), nullptr), EVP_PKEY_CTX_free);
        if (!rsa_ctx) {
            std::cerr << "Error: EVP_PKEY_CTX_new failed." << std::endl;
            return 0;
        }
        if (EVP_PKEY_decrypt_init(rsa_ctx.get()) <= 0) {
            std::cerr << "Error: EVP_PKEY_decrypt_init failed." << std::endl;
            return 0;
        }
        int pad = this->rsa_padding2int(padding);
        if (EVP_PKEY_CTX_set_rsa_padding(rsa_ctx.get(), pad) <= 0) {
            std::cerr << "Error: EVP_PKEY_CTX_set_rsa_padding failed." << std::endl;
            return 0;
        }
        std::size_t out_len = this->modulus_size();
        if (EVP_PKEY_decrypt(rsa_ctx.get(), to, &out_len, from, flen) <= 0) {
            std::cerr << "Error: EVP_PKEY_decrypt failed." << std::endl;
            return 0;
        }
        return static_cast<int>(out_len);
    }

    int modulus_size() const {
        return EVP_PKEY_get_size(this->rsa_key.get());
    }
private:
    int rsa_padding2int(rsa_padding padding) {
        switch (padding) {
            case rsa_padding::pkcs1_padding:
                return RSA_PKCS1_PADDING;
                break;
            case rsa_padding::pkcs1_oaep_padding:
                return RSA_PKCS1_OAEP_PADDING;
                break;
            default:
                return RSA_NO_PADDING;
        }
    }
};

} // namespace azure_proxy

#endif
