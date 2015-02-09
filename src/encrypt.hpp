/*
 *    encrypt.hpp:
 *
 *    Copyright (C) 2014-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_ENCRYPT_HPP
#define AZURE_ENCRYPT_HPP

#include <cassert>
#include <cstring>
#include <memory>
#include <stdexcept>

extern "C" {
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
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

class aes_cfb128_encryptor : public stream_encryptor {
    AES_KEY aes_ctx;
    int num;
    unsigned char key[32];
    unsigned char ivec[16];
public:
    aes_cfb128_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0) {
        assert(key && ivec);
        assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
        std::memcpy(this->key, key, key_bits / 8);
        std::memcpy(this->ivec, ivec, sizeof(this->ivec));
        AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
    }

    virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length) {
        assert(in && out);
        AES_cfb128_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_ENCRYPT);
    }

    virtual ~aes_cfb128_encryptor() {}
};

class aes_cfb128_decryptor : public stream_decryptor {
    AES_KEY aes_ctx;
    int num;
    unsigned char key[32];
    unsigned char ivec[16];
public:
    aes_cfb128_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0) {
        assert(key && ivec);
        assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
        std::memcpy(this->key, key, key_bits / 8);
        std::memcpy(this->ivec, ivec, sizeof(this->ivec));
        AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
    }

    virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length) {
        assert(in && out);
        AES_cfb128_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_DECRYPT);
    }

    virtual ~aes_cfb128_decryptor() {}
};

class aes_cfb8_encryptor : public stream_encryptor {
    AES_KEY aes_ctx;
    int num;
    unsigned char key[32];
    unsigned char ivec[16];
public:
    aes_cfb8_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0) {
        assert(key && ivec);
        assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
        std::memcpy(this->key, key, key_bits / 8);
        std::memcpy(this->ivec, ivec, sizeof(this->ivec));
        AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
    }

    virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length) {
        assert(in && out);
        AES_cfb8_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_ENCRYPT);
    }

    virtual ~aes_cfb8_encryptor() {}
};

class aes_cfb8_decryptor : public stream_decryptor{
    AES_KEY aes_ctx;
    int num;
    unsigned char key[32];
    unsigned char ivec[16];
public:
    aes_cfb8_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0) {
        assert(key && ivec);
        assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
        std::memcpy(this->key, key, key_bits / 8);
        std::memcpy(this->ivec, ivec, sizeof(this->ivec));
        AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
    }

    virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length) {
        assert(in && out);
        AES_cfb8_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_DECRYPT);
    }

    virtual ~aes_cfb8_decryptor() {}
};

class aes_cfb1_encryptor : public stream_encryptor {
    AES_KEY aes_ctx;
    int num;
    unsigned char key[32];
    unsigned char ivec[16];
public:
    aes_cfb1_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0) {
        assert(key && ivec);
        assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
        std::memcpy(this->key, key, key_bits / 8);
        std::memcpy(this->ivec, ivec, sizeof(this->ivec));
        AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
    }

    virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length) {
        assert(in && out);
        AES_cfb1_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_ENCRYPT);
    }

    virtual ~aes_cfb1_encryptor() {
    }
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

class aes_cfb1_decryptor : public stream_decryptor {
    AES_KEY aes_ctx;
    int num;
    unsigned char key[32];
    unsigned char ivec[16];
public:
    aes_cfb1_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0) {
        assert(key && ivec);
        assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
        std::memcpy(this->key, key, key_bits / 8);
        std::memcpy(this->ivec, ivec, sizeof(this->ivec));
        AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
    }

    virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length) {
        assert(in && out);
        AES_cfb1_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_DECRYPT);
    }

    virtual ~aes_cfb1_decryptor() {
    }
};

class aes_ofb128_encryptor : public stream_encryptor {
    AES_KEY aes_ctx;
    int num;
    unsigned char key[32];
    unsigned char ivec[16];
public:
    aes_ofb128_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0) {
        assert(key && ivec);
        assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
        std::memcpy(this->key, key, key_bits / 8);
        std::memcpy(this->ivec, ivec, sizeof(this->ivec));
        AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
    }

    virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length) {
        assert(in && out);
        AES_ofb128_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num);
    }
    virtual ~aes_ofb128_encryptor() {}
};

class aes_ofb128_decryptor : public stream_decryptor {
    AES_KEY aes_ctx;
    int num;
    unsigned char key[32];
    unsigned char ivec[16];
public:
    aes_ofb128_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0) {
        assert(key && ivec);
        assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
        std::memcpy(this->key, key, key_bits / 8);
        std::memcpy(this->ivec, ivec, sizeof(this->ivec));
        AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
    }

    virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length) {
        assert(in && out);
        AES_ofb128_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num);
    }
    virtual ~aes_ofb128_decryptor() {}
};

class aes_ctr128_encryptor : public stream_encryptor {
     AES_KEY aes_ctx;
     unsigned int num;
     unsigned char key[32];
     unsigned char ivec[16];
     unsigned char ecount_buf[16];
public:
    aes_ctr128_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0) {
        assert(key && ivec);
        assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
        std::memcpy(this->key, key, key_bits / 8);
        std::memcpy(this->ivec, ivec, sizeof(this->ivec));
        std::memset(this->ecount_buf, 0, sizeof(this->ecount_buf));
        AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
    }

    virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length) {
        assert(in && out);
        AES_ctr128_encrypt(in, out, length, &aes_ctx, this->ivec, this->ecount_buf, &this->num);
    }

    virtual ~aes_ctr128_encryptor() {
    }
};

class aes_ctr128_decryptor : public stream_decryptor {
     AES_KEY aes_ctx;
     unsigned int num;
     unsigned char key[32];
     unsigned char ivec[16];
     unsigned char ecount_buf[16];
public:
    aes_ctr128_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0) {
        assert(key && ivec);
        assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
        std::memcpy(this->key, key, key_bits / 8);
        std::memcpy(this->ivec, ivec, sizeof(this->ivec));
        std::memset(this->ecount_buf, 0, sizeof(this->ecount_buf));
        AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
    }

    virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length) {
        assert(in && out);
        AES_ctr128_encrypt(in, out, length, &aes_ctx, this->ivec, this->ecount_buf, &this->num);
    }

    virtual ~aes_ctr128_decryptor() {
    }
};

enum class rsa_padding {
    pkcs1_padding,
    pkcs1_oaep_padding,
    sslv23_padding,
    no_padding
};

class rsa {
    bool is_pub;
    std::shared_ptr<RSA> rsa_handle;
public:
    rsa(const std::string& key) {
        if (key.size() > 26 && std::equal(key.begin(), key.begin() + 26, "-----BEGIN PUBLIC KEY-----")) {
            this->is_pub = true;
        }
        else if (key.size() > 31 && std::equal(key.begin(), key.begin() + 31, "-----BEGIN RSA PRIVATE KEY-----")) {
            this->is_pub = false;
        }
        else {
            throw std::invalid_argument("invalid argument");
        }

        auto bio_handle = std::shared_ptr<BIO>(BIO_new_mem_buf(const_cast<char*>(key.data()), key.size()), BIO_free);
        if (bio_handle) {
            if (this->is_pub) {
                this->rsa_handle = std::shared_ptr<RSA>(PEM_read_bio_RSA_PUBKEY(bio_handle.get(), nullptr, nullptr, nullptr), RSA_free);
            }
            else {
                this->rsa_handle = std::shared_ptr<RSA>(PEM_read_bio_RSAPrivateKey(bio_handle.get(), nullptr, nullptr, nullptr), RSA_free);
            }
        }
        if (!this->rsa_handle) {
            throw std::invalid_argument("invalid argument");
        }
    }

    int encrypt(int flen, unsigned char* from, unsigned char* to, rsa_padding padding) {
        assert(from && to);
        int pad = this->rsa_padding2int(padding);
        if (this->is_pub) {
            return RSA_public_encrypt(flen, from, to, this->rsa_handle.get(), pad);
        }
        else {
            return RSA_private_encrypt(flen, from, to, this->rsa_handle.get(), pad);
        }
    }

    int decrypt(int flen, unsigned char* from, unsigned char* to, rsa_padding padding) {
        assert(from && to);
        int pad = this->rsa_padding2int(padding);
        if (this->is_pub) {
            return RSA_private_decrypt(flen, from, to, this->rsa_handle.get(), pad);
        }
        else {
            return RSA_private_decrypt(flen, from, to, this->rsa_handle.get(), pad);
        }
    }

    int modulus_size() const {
        return RSA_size(this->rsa_handle.get());
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
            case rsa_padding::sslv23_padding:
                return RSA_SSLV23_PADDING;
                break;
            default:
                return RSA_NO_PADDING;
        }
    }
};

} // namespace azure_proxy

#endif
