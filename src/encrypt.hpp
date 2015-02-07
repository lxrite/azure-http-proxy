/*
 *    encrypt.hpp:
 *
 *    Copyright (C) 2014-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_ENCRYPT_HPP
#define AZURE_ENCRYPT_HPP

#include <cstring>

extern "C" {
#include <openssl/aes.h>
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

} // namespace azure_proxy

#endif
