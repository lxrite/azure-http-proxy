# azure-http-proxy [![Build Status](https://travis-ci.org/lxrite/azure-http-proxy.svg?branch=master)](https://travis-ci.org/lxrite/azure-http-proxy)

## 简介

AHP(Azure Http Proxy)是一款高速、安全、轻量级和跨平台的HTTP代理，使用对称加密算法AES对传输的数据进行加密，使用非对称加密算法RSA传输密钥。

## 特性
 - 一连接一密钥，AHP会对每个连接使用一个随机生成的密钥和初始化向量，避免重复使用同一密钥
 - 使用非对称加密算法RSA传输密钥，只需对客户端公开RSA公钥
 - 对目标域名的解析在服务端进行，可以解决本地DNS污染的问题
 - 服务端同时支持多种数据加密方式，数据加密方式可由客户端任意指定，客户端可以权衡机器性能以及安全需求选择合适的加密方式
 - 多线程并发处理，充分利用多处理器的优势，能同时处理成千上万的并发连接
 - 多用户支持，允许为每个用户使用独立的帐号和密码

## 编译和安装

Windows平台可以从 https://github.com/lxrite/azure-http-proxy/releases 下载已经编译好的(win32-binary.zip)。

### 编译器

AHP使用了部分C++11特性，所以对编译器的版本有较高要求，下面列出了部分已测试过可以用来编译AHP的编译器

 - Microsoft Visual Studio >= 2013
 - GCC >= 4.8
 - Clang >= 3.2
 - MinGW >= 4.8

参考：http://en.cppreference.com/w/cpp/compiler_support

### 安装依赖

AHP依赖Boost和OpenSSL库，且要求Boost库版本不低于1.52

绝大多数Linux发行版都可以通过包管理安装Boost和OpenSSL

#### Ubuntu

    $ apt-get install libboost-system-dev
    $ apt-get install libboost-regex-dev
    $ apt-get install libssl-dev

#### Fedora

    $ yum install boost-devel
    $ yum install boost-system
    $ yum install boost-regex
    $ yum install openssl
    $ yum install openssl-devel

Windows则需要自己编译Boost库，而OpenSSL库可以从 https://www.openssl.org/related/binaries.html 下载到编译好的。

### 编译
AHP使用自动化构建工具CMake来实现跨平台构建

 - CMake >= 2.8

Windows下可以使用cmake-gui.exe，Linux或其他类Unix系统可以使用下面的命令编译

    $ cd azure-http-proxy
    $ mkdir build
    $ cd build
    $ cmake ..
    $ make

如果编译成功会生成ahpc（客户端）和ahps（服务端）。

OpenWrt/LEDE 编译参考 [openwrt-ahp](https://github.com/lxrite/openwrt-ahp)

## 配置和运行

完整的配置示例见这里： https://github.com/lxrite/azure-http-proxy/tree/master/example

注意：不要使用示例配置中的RSA私钥和公钥，因为私钥一公开就是不安全的了。

如果你要运行的是服务端，那么你首先需要生成一对RSA密钥对，AHP支持任意长度不小于1024位的RSA密钥。下面的命令使用openssl生成2048位的私钥和公钥

    $ openssl genrsa -out rsa_private_key.pem 2048
    $ openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

服务端保留私钥并将公钥告诉客户端。

### 配置服务端 

编辑server.json文件，Windows下应将此文件放到ahps.exe同目录下，Linux或其他类Unix系统将此文件放到~/.ahps/server.json。

    {
      "bind_address": "0.0.0.0",
      "listen_port": 8090,
      "rsa_private_key": "-----BEGIN RSA PRIVATE KEY----- ...... -----END RSA PRIVATE KEY-----",
      "timeout": 240,
      "workers": 4,
      "auth": true,
      "users": [
        {
          "username": "username1",
          "password": "password1"
        },
        {
          "username": "foobar",
          "password": "bazqux"
        }
      ]
    }

字段名          | 描述               | 是否必选         | 默认值    |
----------------|--------------------|------------------|-----------|
bind_address    | 服务端绑定的IP地址 | 否               | "0.0.0.0" |
listen_port     | 服务端绑定的端口   | 否               | 8090      |
rsa_private_key | RSA私钥            | 是               | 无        |
timeout         | 超时时间（秒）     | 否               | 240       |
workers         | 并发工作线程数     | 否               | 4         |
auth            | 启用代理身份验证   | 否               | false     |
users           | 用户列表           | auth为true时必选 | 无        |

### 配置客户端

编辑client.json文件，Windows下应将此文件放到ahpc.exe或ahpc-gui.exe同目录下，Linux或其他类Unix系统将此文件放到~/.ahpc/client.json。

    {
      "proxy_server_address": "127.0.0.1",
      "proxy_server_port": 8090,
      "bind_address": "127.0.0.1",
      "listen_port": 8089,
      "rsa_public_key": "-----BEGIN PUBLIC KEY----- ...... -----END PUBLIC KEY-----",
      "cipher": "aes-256-ofb",
      "timeout": 240,
      "workers": 2
    }

字段名               | 描述                 | 是否必选         | 默认值        |
---------------------|----------------------|------------------|---------------|
proxy_server_address | 服务端的IP地址或域名 | 是               | 无            |
proxy_server_port    | 服务端的端口         | 是               | 无            |
bind_address         | 客户端绑定的IP地址   | 否               | "127.0.0.1"   |
listen_port          | 客户端的监听端口     | 否               | 8089          |
rsa_public_key       | RSA公钥              | 是               | 无            |
cipher               | 加密方法             | 否               | "aes-256-ofb" |
timeout              | 超时时间（秒）       | 否               | 240           |
workers              | 并发工作线程数       | 否               | 2             |

#### 支持的加密方法

 - aes-xyz-cfb
 - aes-xyz-cfb8
 - aes-xyz-cfb1
 - aes-xyz-ofb
 - aes-xyz-ctr

中间的xyz可以为128、192或256。

## 运行

确定配置无误后就可以运行AHP了。

### 运行服务端

 Linux或其他类Unix系统
 
    $ ./ahps
 
 Windows
 
    $ ahps.exe
 
### 运行客户端

Linux或其他类Unix系统

    $ ./ahpc
 
Windows
 
    $ ahpc.exe
 
 Enjoy!
 
