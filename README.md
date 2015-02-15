# azure-http-proxy [![Build Status](https://travis-ci.org/lxrite/azure-http-proxy.svg?branch=master)](https://travis-ci.org/lxrite/azure-http-proxy)

## 简介

AHP(Azure Http Proxy)是一款高速、安全、轻量级和跨平台的HTTP代理，使用对称加密算法AES对传输的数据进行加密，使用非对称加密算法RSA传输密钥。

HTTP代理对域名的解析是在服务端进行的，所以AHP还能解决本地DNS污染问题。

## 编译和安装

### 编译器

AHP使用了部分C++11特性，所以要求对编译器的版本有较高要求，下面列出了部分已测试过可以用来编译AHP的编译器

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
## 配置和运行

如果你要运行的是服务端，那么你首先需要生成一对RSA密钥对，AHP支持任意长度不小于1024位的RSA密钥。下面的命令使用openssl生成2048位的私钥和公钥

    openssl genrsa -out rsa_private_key.pem 204
    openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

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
cipher               | 加密算法             | 是               | "aes-256-ofb" |
timeout              | 超时时间（秒）       | 否               | 240           |
workers              | 并发工作线程数       | 否               | 2             |

## 运行

确定配置无误后就可以运行AHP了。

### 运行服务端

 Linux或其他类Unix系统
 
    ./ahps
 
 Windows
 
    ahps.exe
 
### 运行客户端

Linux或其他类Unix系统

    ./ahpc
 
Windows
 
    ahpc.exe
 
 Enjoy!
 
