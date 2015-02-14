# azure-http-proxy [![Build Status](https://travis-ci.org/lxrite/azure-http-proxy.svg?branch=master)](https://travis-ci.org/lxrite/azure-http-proxy)

AHP(Azure Http Proxy)是一款高速、安全、轻量级和跨平台的HTTP代理，使用对称加密算法AES对传输的数据进行加密，使用非对称加密算法RSA传输密钥。

HTTP代理对域名的解析是在服务端进行的，所以AHP还能解决本地DNS污染问题。

# 快速开始

## 编译和安装

### 编译器

AHP使用了部分C++11特性，所以要求对编译器的版本有较高要求，下面列出了部分已测试过可以用来编译AHP的编译器

 - Microsoft Visual Studio >= 2013
 - GCC >= 3.8
 - Clang >= 3.2
 - MinGW >= 3.8

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

#### 编译
AHP使用自动化构建工具CMake来实现跨平台构建

 - CMake >= 2.8

Windows下可以使用cmake-gui.exe，Linux和其他类Unix系统可以使用下面的命令编译

    $ cd azure-http-proxy
    $ mkdir build
    $ cd build
    $ cmake ..
    $ make

如果编译成功会生成ahpc（客户端）和ahps（服务端）。
## 配置和运行

未完待续...
