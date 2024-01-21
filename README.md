# azure-http-proxy

## 简介

AHP(Azure Http Proxy)是一款高速、安全、轻量级和跨平台的HTTP代理，使用对称加密算法AES对传输的数据进行加密，使用非对称加密算法RSA传输密钥。

## 特性
 - 一连接一密钥，AHP会对每个连接使用一个随机生成的密钥和初始化向量，避免重复使用同一密钥
 - 使用非对称加密算法RSA传输密钥，只需对客户端公开RSA公钥
 - 对目标域名的解析在服务端进行，可以解决本地DNS污染的问题
 - 服务端同时支持多种数据加密方式，数据加密方式可由客户端任意指定，客户端可以权衡机器性能以及安全需求选择合适的加密方式
 - 多线程并发处理，充分利用多处理器的优势，能同时处理成千上万的并发连接
 - 多用户支持，允许为每个用户使用独立的auth_key `(1.1及以上版本)`

## 编译和安装

### 拉取代码
``` shell
$ git clone --recursive https://github.com/lxrite/azure-http-proxy.git
```

### 编译器

AHP使用了部分C++17特性，所以对编译器的版本有较高要求，下面列出了部分已测试过可以用来编译AHP的编译器

 - Microsoft Visual Studio >= 2017
 - GCC >= 7.3
 - Clang >= 6.0

### 编译
AHP使用自动化构建工具CMake来实现跨平台构建

 - CMake >= 2.8

```shell
$ cd azure-http-proxy
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Release ..
$ cmake --build .
```

如果编译成功会生成ahpc（客户端）和ahps（服务端）。

OpenWrt/LEDE 编译参考 [openwrt-ahp](https://github.com/lxrite/openwrt-ahp)

## 配置和运行

完整的配置示例见这里： https://github.com/lxrite/azure-http-proxy/tree/master/example

注意：不要使用示例配置中的RSA私钥和公钥，因为私钥一公开就是不安全的了。

如果你要运行的是服务端，那么你首先需要生成一对RSA密钥对，AHP支持任意长度不小于1024位的RSA密钥。下面的命令使用openssl生成2048位的私钥和公钥
```shell
$ openssl genrsa -out rsa_private_key.pem 2048
$ openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
```

服务端保留私钥并将公钥告诉客户端。

### 配置服务端 

编辑`server.json`文件
```json
{
  "bind_address": "0.0.0.0",
  "listen_port": 8090,
  "rsa_private_key": "-----BEGIN RSA PRIVATE KEY----- ...... -----END RSA PRIVATE KEY-----",
  "timeout": 240,
  "workers": 4,
  "auth": true,
  "auth_key_list": [
    "testing_key",
    "Bob",
    "Alice"
  ]
}
```

字段名          | 描述               | 是否必选         | 默认值    |
----------------|--------------------|------------------|-----------|
bind_address    | 服务端绑定的IP地址 | 否               | "0.0.0.0" |
listen_port     | 服务端绑定的端口   | 否               | 8090      |
rsa_private_key | RSA私钥          | 是               | 无        |
timeout         | 超时时间（秒）     | 否               | 240       |
workers         | 并发工作线程数     | 否               | 4         |
auth            | 启用代理身份验证   | 否               | false     |
auth_key_list   | auth_key列表     | auth为true时必选  | 无        |

### 配置客户端

编辑`client.json`文件
```json
{
  "proxy_server_address": "127.0.0.1",
  "proxy_server_port": 8090,
  "bind_address": "127.0.0.1",
  "listen_port": 8089,
  "rsa_public_key": "-----BEGIN PUBLIC KEY----- ...... -----END PUBLIC KEY-----",
  "cipher": "aes-256-cfb",
  "timeout": 240,
  "workers": 2,
  "auth_key": "testing_key"
}
```

字段名               | 描述                 | 是否必选         | 默认值        |
---------------------|----------------------|------------------|---------------|
proxy_server_address | 服务端的IP地址或域名 | 是               | 无            |
proxy_server_port    | 服务端的端口         | 是               | 无            |
bind_address         | 客户端绑定的IP地址   | 否               | "127.0.0.1"   |
listen_port          | 客户端的监听端口     | 否               | 8089          |
rsa_public_key       | RSA公钥              | 是               | 无            |
cipher               | 加密方法             | 否               | "aes-256-cfb" |
timeout              | 超时时间（秒）       | 否               | 240           |
workers              | 并发工作线程数       | 否               | 2             |
auth_key             | 用于身份验证的字符串  | 否               | 值为空字符串或没有这个字段时，请求不携带auth_key，仅当server的auth为false时才能成功建立连接|

#### 支持的加密方法

 - aes-xyz-cfb
 - <del>aes-xyz-cfb8</del> (自1.2版本开始不再支持)
 - <del>aes-xyz-cfb1</del> (自1.2版本开始不再支持)
 - aes-xyz-ofb
 - aes-xyz-ctr

中间的xyz可以为128、192或256。

## 运行

确定配置无误后就可以运行AHP了。

### 运行服务端

Linux或其他类Unix系统
```shell
$ ./ahps -c server.json
```

Windows
```shell
$ ahps.exe -c server.json
``` 

### 运行客户端

Linux或其他类Unix系统
```shell
$ ./ahpc -c client.json
```

Windows
```shell
$ ahpc.exe -c client.json
```

## 使用Docker
```shell
# 使用拉取到本地的源码进行构建
docker build . -t lxrite/azure-http-proxy
# 或者使用URL自动拉取源码构建
docker build -t lxrite/azure-http-proxy https://github.com/lxrite/azure-http-proxy.git

# 启动 ahps
docker run -d -p 8090:8090 --mount type=bind,source=$PWD/server.json,target=/data/ahp/server.json lxrite/azure-http-proxy ahps -c /data/ahp/server.json
```
