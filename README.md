# Melissa's PKI Lab

使用 OpenSSL + Python 搭建的完整 PKI 证书体系。

## 证书链架构
Root CA (RSA 4096, 10年)
        └── Intermediate CA (RSA 2048, 5年)
                          └── Server Certificate (RSA 2048, 1年)
## 技术栈

- **OpenSSL** - 生成密钥对和 X.509 证书
- **Python** - 启动 HTTPS 服务器
- **证书格式** - PEM (Base64 + DER)
- **私钥格式** - PKCS#1
- **CSR 格式** - PKCS#10

## 如何运行

1. 生成服务器私钥: 不要将私钥上传
2. 启动服务器：`python server.py`
3. 访问：https://localhost:4443

## 文件说明

| 文件 | 说明 |
|------|------|
| root-ca.pem | 根 CA 证书 |
| intermediate-ca.pem | 中间 CA 证书 |
| server.pem | 服务器证书 |
| cert-chain.pem | 证书链（服务器证书 + 中间证书）|
| server.py | HTTPS 服务器脚本 |
| index.html | 欢迎页面 |
