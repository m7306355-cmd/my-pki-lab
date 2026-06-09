# Melissa PKI Lab

基于 OpenSSL 和 GmSSL 搭建的私有 PKI 证书管理系统，支持 RSA 和 SM2 双证书链。

## 启动方式

打开 PowerShell 执行：

    . D:\pki\start.ps1

启动后访问：
- 交互网站：http://localhost:5000
- HTTPS 演示：https://localhost:4443
- CRL 服务：http://localhost:8080

## 账号

- 管理员：admin / admin123
- 普通用户：自行注册

## PKI 体系

RSA 证书链：Root CA (RSA 4096) -> Intermediate CA (RSA 2048) -> 终端证书 (RSA 2048)
SM2 证书链：Root CA (SM2) -> Intermediate CA (SM2) -> 终端证书 (SM2)

## 主要功能

- 用户注册登录
- 申请 RSA 或 SM2 证书
- 下载证书文件
- 管理员查看所有证书
- 管理员吊销证书（RSA 和 SM2 均支持真实 CRL 更新）
- CRL 吊销列表在线访问

## 首次使用

导入根证书到系统信任库（管理员 PowerShell）：

    Import-Certificate -FilePath "D:\pki\RSA\Root\root-ca.pem" -CertStoreLocation Cert:\LocalMachine\Root
