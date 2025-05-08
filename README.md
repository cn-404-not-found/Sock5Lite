# Sock5Lite

一个轻量级的SOCKS5代理程序，使用Go语言编写，支持Windows系统。

## 功能特点

- 基本的SOCKS5代理功能
- 支持用户名/密码认证或无认证模式
- 可作为系统服务运行
- 可直接在命令行中运行
- 无需额外运行库，可在Windows 10及以上系统直接运行

## 配置文件

程序使用`Sock5Lite.ini`配置文件，格式如下：

```ini
[Settings]
# 是否需要认证，true为需要认证，false为无需认证
NeedAuth=false

# 认证的用户名和密码，仅在NeedAuth=true时有效
Username=admin
Password=password

# 代理服务器监听端口
Port=1080
```

## 使用方法

### 直接运行

```
Sock5Lite.exe Sock5Lite.ini
```

### 安装为系统服务

```
Sock5Lite.exe --install Sock5Lite.ini
```

## 编译说明

1. 确保已安装Go语言环境（推荐Go 1.16或更高版本）
2. 克隆或下载本项目代码
3. 在项目目录中执行以下命令：

```
go mod tidy
go build -o Sock5Lite.exe main.go
```

## 注意事项

- 程序运行时会显示"Sock5Lite is running"提示
- 作为系统服务运行时，可以通过Windows服务管理器管理服务
- 如需卸载服务，可使用Windows服务管理器或sc命令