package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/kardianos/service"
	"gopkg.in/ini.v1"
)

// 配置结构体
type Config struct {
	NeedAuth bool
	Username string
	Password string
	Port     int
}

// 服务结构体
type program struct {
	config *Config
	exit   chan struct{}
}

// 解析配置文件
func parseConfig(configPath string) (*Config, error) {
	cfg, err := ini.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("无法加载配置文件: %v", err)
	}

	needAuth, err := cfg.Section("Settings").Key("NeedAuth").Bool()
	if err != nil {
		needAuth = false
	}

	port, err := cfg.Section("Settings").Key("Port").Int()
	if err != nil {
		port = 1080 // 默认端口
	}

	return &Config{
		NeedAuth: needAuth,
		Username: cfg.Section("Settings").Key("Username").String(),
		Password: cfg.Section("Settings").Key("Password").String(),
		Port:     port,
	}, nil
}

// 启动服务
func (p *program) Start(s service.Service) error {
	p.exit = make(chan struct{})
	go p.run()
	return nil
}

// 停止服务
func (p *program) Stop(s service.Service) error {
	close(p.exit)
	return nil
}

// 运行SOCKS5代理服务
func (p *program) run() {
	addr := fmt.Sprintf(":%d", p.config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("无法监听端口 %d: %v", p.config.Port, err)
	}
	defer listener.Close()

	fmt.Println("Sock5Lite is running")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-p.exit:
					return
				default:
					log.Printf("接受连接错误: %v", err)
				}
				continue
			}

			go p.handleConnection(conn)
		}
	}()

	<-p.exit
}

// 处理客户端连接
func (p *program) handleConnection(conn net.Conn) {
	defer conn.Close()

	// 协商认证方法
	if err := p.negotiateAuth(conn); err != nil {
		log.Printf("认证协商失败: %v", err)
		return
	}

	// 处理客户端请求
	if err := p.handleClientRequest(conn); err != nil {
		log.Printf("处理请求失败: %v", err)
	}
}

// 协商认证方法
func (p *program) negotiateAuth(conn net.Conn) error {
	buf := make([]byte, 258)

	// 读取客户端支持的认证方法
	n, err := conn.Read(buf[:2])
	if err != nil || n != 2 {
		return fmt.Errorf("读取SOCKS版本错误: %v", err)
	}

	ver := buf[0]
	nmethods := buf[1]

	if ver != 5 {
		return fmt.Errorf("不支持的SOCKS版本: %d", ver)
	}

	n, err = conn.Read(buf[:nmethods])
	if err != nil || n != int(nmethods) {
		return fmt.Errorf("读取认证方法错误: %v", err)
	}

	// 回复认证方法
	if p.config.NeedAuth {
		// 需要用户名密码认证
		conn.Write([]byte{5, 2})
		return p.authenticate(conn)
	} else {
		// 无需认证
		conn.Write([]byte{5, 0})
		return nil
	}
}

// 用户名密码认证
func (p *program) authenticate(conn net.Conn) error {
	buf := make([]byte, 513)

	// 读取认证版本和用户名长度
	n, err := conn.Read(buf[:2])
	if err != nil || n != 2 {
		return fmt.Errorf("读取认证版本错误: %v", err)
	}

	ver := buf[0]
	ulen := buf[1]

	if ver != 1 {
		return fmt.Errorf("不支持的认证版本: %d", ver)
	}

	// 读取用户名
	n, err = conn.Read(buf[:ulen])
	if err != nil || n != int(ulen) {
		return fmt.Errorf("读取用户名错误: %v", err)
	}

	username := string(buf[:ulen])

	// 读取密码长度
	n, err = conn.Read(buf[:1])
	if err != nil || n != 1 {
		return fmt.Errorf("读取密码长度错误: %v", err)
	}

	plen := buf[0]

	// 读取密码
	n, err = conn.Read(buf[:plen])
	if err != nil || n != int(plen) {
		return fmt.Errorf("读取密码错误: %v", err)
	}

	password := string(buf[:plen])

	// 验证用户名和密码
	if username == p.config.Username && password == p.config.Password {
		conn.Write([]byte{1, 0}) // 认证成功
		return nil
	} else {
		conn.Write([]byte{1, 1}) // 认证失败
		return fmt.Errorf("用户名或密码错误")
	}
}