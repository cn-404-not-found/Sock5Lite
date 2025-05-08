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

// 处理客户端请求
func (p *program) handleClientRequest(conn net.Conn) error {
	buf := make([]byte, 4096)

	// 读取请求头
	n, err := conn.Read(buf[:4])
	if err != nil || n != 4 {
		return fmt.Errorf("读取请求头错误: %v", err)
	}

	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]

	if ver != 5 {
		return fmt.Errorf("不支持的SOCKS版本: %d", ver)
	}

	if cmd != 1 {
		// 只支持CONNECT命令
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("不支持的命令: %d", cmd)
	}

	// 解析目标地址
	var host string
	var port int

	switch atyp {
	case 1: // IPv4
		n, err = conn.Read(buf[:4])
		if err != nil || n != 4 {
			return fmt.Errorf("读取IPv4地址错误: %v", err)
		}
		host = net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()

	case 3: // 域名
		n, err = conn.Read(buf[:1])
		if err != nil || n != 1 {
			return fmt.Errorf("读取域名长度错误: %v", err)
		}
		addrLen := buf[0]

		n, err = conn.Read(buf[:addrLen])
		if err != nil || n != int(addrLen) {
			return fmt.Errorf("读取域名错误: %v", err)
		}
		host = string(buf[:addrLen])

	case 4: // IPv6
		n, err = conn.Read(buf[:16])
		if err != nil || n != 16 {
			return fmt.Errorf("读取IPv6地址错误: %v", err)
		}
		host = net.IP(buf[:16]).String()

	default:
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("不支持的地址类型: %d", atyp)
	}

	// 读取端口
	n, err = conn.Read(buf[:2])
	if err != nil || n != 2 {
		return fmt.Errorf("读取端口错误: %v", err)
	}
	port = int(binary.BigEndian.Uint16(buf[:2]))

	// 连接目标服务器
	target, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("连接目标服务器错误: %v", err)
	}
	defer target.Close()

	// 发送连接成功响应
	localAddr := target.LocalAddr().(*net.TCPAddr)
	ip := localAddr.IP.To4()
	if ip == nil {
		ip = localAddr.IP.To16()
	}

	response := []byte{5, 0, 0}
	if ip.To4() != nil {
		response = append(response, 1)
	} else {
		response = append(response, 4)
	}

	response = append(response, ip...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(localAddr.Port))
	response = append(response, portBytes...)

	_, err = conn.Write(response)
	if err != nil {
		return fmt.Errorf("发送响应错误: %v", err)
	}

	// 开始转发数据
	errc := make(chan error, 2)

	go func() {
		_, err := io.Copy(target, conn)
		errc <- err
	}()

	go func() {
		_, err := io.Copy(conn, target)
		errc <- err
	}()

	<-errc
	return nil
}

func main() {
	// 解析命令行参数
	install := flag.String("install", "", "安装为系统服务")
	flag.Parse()

	// 获取配置文件路径
	var configPath string
	if *install != "" {
		configPath = *install
	} else if len(flag.Args()) > 0 {
		configPath = flag.Args()[0]
	} else {
		// 默认配置文件路径
		execPath, err := os.Executable()
		if err != nil {
			log.Fatalf("获取可执行文件路径失败: %v", err)
		}
		configPath = strings.TrimSuffix(execPath, ".exe") + ".ini"
	}

	// 解析配置文件
	config, err := parseConfig(configPath)
	if err != nil {
		log.Fatalf("解析配置文件失败: %v", err)
	}

	// 创建服务
	prg := &program{config: config}
	svcConfig := &service.Config{
		Name:        "Sock5Lite",
		DisplayName: "Sock5Lite SOCKS5 Proxy",
		Description: "A lightweight SOCKS5 proxy service",
	}

	svc, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatalf("创建服务失败: %v", err)
	}

	// 安装服务
	if *install != "" {
		err = svc.Install()
		if err != nil {
			log.Fatalf("安装服务失败: %v", err)
		}
		fmt.Println("服务安装成功")
		return
	}

	// 直接运行
	err = svc.Run()
	if err != nil {
		log.Fatalf("运行服务失败: %v", err)
	}
}