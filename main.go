package main

import (
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/gliderlabs/ssh"
	"github.com/teris-io/shortid"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// ssh-keygen -f "/root/.ssh/known_hosts" -R "[localhost]:2222" 需要这一步

type Session struct {
	session     ssh.Session
	destination string
}

var clients sync.Map

type HTTPHandler struct{
}


// 这个函数处理传入的 HTTP 请求，并将请求转发到客户端指定的目的地。
func (h *HTTPHandler) handleWebhook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	value, ok := clients.Load(id)

	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("client id not found"))
		return
	}

	session := value.(Session)
	req, err := http.NewRequest(r.Method, session.destination, r.Body)
	if err != nil {
		log.Fatal(err)
	}
	// 使用 http.DefaultClient 发送新创建的请求，并获取响应 resp。
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	defer r.Body.Close()
	// 将响应体 resp.Body 的内容复制到 HTTP 响应写入器 w，这样客户端就能收到来自目标服务器的响应。
	io.Copy(w, resp.Body)
}

func startHttpServer() error {
	httpPort := ":5000"
	router := http.NewServeMux()

	handle := &HTTPHandler{}
	router.HandleFunc("/{id}", handle.handleWebhook)
	router.HandleFunc("/{id}/*", handle.handleWebhook)

	return http.ListenAndServe(httpPort, router)
}

func startSSHServer() error {
	sshPort := ":2222"
	handler := &SSHHandler{}

	// 用来处理端口转发请求
	fwhandler := &ssh.ForwardedTCPHandler{}
	server := ssh.Server{
		Addr:    sshPort,
		Handler: handler.handleSSHSession,
		// ServerConfigCallback 用于配置服务器的 SSH 配置，如版本和加密算法。
		ServerConfigCallback: func(ctx ssh.Context) *gossh.ServerConfig {
			cfg := &gossh.ServerConfig{
				ServerVersion: "SSH-2.0-sendit",
			}
			cfg.Ciphers = []string{"chacha20-poly1305@openssh.com"}
			return cfg
		},
		// PublicKeyHandler 用于验证客户端的公钥，这里总是返回 true，表示接受所有公钥。
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			return true
		},
		// 用于处理本地和远程端口转发请求
		LocalPortForwardingCallback: ssh.LocalPortForwardingCallback(func(ctx ssh.Context, dhost string, dport uint32) bool {
			log.Println("Accepted forward", dhost, dport)
			// todo: auth validation
			return true
		}),
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) bool {
			log.Println("attempt to bind", host, port, "granted")
			// todo: auth validation
			return true
		}),
		// 映射，定义了处理特定 SSH 请求的方法。
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpup-forward":        fwhandler.HandleSSHRequest,
			"cancel-tcpip-forward": fwhandler.HandleSSHRequest,
		},
	}
	b, err := os.ReadFile("keys/privatekey.pub")
	if err != nil {
		log.Fatal(err)
	}
	privateKey, err := gossh.ParsePrivateKey(b)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}
	// 将解析的私钥添加到 SSH 服务器，用于身份验证。
	server.AddHostKey(privateKey)
	// 启动 SSH 服务器并监听连接，ListenAndServe 方法会阻塞直到服务器停止
	return server.ListenAndServe()
}

func main() {
	go startSSHServer()
	startHttpServer()
}

type SSHHandler struct {
}

var banner = `
##      ## ######## ########  ##     ##  #######   #######  ##    ## ######## ########  
##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##   ##  ##       ##     ## 
##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##  ##   ##       ##     ## 
##  ##  ## ######   ########  ######### ##     ## ##     ## #####    ######   ########  
##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##  ##   ##       ##   ##   
##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##   ##  ##       ##    ##  
 ###  ###  ######## ########  ##     ##  #######   #######  ##    ## ######## ##     ## 
`

// 这个方法处理 SSH 会话，根据客户端的命令执行不同的操作
// 通过这个 webhook 可以将流量转发到指定的目的地。
// 用户输入目的地后，服务器会生成一个随机端口和一个短链接，用户可以使用这个短链接和相应的 SSH 命令来设置端口转发。
func (h *SSHHandler) handleSSHSession(session ssh.Session) {
	if session.RawCommand() == "tunnel" {
		session.Write([]byte("tunneling traffic..."))
		<-session.Context().Done()
		return
	}

	term := term.NewTerminal(session, "$ ")
	msg := fmt.Sprintf("%s\n\nWelcome to webhooker!\n\nenter webhook destination:\n", banner)
	term.Write([]byte(msg))

	for {
		input, err := term.ReadLine()
		if err != nil {
			log.Fatal()
		}

		generatedPort := randomPort()
		id := shortid.MustGenerate() 
		// 尝试解析用户输入的字符串为 URL 对象
		destination, err := url.Parse(input)
		if err != nil {
			log.Fatal(err)
		}
		// 从 URL 对象中提取主机名和端口。
		host := destination.Host
		// 存储 SSH 会话和目标地址
		internalSession := Session{
			session:     session,
			destination: destination.String(),
		}
		clients.Store(id, internalSession)

		webhookURL := fmt.Sprintf("http://localhost:5000/%s", id)
		// 构造一条包含生成的 webhook URL 和 SSH 命令的字符串，该命令用于设置端口转发
		command := fmt.Sprintf("\nGenerated webhook: %s\n\nCommand to copy:\nssh -R 127.0.0.1:%d:%s localhost -p 2222 tunnel\n", webhookURL, generatedPort, host)
		term.Write([]byte(command))
		return
	}
}

func randomPort() int {
	min := 49152
	max := 65535
	return min + rand.IntN(max-min+1)
}
