# webhooker
## 基于SSH的Webhook转发
```
|-------------|     |--------------|                |--------------|
| ssh server  | <-- |  http server | <------------- |  stripe      |
|-------------|     |--------------|   post request |--------------|
    |
    |
    |
    |
|-------------|    forward / tunnel   |-------------------------|
|   terminal  |   ------------------> |  local web application  |
|-------------|                       |-------------------------|
```
## SSH Server：
`启动了一个SSH服务器，监听在特定端口（例如:2222）`
## HTTP Server
`用于接收外部的POST请求`
## Webhook URL
`当用户通过SSH连接到服务器并输入命令时，系统会生成一个Webhook URL,这个URL是外部服务发送POST请求的目标地址`
## POST Request
`外部服务会向这个Webhook URL发送POST请求，这些请求会被HTTP服务器接收`
## Forward/Tunnel
`SSH服务器处理端口转发请求，允许从本地Web应用程序转发流量到远程服务器`
## Local Web Application
`本地Web应用程序可以通过SSH隧道安全地接收来自外部服务的请求`
## Terminal
`用户通过SSH连接到服务器，并在终端中输入命令来设置Webhook目的地和启动隧道`

* 用户通过SSH连接到SSH服务器，并输入命令来设置Webhook。
* SSH服务器生成一个Webhook URL，并提示用户使用这个URL。
* 用户的本地Web应用程序准备好接收请求。
* 外部服务向Webhook URL发送POST请求。
* HTTP服务器接收POST请求，并根据配置将请求转发到用户指定的目的地，或者通过SSH隧道将请求转发到用户本地环境。
* 用户的本地Web应用程序接收到请求并进行处理
