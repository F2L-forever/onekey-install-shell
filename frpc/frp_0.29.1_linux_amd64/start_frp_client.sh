#!/usr/bin/env bash
#切换当前目录
#echo '921011' | sudo 

cd `dirname "$0"`

function checkHost(){
    if [ ! -n "$host" ]; then
      read -p "域名前缀不能为空，请重新输入:" host
      checkHost
    else
       echo "$host"
    fi 
}

function checkPort(){
    if [ ! -n "$port" ]; then
      read -p "端口不能为空，请重新输入:" port
      checkPort
    elif [ "$port" -gt 0 ] 2>/dev/null ;then 
       #判断进程是否存在
       #netstat -aln|grep $port

        echo ""
    else
       read -p "端口必须为数字，请重新输入:" port
       checkPort
    fi 

}


read -p "请输入域名前缀:" host
checkHost

read -p "请输入端口:" port
checkPort

#写入配置文件
frpcConf=./bin/frpc.ini
logfile=./logs/frpc.log

cat > $frpcConf <<EOF
# [common] is integral section
[common]
# A literal address or host name for IPv6 must be enclosed
# in square brackets, as in "[::1]:80", "[ipv6-host]:http" or "[ipv6-host%zone]:80"
server_addr = 120.25.225.59
server_port = 7000
# if you want to connect frps by http proxy or socks5 proxy, you can set http_proxy here or in global environment variables
# it only works when protocol is tcp
# http_proxy = http://user:passwd@192.168.1.128:8080
# http_proxy = socks5://user:passwd@192.168.1.128:1080
# console or real logFile path like ./frpc.log
log_file = $logfile
# trace, debug, info, warn, error
log_level = info
log_max_days = 3
# disable log colors when log_file is console, default is false
#disable_log_color = false
# for authentication
token = ZpZy8AAS6EkuGsfz
# Admin assets directory. By default, these assets are bundled with frpc.
# assets_dir = ./static
# connections will be established in advance, default value is zero
pool_count = 50
# if tcp stream multiplexing is used, default is true, it must be same with frps
tcp_mux = true
###############################
# set admin address for control frpc's action by http api such as reload
#admin_addr = 127.0.0.1
#修改此处
#admin_port = 7400
#修改此处
#admin_user = admin
#修改此处
#admin_pwd = admin
# your proxy name will be changed to {user}.{proxy}
#修改此处
user = $host
# decide if exit program when first login failed, otherwise continuous relogin to frps
# default is true
login_fail_exit = true
# communication protocol used to connect to server
# now it supports tcp and kcp and websocket, default is tcp
protocol = tcp
# if tls_enable is true, frpc will connect frps by tls
#tls_enable = true
# specify a dns server, so frpc will use this instead of default one
# dns_server = 8.8.8.8
# proxy names you want to start seperated by ','
# default is empty, means all proxies
# start = ssh,dns
# heartbeat configure, it's not recommended to modify the default value
# the default value of heartbeat_interval is 10 and heartbeat_timeout is 90
# heartbeat_interval = 30
# heartbeat_timeout = 90
#############################################################################################
# 'ssh' is the unique proxy name
# if user in [common] section is not empty, it will be changed to {user}.{proxy} such as 'test.ssh'
#[ssh]
# tcp | udp | http | https | stcp | xtcp, default is tcp
#type = tcp
#local_ip = 127.0.0.1
#local_port = 22
# true or false, if true, messages between frps and frpc will be encrypted, default is false
#use_encryption = false
# if true, message will be compressed
#use_compression = false
# remote port listen by frps
#remote_port = 6001
# frps will load balancing connections for proxies in same group
#group = test_group
# group should have same group key
#group_key = 123456
# enable health check for the backend service, it support 'tcp' and 'http' now
# frpc will connect local service's port to detect it's healthy status
#health_check_type = tcp
# health check connection timeout
#health_check_timeout_s = 3
# if continuous failed in 3 times, the proxy will be removed from frps
#health_check_max_failed = 3
# every 10 seconds will do a health check
#health_check_interval_s = 10
#############################################################################################
#[ssh_random]
#type = tcp
#local_ip = 127.0.0.1
#local_port = 22
# if remote_port is 0, frps will assign a random port for you
#remote_port = 0
#############################################################################################
# if you want to expose multiple ports, add 'range:' prefix to the section name
# frpc will generate multiple proxies such as 'tcp_port_6010', 'tcp_port_6011' and so on.
#[range:tcp_port]
#type = tcp
#local_ip = 127.0.0.1
#local_port = 6010-6020,6022,6024-6028
#remote_port = 6010-6020,6022,6024-6028
#use_encryption = false
#use_compression = false
##############################################################################################
#[dns]
#type = udp
#local_ip = 114.114.114.114
#local_port = 53
#remote_port = 6002
#use_encryption = false
#use_compression = false
#############################################################################################
#[range:udp_port]
#type = udp
#local_ip = 127.0.0.1
#local_port = 6010-6020
#remote_port = 6010-6020
#use_encryption = false
#use_compression = false
#############################################################################################
# Resolve your domain names to [server_addr] so you can use http://web01.ngrok.qqmylove.top to browse web01 and http://web02.ngrok.qqmylove.top to browse web02
[http]
type = http
local_ip = 127.0.0.1
#修改此处
local_port =$port
use_encryption = true
use_compression = true
# http username and password are safety certification for http protocol
# if not set, you can access this custom_domains without certification
#http_user = admin
#http_pwd = admin
# if domain for frps is frps.com, then you can access [web01] proxy by URL http://test.frps.com
#修改此处
subdomain =$host
# locations is only available for http type
#locations = /,/pic
#host_header_rewrite = example.com
# params with prefix "header_" will be used to update http request headers
#header_X-From-Where = frp
#health_check_type = http
# frpc will send a GET http request '/status' to local http service
# http service is alive when it return 2xx http response code
#health_check_url = /status
#health_check_interval_s = 10
#health_check_max_failed = 3
#health_check_timeout_s = 3
#############################################################################################
#[web02]
#type = https
#local_ip = 127.0.0.1
#local_port = 8000
#use_encryption = false
#use_compression = false
#subdomain = web01
#custom_domains = web02.ngrok.qqmylove.top
# if not empty, frpc will use proxy protocol to transfer connection info to your local service
# v1 or v2 or empty
#proxy_protocol_version = v2
#############################################################################################
#[plugin_unix_domain_socket]
#type = tcp
#remote_port = 6003
# if plugin is defined, local_ip and local_port is useless
# plugin will handle connections got from frps
#plugin = unix_domain_socket
# params with prefix "plugin_" that plugin needed
#plugin_unix_path = /var/run/docker.sock
#############################################################################################
#[plugin_http_proxy]
#type = tcp
#remote_port = 6004
#plugin = http_proxy
#plugin_http_user = abc
#plugin_http_passwd = abc
#[plugin_socks5]
#type = tcp
#remote_port = 6005
#plugin = socks5
#plugin_user = abc
#plugin_passwd = abc
#
#[plugin_static_file]
#type = tcp
#remote_port = 6006
#plugin = static_file
#plugin_local_path = /var/www/blog
#plugin_strip_prefix = static
#plugin_http_user = abc
#plugin_http_passwd = abc
#############################################################################################
#[plugin_https2http]
#type = https
#custom_domains = test.ngrok.qqmylove.top
#plugin = https2http
#plugin_local_addr = 127.0.0.1:80
#plugin_crt_path = ./server.crt
#plugin_key_path = ./server.key
#plugin_host_header_rewrite = 127.0.0.1
#plugin_header_X-From-Where = frp
#############################################################################################
#[secret_tcp]
# If the type is secret tcp, remote_port is useless
# Who want to connect local port should deploy another frpc with stcp proxy and role is visitor
#type = stcp
# sk used for authentication for visitors
#sk = abcdefg
#local_ip = 127.0.0.1
#local_port = 22
#use_encryption = false
#use_compression = false
#############################################################################################
# user of frpc should be same in both stcp server and stcp visitor
#[secret_tcp_visitor]
# frpc role visitor -> frps -> frpc role server
#role = visitor
#type = stcp
# the server name you want to visitor
#server_name = secret_tcp
#sk = abcdefg
# connect this address to visitor stcp server
#bind_addr = 127.0.0.1
#bind_port = 9000
#use_encryption = false
#use_compression = false
#############################################################################################
#[p2p_tcp]
#type = xtcp
#sk = abcdefg
#local_ip = 127.0.0.1
#local_port = 22
#use_encryption = false
#use_compression = false
#############################################################################################
#[p2p_tcp_visitor]
#role = visitor
#type = xtcp
#server_name = p2p_tcp
#sk = abcdefg
#bind_addr = 127.0.0.1
#bind_port = 9001
#use_encryption = false
#use_compression = false
#############################################################################################


EOF

echo 请使用 http://$host.ngrok.qqmylove.top 访问你的服务

nohup ./bin/frpc -c $frpcConf > ./logs/frpc.log 2>&1 &