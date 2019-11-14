#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#===============================================================================================
#   System Required:  CentOS Debian or Ubuntu (32bit/64bit)
#   Description:  A tool to auto-compile & install frps on Linux
#   Author: Clang
#   Intro:  http://koolshare.cn/forum-72-1.html
#===============================================================================================

version="0.29.1"

soft_name="frp"

program_name="frps"
client_program_name="frpc"

str_program_dir="/usr/local/${soft_name}/${program_name}"
client_str_program_dir="/usr/local/${soft_name}/${client_program_name}"

program_init="/etc/init.d/${program_name}"

program_config_file="frps.ini"
client_program_config_file="frpc.ini"

ver_file="/tmp/.frp_ver.sh"
program_version_link="https://raw.githubusercontent.com/F2L-forever/onekey-install-shell/master/frps/version.sh"
str_install_shell=https://raw.githubusercontent.com/F2L-forever/onekey-install-shell/master/frps/install-frps.sh
shell_update(){
    fun_clangcn "clear"
    echo "Check updates for shell..."
    remote_shell_version=`wget --no-check-certificate -qO- ${str_install_shell} | sed -n '/'^version'/p' | cut -d\" -f2`
    if [ ! -z ${remote_shell_version} ]; then
        if [[ "${version}" != "${remote_shell_version}" ]];then
            echo -e "${COLOR_GREEN}Found a new version,update now!!!${COLOR_END}"
            echo
            echo -n "Update shell ..."
            if ! wget --no-check-certificate -qO $0 ${str_install_shell}; then
                echo -e " [${COLOR_RED}failed${COLOR_END}]"
                echo
                exit 1
            else
                echo -e " [${COLOR_GREEN}OK${COLOR_END}]"
                echo
                echo -e "${COLOR_GREEN}Please Re-run${COLOR_END} ${COLOR_PINK}$0 ${clang_action}${COLOR_END}"
                echo
                exit 1
            fi
            exit 1
        fi
    fi
}
fun_clangcn(){
    local clear_flag=""
    clear_flag=$1
    if [[ ${clear_flag} == "clear" ]]; then
        clear
    fi
    echo ""
    echo "+---------------------------------------------------------+"
    echo "|        frps for Linux Server, Written by Clang          |"
    echo "+---------------------------------------------------------+"
    echo "|     A tool to auto-compile & install frps on Linux      |"
    echo "+---------------------------------------------------------+"
    echo "|    Intro: http://koolshare.cn/thread-65379-1-1.html     |"
    echo "+---------------------------------------------------------+"
    echo ""
}
fun_set_text_color(){
    COLOR_RED='\E[1;31m'
    COLOR_GREEN='\E[1;32m'
    COLOR_YELOW='\E[1;33m'
    COLOR_BLUE='\E[1;34m'
    COLOR_PINK='\E[1;35m'
    COLOR_PINKBACK_WHITEFONT='\033[45;37m'
    COLOR_GREEN_LIGHTNING='\033[32m \033[05m'
    COLOR_END='\E[0m'
}
# Check if user is root
rootness(){
    if [[ $EUID -ne 0 ]]; then
        fun_clangcn
        echo "Error:This script must be run as root!" 1>&2
        exit 1
    fi
}
get_char(){
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}
# Check OS
checkos(){
    if grep -Eqi "CentOS" /etc/issue || grep -Eq "CentOS" /etc/*-release; then
        OS=CentOS
    elif grep -Eqi "Debian" /etc/issue || grep -Eq "Debian" /etc/*-release; then
        OS=Debian
    elif grep -Eqi "Ubuntu" /etc/issue || grep -Eq "Ubuntu" /etc/*-release; then
        OS=Ubuntu
    elif grep -Eqi "Deepin" /etc/issue || grep -Eq "Deepin" /etc/*-release; then
        OS=Deepin
    else
        echo "Not support OS, Please reinstall OS and retry!"
        exit 1
    fi
}
# Get version
getversion(){
    if [[ -s /etc/redhat-release ]];then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}
# CentOS version
centosversion(){
    local code=$1
    local version="`getversion`"
    local main_ver=${version%%.*}
    if [ $main_ver == $code ];then
        return 0
    else
        return 1
    fi
}
# Check OS bit
check_os_bit(){
    ARCHS=""
    if [[ `getconf WORD_BIT` = '32' && `getconf LONG_BIT` = '64' ]] ; then
        Is_64bit='y'
        ARCHS="amd64"
    else
        Is_64bit='n'
        ARCHS="386"
    fi
}
check_centosversion(){
if centosversion 5; then
    echo "Not support CentOS 5.x, please change to CentOS 6,7 or Debian or Ubuntu and try again."
    exit 1
fi
}
# Disable selinux
disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}
pre_install_packs(){
    local wget_flag=''
    local killall_flag=''
    local netstat_flag=''
    wget --version > /dev/null 2>&1
    wget_flag=$?
    killall -V >/dev/null 2>&1
    killall_flag=$?
    netstat --version >/dev/null 2>&1
    netstat_flag=$?
    if [[ ${wget_flag} -gt 1 ]] || [[ ${killall_flag} -gt 1 ]] || [[ ${netstat_flag} -gt 6 ]];then
        echo -e "${COLOR_GREEN} Install support packs...${COLOR_END}"
        if [ "${OS}" == 'CentOS' ]; then
            yum install -y wget psmisc net-tools
        else
            apt-get -y update && apt-get -y install wget psmisc net-tools
        fi
    fi
}
# Random password
fun_randstr(){
    strNum=$1
    [ -z "${strNum}" ] && strNum="16"
    strRandomPass=""
    strRandomPass=`tr -cd '[:alnum:]' < /dev/urandom | fold -w ${strNum} | head -n1`
    echo ${strRandomPass}
}
fun_get_version(){
    rm -f ${ver_file}
    if ! wget --no-check-certificate -qO ${ver_file} ${program_version_link}; then
        echo -e "${COLOR_RED}Failed to download version.sh${COLOR_END}"
    fi
    if [ -s ${ver_file} ]; then
        [ -x ${ver_file} ] && chmod +x ${ver_file}
        . ${ver_file}
    fi
    if [ -z ${FRPS_VER} ] || [ -z ${FRPS_INIT} ] || [ -z ${github_download_url} ]; then
        echo -e "${COLOR_RED}Error: ${COLOR_END}Get Program version failed!"
        exit 1
    fi
}
fun_getServer(){
    def_server_url="github"
    echo ""
    echo -e "Please select ${program_name} download url:"
    echo -e "[1].github (default)"
    read -p "Enter your choice (1 or exit. default [${def_server_url}]): " set_server_url
    [ -z "${set_server_url}" ] && set_server_url="${def_server_url}"
    case "${set_server_url}" in
        1|[Aa][Ll][Ii][Yy][Uu][Nn])
            program_download_url=${github_download_url}
            ;;
        [eE][xX][iI][tT])
            exit 1
            ;;
        *)
            program_download_url=${github_download_url}
            ;;
    esac
    echo "---------------------------------------"
    echo "Your select: ${set_server_url}"
    echo "---------------------------------------"
}
fun_getVer(){
    echo -e "Loading network version for ${program_name}, please wait..."
    program_latest_filename="frp_${FRPS_VER}_linux_${ARCHS}.tar.gz"
    program_latest_file_url="${program_download_url}/v${FRPS_VER}/${program_latest_filename}"
    if [ -z "${program_latest_filename}" ]; then
        echo -e "${COLOR_RED}Load network version failed!!!${COLOR_END}"
    else
        echo -e "${program_name} Latest release file ${COLOR_GREEN}${program_latest_filename}${COLOR_END}"
    fi
}
fun_download_file(){
    # download
    if [ ! -s ${str_program_dir}/${program_name} ]; then
        rm -fr ${program_latest_filename} frp_${FRPS_VER}_linux_${ARCHS}
        if ! wget --no-check-certificate -q ${program_latest_file_url} -O ${program_latest_filename}; then
            echo -e " ${COLOR_RED}failed${COLOR_END}"
            exit 1
        fi
        tar xzf ${program_latest_filename}

        mv frp_${FRPS_VER}_linux_${ARCHS}/frps ${str_program_dir}/${program_name}

        mv frp_${FRPS_VER}_linux_${ARCHS}/frpc ${client_str_program_dir}/${client_program_name}

        rm -fr ${program_latest_filename} frp_${FRPS_VER}_linux_${ARCHS}
    fi
    chown root:root -R ${str_program_dir}
    if [ -s ${str_program_dir}/${program_name} ]; then
        [ ! -x ${str_program_dir}/${program_name} ] && chmod 755 ${str_program_dir}/${program_name}
        [ ! -x ${client_str_program_dir}/${client_program_name} ] && chmod 755 ${client_str_program_dir}/${client_program_name}
    else
        echo -e " ${COLOR_RED}failed${COLOR_END}"
        exit 1
    fi
}
function __readINI() {
 INIFILE=$1; SECTION=$2; ITEM=$3
 _readIni=`awk -F '=' '/\['$SECTION'\]/{a=1}a==1&&$1~/'$ITEM'/{print $2;exit}' $INIFILE`
echo ${_readIni}
}
# Check port
fun_check_port(){
    port_flag=""
    strCheckPort=""
    input_port=""
    port_flag="$1"
    strCheckPort="$2"
    if [ ${strCheckPort} -ge 1 ] && [ ${strCheckPort} -le 65535 ]; then
        checkServerPort=`netstat -ntulp | grep "\b:${strCheckPort}\b"`
        if [ -n "${checkServerPort}" ]; then
            echo ""
            echo -e "${COLOR_RED}Error:${COLOR_END} Port ${COLOR_GREEN}${strCheckPort}${COLOR_END} is ${COLOR_PINK}used${COLOR_END},view relevant port:"
            netstat -ntulp | grep "\b:${strCheckPort}\b"
            fun_input_${port_flag}_port
        else
            input_port="${strCheckPort}"
        fi
    else
        echo "Input error! Please input correct numbers."
        fun_input_${port_flag}_port
    fi
}
fun_check_subdomain_host(){
    input_subdomain_host=""
    strCheckSubdomainHost="$1"
    strB="."
    if [ -n "$strCheckSubdomainHost" ]; then
        result=$(echo $strCheckSubdomainHost | grep "${strB}")
        if [[ "$result" != "" ]]; then
            input_subdomain_host="${strCheckSubdomainHost}"
        else
            echo "Input error! Please input subdomain_host (eg: frps.com)."
            fun_input_subdomain_host
        fi
    else
        echo "Input error! Please input subdomain_host (eg: frps.com)."
        fun_input_subdomain_host
    fi
}

fun_check_number(){
    num_flag=""
    strMaxNum=""
    strCheckNum=""
    input_number=""
    num_flag="$1"
    strMaxNum="$2"
    strCheckNum="$3"
    if [ ${strCheckNum} -ge 1 ] && [ ${strCheckNum} -le ${strMaxNum} ]; then
        input_number="${strCheckNum}"
    else
        echo "Input error! Please input correct numbers."
        fun_input_${num_flag}
    fi
}
fun_add_firewall(){
    checkos
    if [ "${OS}" == 'CentOS' ]; then
        firewall-cmd --zone=public --add-port=$1/$2 --permanent
        firewall-cmd --reload
    else
        echo ""
    fi
    
}

# input port
fun_input_bind_port(){
    def_server_port="7000"
    echo ""
    echo -n -e "Please input ${program_name} ${COLOR_GREEN}bind_port${COLOR_END} [1-65535]"
    read -p "(Default Server Port: ${def_server_port}):" serverport
    [ -z "${serverport}" ] && serverport="${def_server_port}"
    fun_check_port "bind" "${serverport}"
    fun_add_firewall ${serverport} tcp
}
fun_input_dashboard_port(){
    def_dashboard_port="7500"
    echo ""
    echo -n -e "Please input ${program_name} ${COLOR_GREEN}dashboard_port${COLOR_END} [1-65535]"
    read -p "(Default dashboard_port: ${def_dashboard_port}):" input_dashboard_port
    [ -z "${input_dashboard_port}" ] && input_dashboard_port="${def_dashboard_port}"
    fun_check_port "dashboard" "${input_dashboard_port}"
    fun_add_firewall ${input_dashboard_port} tcp
}
fun_input_vhost_http_port(){
    def_vhost_http_port="80"
    echo ""
    echo -n -e "Please input ${program_name} ${COLOR_GREEN}vhost_http_port${COLOR_END} [1-65535]"
    read -p "(Default vhost_http_port: ${def_vhost_http_port}):" input_vhost_http_port
    [ -z "${input_vhost_http_port}" ] && input_vhost_http_port="${def_vhost_http_port}"
    fun_check_port "vhost_http" "${input_vhost_http_port}"
    fun_add_firewall ${input_vhost_http_port} tcp
}
fun_input_vhost_https_port(){
    def_vhost_https_port="443"
    echo ""
    echo -n -e "Please input ${program_name} ${COLOR_GREEN}vhost_https_port${COLOR_END} [1-65535]"
    read -p "(Default vhost_https_port: ${def_vhost_https_port}):" input_vhost_https_port
    [ -z "${input_vhost_https_port}" ] && input_vhost_https_port="${def_vhost_https_port}"
    fun_check_port "vhost_https" "${input_vhost_https_port}"
    fun_add_firewall ${input_vhost_https_port} tcp
}

fun_input_subdomain_host(){
    def_subdomain_host="frps.com"
    echo ""
    echo -n -e "Please input ${program_name} ${COLOR_GREEN}subdomain_host${COLOR_END} "
    read -p "(Default subdomain_host: ${def_subdomain_host}):" input_subdomain_host
    [ -z "${input_subdomain_host}" ] && input_subdomain_host="${def_subdomain_host}"
    fun_check_subdomain_host "${input_subdomain_host}"
}
fun_input_log_max_days(){
    def_max_days="30"
    def_log_max_days="3"
    echo ""
    echo -e "Please input ${program_name} ${COLOR_GREEN}log_max_days${COLOR_END} [1-${def_max_days}]"
    read -p "(Default log_max_days: ${def_log_max_days} day):" input_log_max_days
    [ -z "${input_log_max_days}" ] && input_log_max_days="${def_log_max_days}"
    fun_check_number "log_max_days" "${def_max_days}" "${input_log_max_days}"
}
fun_input_max_pool_count(){
    def_max_pool="200"
    def_max_pool_count="50"
    echo ""
    echo -e "Please input ${program_name} ${COLOR_GREEN}max_pool_count${COLOR_END} [1-${def_max_pool}]"
    read -p "(Default max_pool_count: ${def_max_pool_count}):" input_max_pool_count
    [ -z "${input_max_pool_count}" ] && input_max_pool_count="${def_max_pool_count}"
    fun_check_number "max_pool_count" "${def_max_pool}" "${input_max_pool_count}"
}
save_server_config(){
if [[ "${set_kcp}" == "false" ]]; then
cat > ${str_program_dir}/${program_config_file}<<-EOF
# [common] is integral section
[common]
# A literal address or host name for IPv6 must be enclosed
# in square brackets, as in "[::1]:80", "[ipv6-host]:http" or "[ipv6-host%zone]:80"
bind_addr = 0.0.0.0
bind_port = ${set_bind_port}
# udp port to help make udp hole to penetrate nat
#bind_udp_port = 7001
# udp port used for kcp protocol, it can be same with 'bind_port'
# if not set, kcp is disabled in frps
#kcp_bind_port = ${set_bind_port}
# specify which address proxy will listen for, default value is same with bind_addr
# proxy_bind_addr = 127.0.0.1
# if you want to support virtual host, you must set the http port for listening (optional)
# Note: http port and https port can be same with bind_port
vhost_http_port = ${set_vhost_http_port}
vhost_https_port = ${set_vhost_https_port}
# response header timeout(seconds) for vhost http server, default is 60s
# vhost_http_timeout = 60
# set dashboard_addr and dashboard_port to view dashboard of frps
# dashboard_addr's default value is same with bind_addr
# dashboard is available only if dashboard_port is set
dashboard_addr = 0.0.0.0
dashboard_port = ${set_dashboard_port}
# dashboard user and passwd for basic auth protect, if not set, both default value is admin
dashboard_user = ${set_dashboard_user}
dashboard_pwd = ${set_dashboard_pwd}
# dashboard assets directory(only for debug mode)
# assets_dir = ./static
# console or real logFile path like ./frps.log
log_file = ${str_log_file}
# trace, debug, info, warn, error
log_level = ${str_log_level}
log_max_days = ${set_log_max_days}
# disable log colors when log_file is console, default is false
#disable_log_color = false
# auth token
token = ${set_token}
# heartbeat configure, it's not recommended to modify the default value
# the default value of heartbeat_timeout is 90
# heartbeat_timeout = 90
# only allow frpc to bind ports you list, if you set nothing, there won't be any limit
#allow_ports = 2000-3000,3001,3003,4000-50000
# pool_count in each proxy will change to max_pool_count if they exceed the maximum value
max_pool_count = ${set_max_pool_count}
# max ports can be used for each client, default value is 0 means no limit
#max_ports_per_client = true
# if subdomain_host is not empty, you can set subdomain when type is http or https in frpc's configure file
# when subdomain is test, the host used by routing is test.frps.com
subdomain_host = ${set_subdomain_host}
# if tcp stream multiplexing is used, default is true
tcp_mux = ${set_tcp_mux}
# custom 404 page for HTTP requests
# custom_404_page = /path/to/404.html

EOF
else
cat > ${str_program_dir}/${program_config_file}<<-EOF
# [common] is integral section
[common]
# A literal address or host name for IPv6 must be enclosed
# in square brackets, as in "[::1]:80", "[ipv6-host]:http" or "[ipv6-host%zone]:80"
bind_addr = 0.0.0.0
bind_port = ${set_bind_port}
# udp port to help make udp hole to penetrate nat
#bind_udp_port = 7001
# udp port used for kcp protocol, it can be same with 'bind_port'
# if not set, kcp is disabled in frps
kcp_bind_port = ${set_bind_port}
# specify which address proxy will listen for, default value is same with bind_addr
# proxy_bind_addr = 127.0.0.1
# if you want to support virtual host, you must set the http port for listening (optional)
# Note: http port and https port can be same with bind_port
vhost_http_port = ${set_vhost_http_port}
vhost_https_port = ${set_vhost_https_port}
# response header timeout(seconds) for vhost http server, default is 60s
# vhost_http_timeout = 60
# set dashboard_addr and dashboard_port to view dashboard of frps
# dashboard_addr's default value is same with bind_addr
# dashboard is available only if dashboard_port is set
dashboard_addr = 0.0.0.0
dashboard_port = ${set_dashboard_port}
# dashboard user and passwd for basic auth protect, if not set, both default value is admin
dashboard_user = ${set_dashboard_user}
dashboard_pwd = ${set_dashboard_pwd}
# dashboard assets directory(only for debug mode)
# assets_dir = ./static
# console or real logFile path like ./frps.log
log_file = ${str_log_file}
# trace, debug, info, warn, error
log_level = ${str_log_level}
log_max_days = ${set_log_max_days}
# disable log colors when log_file is console, default is false
#disable_log_color = false
# auth token
token = ${set_token}
# heartbeat configure, it's not recommended to modify the default value
# the default value of heartbeat_timeout is 90
# heartbeat_timeout = 90
# only allow frpc to bind ports you list, if you set nothing, there won't be any limit
#allow_ports = 2000-3000,3001,3003,4000-50000
# pool_count in each proxy will change to max_pool_count if they exceed the maximum value
max_pool_count = ${set_max_pool_count}
# max ports can be used for each client, default value is 0 means no limit
#max_ports_per_client = true
# if subdomain_host is not empty, you can set subdomain when type is http or https in frpc's configure file
# when subdomain is test, the host used by routing is test.frps.com
subdomain_host = ${set_subdomain_host}
# if tcp stream multiplexing is used, default is true
tcp_mux = ${set_tcp_mux}
# custom 404 page for HTTP requests
# custom_404_page = /path/to/404.html
EOF
fi
}

save_client_config(){
cat > ${client_str_program_dir}/${client_program_config_file}<<-EOF
# [common] is integral section
[common]
# A literal address or host name for IPv6 must be enclosed
# in square brackets, as in "[::1]:80", "[ipv6-host]:http" or "[ipv6-host%zone]:80"
server_addr = ${defIP}
server_port = ${set_bind_port}
# if you want to connect frps by http proxy or socks5 proxy, you can set http_proxy here or in global environment variables
# it only works when protocol is tcp
# http_proxy = http://user:passwd@192.168.1.128:8080
# http_proxy = socks5://user:passwd@192.168.1.128:1080
# console or real logFile path like ./frpc.log
log_file = ${str_client_log_file}
# trace, debug, info, warn, error
log_level = ${str_log_level}
log_max_days = ${set_log_max_days}
# disable log colors when log_file is console, default is false
#disable_log_color = false
# for authentication
token = ${set_token}
# Admin assets directory. By default, these assets are bundled with frpc.
# assets_dir = ./static
# connections will be established in advance, default value is zero
pool_count = ${set_max_pool_count}
# if tcp stream multiplexing is used, default is true, it must be same with frps
tcp_mux = ${set_tcp_mux}
###############################
# set admin address for control frpc's action by http api such as reload
admin_addr = 127.0.0.1
admin_port = 7400
admin_user = admin
admin_pwd = admin
# your proxy name will be changed to {user}.{proxy}
user = your_name
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
# if user in [common] section is not empty, it will be changed to {user}.{proxy} such as 'your_name.ssh'
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
local_port = 8080
use_encryption = false
use_compression = true
# http username and password are safety certification for http protocol
# if not set, you can access this custom_domains without certification
#http_user = admin
#http_pwd = admin
# if domain for frps is frps.com, then you can access [web01] proxy by URL http://test.frps.com
subdomain = your_name
#custom_domains = hl.qqmylove.top

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
}

pre_install_clang(){
    fun_clangcn
    echo -e "Check your server setting, please wait..."
    disable_selinux
    if [ -s ${str_program_dir}/${program_name} ] && [ -s ${program_init} ]; then
        echo "${program_name} is installed!"
    else
        clear
        fun_clangcn
        fun_get_version
        fun_getServer
        fun_getVer
        echo -e "Loading You Server IP, please wait..."
        defIP=$(wget -qO- ip.clang.cn | sed -r 's/\r//')
        echo -e "You Server IP:${COLOR_GREEN}${defIP}${COLOR_END}"
        echo -e  "${COLOR_YELOW}Please input your server setting:${COLOR_END}"
        fun_input_bind_port
        [ -n "${input_port}" ] && set_bind_port="${input_port}"
        echo "${program_name} bind_port: ${set_bind_port}"
        echo ""
        fun_input_vhost_http_port
        [ -n "${input_port}" ] && set_vhost_http_port="${input_port}"
        echo "${program_name} vhost_http_port: ${set_vhost_http_port}"
        echo ""
        fun_input_vhost_https_port
        [ -n "${input_port}" ] && set_vhost_https_port="${input_port}"
        echo "${program_name} vhost_https_port: ${set_vhost_https_port}"
        echo ""
        fun_input_dashboard_port
        [ -n "${input_port}" ] && set_dashboard_port="${input_port}"
        echo "${program_name} dashboard_port: ${set_dashboard_port}"
        echo ""
        def_dashboard_user="admin"
        read -p "Please input dashboard_user (Default: ${def_dashboard_user}):" set_dashboard_user
        [ -z "${set_dashboard_user}" ] && set_dashboard_user="${def_dashboard_user}"
        echo "${program_name} dashboard_user: ${set_dashboard_user}"
        echo ""
        def_dashboard_pwd=`fun_randstr 8`
        read -p "Please input dashboard_pwd (Default: ${def_dashboard_pwd}):" set_dashboard_pwd
        [ -z "${set_dashboard_pwd}" ] && set_dashboard_pwd="${def_dashboard_pwd}"
        echo "${program_name} dashboard_pwd: ${set_dashboard_pwd}"
        echo ""
        fun_input_subdomain_host
        [ -n "${input_subdomain_host}" ] && set_subdomain_host="${input_subdomain_host}"
        echo "${program_name} subdomain_host: ${set_subdomain_host}"
        echo ""
        default_token=`fun_randstr 16`
        read -p "Please input token (Default: ${default_token}):" set_token
        [ -z "${set_token}" ] && set_token="${default_token}"
        echo "${program_name} token: ${set_token}"
        echo ""
        fun_input_max_pool_count
        [ -n "${input_number}" ] && set_max_pool_count="${input_number}"
        echo "${program_name} max_pool_count: ${set_max_pool_count}"
        echo ""
        echo "##### Please select log_level #####"
        echo "1: info (default)"
        echo "2: warn"
        echo "3: error"
        echo "4: debug"
        echo "#####################################################"
        read -p "Enter your choice (1, 2, 3, 4 or exit. default [1]): " str_log_level
        case "${str_log_level}" in
            1|[Ii][Nn][Ff][Oo])
                str_log_level="info"
                ;;
            2|[Ww][Aa][Rr][Nn])
                str_log_level="warn"
                ;;
            3|[Ee][Rr][Rr][Oo][Rr])
                str_log_level="error"
                ;;
            4|[Dd][Ee][Bb][Uu][Gg])
                str_log_level="debug"
                ;;
            [eE][xX][iI][tT])
                exit 1
                ;;
            *)
                str_log_level="info"
                ;;
        esac
        echo "log_level: ${str_log_level}"
        echo ""
        fun_input_log_max_days
        [ -n "${input_number}" ] && set_log_max_days="${input_number}"
        echo "${program_name} log_max_days: ${set_log_max_days}"
        echo ""
        echo "##### Please select log_file #####"
        echo "1: enable (default)"
        echo "2: disable"
        echo "#####################################################"
        read -p "Enter your choice (1, 2 or exit. default [1]): " str_log_file
        case "${str_log_file}" in
            1|[yY]|[yY][eE][sS]|[oO][nN]|[tT][rR][uU][eE]|[eE][nN][aA][bB][lL][eE])
                str_log_file="./frps.log"
                str_client_log_file="./frpc.log"
                str_log_file_flag="enable"
                ;;
            0|2|[nN]|[nN][oO]|[oO][fF][fF]|[fF][aA][lL][sS][eE]|[dD][iI][sS][aA][bB][lL][eE])
                str_log_file="/dev/null"
                str_client_log_file="/dev/null"
                str_log_file_flag="disable"
                ;;
            [eE][xX][iI][tT])
                exit 1
                ;;
            *)
                str_log_file="./frps.log"                
                str_client_log_file="./frpc.log"
                str_log_file_flag="enable"
                ;;
        esac
        echo "log_file: ${str_log_file_flag}"
        echo ""
        echo "##### Please select tcp_mux #####"
        echo "1: enable (default)"
        echo "2: disable"
        echo "#####################################################"
        read -p "Enter your choice (1, 2 or exit. default [1]): " str_tcp_mux
        case "${str_tcp_mux}" in
            1|[yY]|[yY][eE][sS]|[oO][nN]|[tT][rR][uU][eE]|[eE][nN][aA][bB][lL][eE])
                set_tcp_mux="true"
                ;;
            0|2|[nN]|[nN][oO]|[oO][fF][fF]|[fF][aA][lL][sS][eE]|[dD][iI][sS][aA][bB][lL][eE])
                set_tcp_mux="false"
                ;;
            [eE][xX][iI][tT])
                exit 1
                ;;
            *)
                set_tcp_mux="true"
                ;;
        esac
        echo "tcp_mux: ${set_tcp_mux}"
        echo ""
        echo "##### Please select kcp support #####"
        echo "1: enable (default)"
        echo "2: disable"
        echo "#####################################################"
        read -p "Enter your choice (1, 2 or exit. default [1]): " str_kcp
        case "${str_kcp}" in
            1|[yY]|[yY][eE][sS]|[oO][nN]|[tT][rR][uU][eE]|[eE][nN][aA][bB][lL][eE])
                set_kcp="true"
                fun_add_firewall ${serverport} udp
                ;;
            0|2|[nN]|[nN][oO]|[oO][fF][fF]|[fF][aA][lL][sS][eE]|[dD][iI][sS][aA][bB][lL][eE])
                set_kcp="false"
                ;;
            [eE][xX][iI][tT])
                exit 1
                ;;
            *)
                set_kcp="true"
                ;;
        esac
        echo "kcp support: ${set_kcp}"
        echo ""
        echo "============== Check your input =============="
        echo -e "You Server IP      : ${COLOR_GREEN}${defIP}${COLOR_END}"
        echo -e "Bind port          : ${COLOR_GREEN}${set_bind_port}${COLOR_END}"
        echo -e "kcp support        : ${COLOR_GREEN}${set_kcp}${COLOR_END}"
        echo -e "vhost http port    : ${COLOR_GREEN}${set_vhost_http_port}${COLOR_END}"
        echo -e "vhost https port   : ${COLOR_GREEN}${set_vhost_https_port}${COLOR_END}"
        echo -e "Dashboard port     : ${COLOR_GREEN}${set_dashboard_port}${COLOR_END}"
        echo -e "Dashboard user     : ${COLOR_GREEN}${set_dashboard_user}${COLOR_END}"
        echo -e "Dashboard password : ${COLOR_GREEN}${set_dashboard_pwd}${COLOR_END}"
        echo -e "token              : ${COLOR_GREEN}${set_token}${COLOR_END}"
        echo -e "tcp_mux            : ${COLOR_GREEN}${set_tcp_mux}${COLOR_END}"
        echo -e "Max Pool count     : ${COLOR_GREEN}${set_max_pool_count}${COLOR_END}"
        echo -e "Log level          : ${COLOR_GREEN}${str_log_level}${COLOR_END}"
        echo -e "Log max days       : ${COLOR_GREEN}${set_log_max_days}${COLOR_END}"
        echo -e "Log file           : ${COLOR_GREEN}${str_log_file_flag}${COLOR_END}"
        echo -e "Subdomain_host     : ${COLOR_GREEN}${set_subdomain_host}${COLOR_END}"
        echo "=============================================="
        echo ""
        echo "Press any key to start...or Press Ctrl+c to cancel"

        char=`get_char`
        install_program_server_clang
    fi
}
# ====== install server ======
install_program_server_clang(){
    [ ! -d ${str_program_dir} ] && mkdir -p ${str_program_dir}
    cd ${str_program_dir}
    echo -n "${program_name} install path:$PWD"
    echo -n "config file for ${program_name} ..."
    # Config file
    save_server_config
    echo "done"
    [ ! -d ${client_str_program_dir} ] && mkdir -p ${client_str_program_dir}
    cd ${client_str_program_dir}
    echo -n "${client_program_name} install path:$PWD"
    echo -n "config file for ${client_program_name} ..."
    save_client_config
    echo " done"
    cd ${str_program_dir}
    echo -n "download ${program_name} ..."
    rm -f ${str_program_dir}/${program_name} ${program_init}
    fun_download_file
    echo " done"
    echo -n "download ${program_init}..."
    if [ ! -s ${program_init} ]; then
        if ! wget --no-check-certificate -q ${FRPS_INIT} -O ${program_init}; then
            echo -e " ${COLOR_RED}failed${COLOR_END}"
            exit 1
        fi
    fi
    [ ! -x ${program_init} ] && chmod +x ${program_init}
    echo " done"

    echo -n "setting ${program_name} boot..."
    [ ! -x ${program_init} ] && chmod +x ${program_init}
    if [ "${OS}" == 'CentOS' ]; then
        chmod +x ${program_init}
        chkconfig --add ${program_name}
    else
        chmod +x ${program_init}
        update-rc.d -f ${program_name} defaults
    fi
    echo " done"
    [ -s ${program_init} ] && ln -s ${program_init} /usr/bin/${program_name}
    ${program_init} start
    fun_clangcn
    #install successfully
    echo ""
    echo "Congratulations, ${program_name} install completed!"
    echo "=============================================="
    echo -e "You Server IP      : ${COLOR_GREEN}${defIP}${COLOR_END}"
    echo -e "Bind port          : ${COLOR_GREEN}${set_bind_port}${COLOR_END}"
    echo -e "KCP support        : ${COLOR_GREEN}${set_kcp}${COLOR_END}"
    echo -e "vhost http port    : ${COLOR_GREEN}${set_vhost_http_port}${COLOR_END}"
    echo -e "vhost https port   : ${COLOR_GREEN}${set_vhost_https_port}${COLOR_END}"
    echo -e "Dashboard port     : ${COLOR_GREEN}${set_dashboard_port}${COLOR_END}"
    echo -e "token              : ${COLOR_GREEN}${set_token}${COLOR_END}"
    echo -e "tcp_mux            : ${COLOR_GREEN}${set_tcp_mux}${COLOR_END}"
    echo -e "Max Pool count     : ${COLOR_GREEN}${set_max_pool_count}${COLOR_END}"
    echo -e "Log level          : ${COLOR_GREEN}${str_log_level}${COLOR_END}"
    echo -e "Log max days       : ${COLOR_GREEN}${set_log_max_days}${COLOR_END}"
    echo -e "Log file           : ${COLOR_GREEN}${str_log_file_flag}${COLOR_END}"
    echo "=============================================="
    echo -e "${program_name} Dashboard     : ${COLOR_GREEN}http://${defIP}:${set_dashboard_port}/${COLOR_END}"
    echo -e "Dashboard user     : ${COLOR_GREEN}${set_dashboard_user}${COLOR_END}"
    echo -e "Dashboard password : ${COLOR_GREEN}${set_dashboard_pwd}${COLOR_END}"
    echo "=============================================="
    echo -e "Subdomain host : ${COLOR_GREEN}${set_subdomain_host}${COLOR_END}"
    echo "=============================================="

    echo ""
    echo -e "${program_name} status manage : ${COLOR_PINKBACK_WHITEFONT}${program_name}${COLOR_END} {${COLOR_GREEN}start|stop|restart|status|config|version${COLOR_END}}"
    echo -e "Example:"
    echo -e "  start: ${COLOR_PINK}${program_name}${COLOR_END} ${COLOR_GREEN}start${COLOR_END}"
    echo -e "   stop: ${COLOR_PINK}${program_name}${COLOR_END} ${COLOR_GREEN}stop${COLOR_END}"
    echo -e "restart: ${COLOR_PINK}${program_name}${COLOR_END} ${COLOR_GREEN}restart${COLOR_END}"
    exit 0
}
############################### configure ##################################
configure_program_server_clang(){
    if [ -s ${str_program_dir}/${program_config_file} ]; then
        vi ${str_program_dir}/${program_config_file}
    else
        echo "${program_name} configuration file not found!"
        exit 1
    fi

    if [ -s ${client_str_program_dir}/${client_program_config_file} ]; then
        vi ${client_str_program_dir}/${client_program_config_file}
    else
        echo "${client_program_name} configuration file not found!"
        exit 1
    fi
}
############################### uninstall ##################################
uninstall_program_server_clang(){
    fun_clangcn
    if [ -s ${program_init} ] || [ -s ${str_program_dir}/${program_name} ] ; then
        echo "============== Uninstall ${program_name} =============="
        str_uninstall="n"
        echo -n -e "${COLOR_YELOW}You want to uninstall?${COLOR_END}"
        read -p "[y/N]:" str_uninstall
        case "${str_uninstall}" in
        [yY]|[yY][eE][sS])
        echo ""
        echo "You select [Yes], press any key to continue."
        str_uninstall="y"
        char=`get_char`
        ;;
        *)
        echo ""
        str_uninstall="n"
        esac
        if [ "${str_uninstall}" == 'n' ]; then
            echo "You select [No],shell exit!"
        else
            checkos
            ${program_init} stop
            if [ "${OS}" == 'CentOS' ]; then
                chkconfig --del ${program_name}
            else
                update-rc.d -f ${program_name} remove
            fi
            rm -f ${program_init} 
            rm -f /var/run/${program_name}.pid 
            rm -f /usr/bin/${program_name}
            rm -fr ${str_program_dir}
            echo "${program_name} uninstall success!"
        fi
    else
        echo "${program_name} Not install!"
    fi

    if [ -s ${client_str_program_dir}/${client_program_name} ] ; then
        echo "============== Uninstall ${client_program_name} =============="
        str_uninstall="n"
        echo -n -e "${COLOR_YELOW}You want to uninstall?${COLOR_END}"
        read -p "[y/n]:" str_uninstall
        case "${str_uninstall}" in
        [yY]|[yY][eE][sS])
        echo ""
        echo "You select [Yes], press any key to continue."
        str_uninstall="y"
        char=`get_char`
        ;;
        *)
        echo ""
        str_uninstall="n"
        esac
        if [ "${str_uninstall}" == 'n' ]; then
            echo "You select [No],shell exit!"
        else
            checkos
            #${client_program_init} stop
            #if [ "${OS}" == 'CentOS' ]; then
            #    chkconfig --del ${client_program_name}
            #else
            #    update-rc.d -f ${client_program_name} remove
            #fi
            #rm -f ${client_program_init} /var/run/${client_program_name}.pid /usr/bin/${client_program_name}
            rm -fr ${client_str_program_dir}
            echo "${client_program_name} uninstall success!"
        fi
    else
        echo "${client_program_name} Not install!"
    fi
    rm -rf /usr/local/${soft_name}
    exit 0
}
############################### update ##################################
update_config_clang(){
    if [ ! -r "${str_program_dir}/${program_config_file}" ]; then
        echo "config file ${str_program_dir}/${program_config_file} not found."
    else
        search_dashboard_user=`grep "dashboard_user" ${str_program_dir}/${program_config_file}`
        search_dashboard_pwd=`grep "dashboard_pwd" ${str_program_dir}/${program_config_file}`
        search_kcp_bind_port=`grep "kcp_bind_port" ${str_program_dir}/${program_config_file}`
        search_tcp_mux=`grep "tcp_mux" ${str_program_dir}/${program_config_file}`
        search_token=`grep "privilege_token" ${str_program_dir}/${program_config_file}`
        search_allow_ports=`grep "privilege_allow_ports" ${str_program_dir}/${program_config_file}`
        search_subdomain_host=`grep "subdomain_host" ${str_program_dir}/${program_config_file}`
        if [ -z "${search_dashboard_user}" ] || [ -z "${search_dashboard_pwd}" ] || [ -z "${search_kcp_bind_port}" ] || [ -z "${search_tcp_mux}" ] || [ ! -z "${search_token}" ] || [ ! -z "${search_allow_ports}" ];then
            echo -e "${COLOR_GREEN}Configuration files need to be updated, now setting:${COLOR_END}"
            echo ""
            if [ -z "${search_subdomain_host}" ];then
                def_subdomain_host_update="frps.com"
                echo -n -e "Please input ${program_name} ${COLOR_GREEN}subdomain_host${COLOR_END} "
                read -p "(Default subdomain_host: ${def_subdomain_host_update}):" set_subdomain_host_update
                [ -z "${set_subdomain_host_update}" ] && set_subdomain_host_update="${def_subdomain_host_update}"
                echo "${program_name} subdomain_host: ${set_subdomain_host_update}"
                sed -i "/subdomain_host = ${set_subdomain_host_update}\n" ${str_program_dir}/${program_config_file}
                sed -i "/custom_domains = example.${set_subdomain_host_update}\n" ${client_str_program_dir}/${client_program_config_file}
            fi
            if [ ! -z "${search_token}" ];then
                sed -i "s/privilege_token/token/" ${str_program_dir}/${program_config_file}                
                sed -i "s/privilege_token/token/" ${client_str_program_dir}/${client_program_config_file}
            fi
            if [ -z "${search_dashboard_user}" ] && [ -z "${search_dashboard_pwd}" ];then
                def_dashboard_user_update="admin"
                read -p "Please input dashboard_user (Default: ${def_dashboard_user_update}):" set_dashboard_user_update
                [ -z "${set_dashboard_user_update}" ] && set_dashboard_user_update="${def_dashboard_user_update}"
                echo "${program_name} dashboard_user: ${set_dashboard_user_update}"
                echo ""
                def_dashboard_pwd_update=`fun_randstr 8`
                read -p "Please input dashboard_pwd (Default: ${def_dashboard_pwd_update}):" set_dashboard_pwd_update
                [ -z "${set_dashboard_pwd_update}" ] && set_dashboard_pwd_update="${def_dashboard_pwd_update}"
                echo "${program_name} dashboard_pwd: ${set_dashboard_pwd_update}"
                echo ""
                sed -i "/dashboard_port =.*/a\dashboard_user = ${set_dashboard_user_update}\ndashboard_pwd = ${set_dashboard_pwd_update}\n" ${str_program_dir}/${program_config_file}
            fi
            if [ -z "${search_kcp_bind_port}" ];then
                echo "##### Please select kcp support #####"
                echo "1: enable (default)"
                echo "2: disable"
                echo "#####################################################"
                read -p "Enter your choice (1, 2 or exit. default [1]): " str_kcp
                case "${str_kcp}" in
                    1|[yY]|[yY][eE][sS]|[oO][nN]|[tT][rR][uU][eE]|[eE][nN][aA][bB][lL][eE])
                        set_kcp="true"
                        ;;
                    0|2|[nN]|[nN][oO]|[oO][fF][fF]|[fF][aA][lL][sS][eE]|[dD][iI][sS][aA][bB][lL][eE])
                        set_kcp="false"
                        ;;
                    [eE][xX][iI][tT])
                        exit 1
                        ;;
                    *)
                        set_kcp="true"
                        ;;
                esac
                echo "kcp support: ${set_kcp}"
                def_kcp_bind_port=( $( __readINI ${str_program_dir}/${program_config_file} common bind_port ) )
                if [[ "${set_kcp}" == "false" ]]; then
                    sed -i "/^bind_port =.*/a\# udp port used for kcp protocol, it can be same with 'bind_port'\n# if not set, kcp is disabled in frps\n#kcp_bind_port = ${def_kcp_bind_port}\n" ${str_program_dir}/${program_config_file}
                else
                    sed -i "/^bind_port =.*/a\# udp port used for kcp protocol, it can be same with 'bind_port'\n# if not set, kcp is disabled in frps\nkcp_bind_port = ${def_kcp_bind_port}\n" ${str_program_dir}/${program_config_file}
                fi

                sed -i "/^server_port =.*/a server_port = ${def_kcp_bind_port}\n" ${client_str_program_dir}/${client_program_config_file}
            fi
            if [ -z "${search_tcp_mux}" ];then
                echo "##### Please select tcp_mux #####"
                echo "1: enable (default)"
                echo "2: disable"
                echo "#####################################################"
                read -p "Enter your choice (1, 2 or exit. default [1]): " str_tcp_mux
                case "${str_tcp_mux}" in
                    1|[yY]|[yY][eE][sS]|[oO][nN]|[tT][rR][uU][eE]|[eE][nN][aA][bB][lL][eE])
                        set_tcp_mux="true"
                        ;;
                    0|2|[nN]|[nN][oO]|[oO][fF][fF]|[fF][aA][lL][sS][eE]|[dD][iI][sS][aA][bB][lL][eE])
                        set_tcp_mux="false"
                        ;;
                    [eE][xX][iI][tT])
                        exit 1
                        ;;
                    *)
                        set_tcp_mux="true"
                        ;;
                esac
                echo "tcp_mux: ${set_tcp_mux}"
                sed -i "/^privilege_mode = true/d" ${str_program_dir}/${program_config_file}
                sed -i "/^token =.*/a\# if tcp stream multiplexing is used, default is true\ntcp_mux = ${set_tcp_mux}\n" ${str_program_dir}/${program_config_file}

                sed -i "/^token =.*/a\# if tcp stream multiplexing is used, default is true, it must be same with frps\ntcp_mux = ${set_tcp_mux}\n" ${client_str_program_dir}/${client_program_config_file}

            fi
            if [ ! -z "${search_allow_ports}" ];then
                sed -i "s/privilege_allow_ports/allow_ports/" ${str_program_dir}/${program_config_file}
            fi
        fi
        verify_dashboard_user=`grep "^dashboard_user" ${str_program_dir}/${program_config_file}`
        verify_dashboard_pwd=`grep "^dashboard_pwd" ${str_program_dir}/${program_config_file}`
        verify_kcp_bind_port=`grep "kcp_bind_port" ${str_program_dir}/${program_config_file}`
        verify_tcp_mux=`grep "^tcp_mux" ${str_program_dir}/${program_config_file}`
        verify_token=`grep "privilege_token" ${str_program_dir}/${program_config_file}`
        verify_subdomain_host=`grep "subdomain_host" ${str_program_dir}/${program_config_file}`
        verify_allow_ports=`grep "privilege_allow_ports" ${str_program_dir}/${program_config_file}`
        if [ ! -z "${verify_dashboard_user}" ] && [ ! -z "${verify_dashboard_pwd}" ] && [ ! -z "${verify_kcp_bind_port}" ] && [ ! -z "${verify_tcp_mux}" ] && [ -z "${verify_token}" ] && [ ! -z "${verify_subdomain_host}" ] && [ -z "${verify_allow_ports}" ];then
            echo -e "${COLOR_GREEN}update configuration file successfully!!!${COLOR_END}"
        else
            echo -e "${COLOR_RED}update configuration file error!!!${COLOR_END}"
        fi
    fi
}

update_program_server_clang(){
    fun_clangcn "clear"
    if [ -s ${program_init} ] || [ -s ${str_program_dir}/${program_name} ] ; then
        echo "============== Update ${program_name} =============="
        update_config_clang
        checkos
        check_centosversion
        check_os_bit
        fun_get_version
        remote_init_version=`wget --no-check-certificate -qO- ${FRPS_INIT} | sed -n '/'^version'/p' | cut -d\" -f2`
        local_init_version=`sed -n '/'^version'/p' ${program_init} | cut -d\" -f2`
        install_shell=${strPath}
        if [ ! -z ${remote_init_version} ];then
            if [[ "${local_init_version}" != "${remote_init_version}" ]];then
                echo "========== Update ${program_name} ${program_init} =========="
                if ! wget --no-check-certificate ${FRPS_INIT} -O ${program_init}; then
                    echo "Failed to download ${program_name}.init file!"
                    exit 1
                else
                    echo -e "${COLOR_GREEN}${program_init} Update successfully !!!${COLOR_END}"
                fi
            fi
        fi
        [ ! -d ${str_program_dir} ] && mkdir -p ${str_program_dir}
        echo -e "Loading network version for ${program_name}, please wait..."
        fun_getServer
        fun_getVer >/dev/null 2>&1
        local_program_version=`${str_program_dir}/${program_name} --version`
        echo -e "${COLOR_GREEN}${program_name}  local version ${local_program_version}${COLOR_END}"
        echo -e "${COLOR_GREEN}${program_name} remote version ${FRPS_VER}${COLOR_END}"
        if [[ "${local_program_version}" != "${FRPS_VER}" ]];then
            echo -e "${COLOR_GREEN}Found a new version,update now!!!${COLOR_END}"
            ${program_init} stop
            sleep 1
            rm -f /usr/bin/${program_name} ${str_program_dir}/${program_name}
            fun_download_file
            if [ "${OS}" == 'CentOS' ]; then
                chmod +x ${program_init}
                chkconfig --add ${program_name}
            else
                chmod +x ${program_init}
                update-rc.d -f ${program_name} defaults
            fi
            [ -s ${program_init} ] && ln -s ${program_init} /usr/bin/${program_name}
            [ ! -x ${program_init} ] && chmod 755 ${program_init}
            ${program_init} start
            echo "${program_name} version `${str_program_dir}/${program_name} --version`"
            echo "${program_name} update success!"
        else
                echo -e "no need to update !!!${COLOR_END}"
        fi
    else
        echo "${program_name} Not install!"
    fi
    exit 0
}
clear
strPath=`pwd`
rootness
fun_set_text_color
checkos
check_centosversion
check_os_bit
pre_install_packs
shell_update
# Initialization
action=$1
[  -z $1 ]
case "$action" in
install)
    pre_install_clang 2>&1 | tee /root/${program_name}-install.log
    ;;
config)
    configure_program_server_clang
    ;;
uninstall)
    uninstall_program_server_clang 2>&1 | tee /root/${program_name}-uninstall.log
    ;;
update)
    update_program_server_clang 2>&1 | tee /root/${program_name}-update.log
    ;;
*)
    fun_clangcn
    echo "Arguments error! [${action} ]"
    echo "Usage: `basename $0` {install|uninstall|update|config}"
    RET_VAL=1
    ;;
esac