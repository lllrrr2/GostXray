#!/bin/bash
# GOST v3 中转脚本 - 普通 VPS 版本
# 适用于 Linux VPS (root 环境，使用 systemd)
# 支持协议: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, SOCKS, HTTP
# 快捷命令: gost

Green="\033[32m" && Red="\033[31m" && Yellow="\033[33m"
Cyan="\033[36m" && Reset="\033[0m"
Info="${Green}[信息]${Reset}"
Error="${Red}[错误]${Reset}"
Warning="${Yellow}[警告]${Reset}"
Tip="${Cyan}[提示]${Reset}"

shell_version="3.5.0"
gost_version="3.0.0"

# 目录配置
GOST_DIR="/etc/gost3"
GOST_BIN="/usr/bin/gost"
GOST_CONF="$GOST_DIR/config.yaml"
RAW_CONF="$GOST_DIR/rawconf"
PORT_CONF="$GOST_DIR/ports.conf"
SERVICE_FILE="/etc/systemd/system/gost.service"

# ==================== 初始化 ====================
init_dirs() {
    mkdir -p "$GOST_DIR"
    touch "$RAW_CONF" "$PORT_CONF" 2>/dev/null
}

# ==================== Root 检查 ====================
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${Error} 请以 root 用户运行此脚本"
        exit 1
    fi
}

# ==================== 系统检测 ====================
check_system() {
    local os=$(uname -s)
    local arch=$(uname -m)
    
    if [[ "$os" != "Linux" ]]; then
        echo -e "${Error} 此脚本仅支持 Linux 系统"
        exit 1
    fi
    
    case $arch in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        i386|i686) ARCH="386" ;;
        armv7l) ARCH="armv7" ;;
        *) echo -e "${Error} 不支持的架构: $arch"; exit 1 ;;
    esac
    
    echo -e "${Info} 系统: $os ($arch)"
}

# ==================== 端口管理 ====================
get_random_port() {
    local min=${1:-10000}
    local max=${2:-65535}
    echo $((RANDOM % (max - min + 1) + min))
}

check_port() {
    local port=$1
    if ss -tuln 2>/dev/null | grep -q ":$port " || \
       netstat -tuln 2>/dev/null | grep -q ":$port "; then
        return 1
    fi
    return 0
}

open_port() {
    local port=$1
    # iptables
    if command -v iptables &>/dev/null; then
        iptables -I INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
        iptables -I INPUT -p udp --dport $port -j ACCEPT 2>/dev/null
    fi
    # firewalld
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --zone=public --add-port=$port/tcp --permanent 2>/dev/null
        firewall-cmd --zone=public --add-port=$port/udp --permanent 2>/dev/null
        firewall-cmd --reload 2>/dev/null
    fi
    # ufw
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        ufw allow $port 2>/dev/null
    fi
}

read_port_config() {
    echo -e ""
    echo -e "${Info} 端口配置:"
    echo -e "[1] 随机端口 (10000-65535)"
    echo -e "[2] 手动指定端口"
    read -p "请选择 [默认1]: " port_mode
    port_mode=${port_mode:-1}
    
    case $port_mode in
        1)
            local_port=$(get_random_port 10000 65535)
            local retry=0
            while ! check_port $local_port && [ $retry -lt 20 ]; do
                local_port=$(get_random_port 10000 65535)
                ((retry++))
            done
            echo -e "${Info} 分配端口: ${Green}$local_port${Reset}"
            ;;
        2)
            read -p "请输入端口: " local_port
            if ! check_port $local_port; then
                echo -e "${Warning} 端口 $local_port 可能已被占用"
            fi
            ;;
        *)
            echo -e "${Error} 无效选择"
            return 1
            ;;
    esac
    
    open_port "$local_port"
    echo "$local_port" >> "$PORT_CONF"
    return 0
}

# ==================== Base64 解码 ====================
base64_decode() {
    local input="$1"
    input="${input//-/+}"
    input="${input//_/\/}"
    local mod=$((${#input} % 4))
    [ $mod -eq 2 ] && input="${input}=="
    [ $mod -eq 3 ] && input="${input}="
    echo "$input" | base64 -d 2>/dev/null
}

url_decode() {
    local url="${1//+/ }"
    printf '%b' "${url//%/\\x}"
}

# ==================== 协议解析 ====================
parse_vless() {
    local link="${1#vless://}"
    local uuid="${link%%@*}"
    local rest="${link#*@}"
    local host_port="${rest%%\?*}"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%#*}"
    
    local params="${rest#*\?}"
    local type="" security="" sni="" path="" flow="" fp="" pbk="" sid=""
    while IFS='=' read -r key value; do
        value="${value%%#*}"
        case $key in
            type) type="$value" ;;
            security) security="$value" ;;
            sni) sni="$value" ;;
            path) path="$(url_decode "$value")" ;;
            flow) flow="$value" ;;
            fp) fp="$value" ;;
            pbk) pbk="$value" ;;
            sid) sid="$value" ;;
        esac
    done <<< "$(echo "$params" | tr '&' '\n' | cut -d'#' -f1)"
    
    echo "vless|$uuid|$host|$port|$type|$security|$sni|$path|$flow|$fp|$pbk|$sid"
}

parse_vmess() {
    local link="${1#vmess://}"
    local decoded=$(base64_decode "$link")
    
    if command -v jq &>/dev/null; then
        local host=$(echo "$decoded" | jq -r '.add // ""')
        local port=$(echo "$decoded" | jq -r '.port // ""')
        local uuid=$(echo "$decoded" | jq -r '.id // ""')
        local net=$(echo "$decoded" | jq -r '.net // "tcp"')
        local tls=$(echo "$decoded" | jq -r '.tls // ""')
        local sni=$(echo "$decoded" | jq -r '.sni // ""')
        local path=$(echo "$decoded" | jq -r '.path // ""')
        local aid=$(echo "$decoded" | jq -r '.aid // "0"')
        local ps=$(echo "$decoded" | jq -r '.ps // ""')
        echo "vmess|$uuid|$host|$port|$net|$tls|$sni|$path|$aid|$ps"
    else
        local host=$(echo "$decoded" | grep -o '"add"[^,]*' | cut -d'"' -f4)
        local port=$(echo "$decoded" | grep -o '"port"[^,]*' | sed 's/[^0-9]//g')
        echo "vmess||$host|$port||||||"
    fi
}

parse_trojan() {
    local link="${1#trojan://}"
    local password="${link%%@*}"
    local rest="${link#*@}"
    local host_port="${rest%%\?*}"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%#*}"
    
    local params="${rest#*\?}"
    local sni="" type=""
    while IFS='=' read -r key value; do
        case $key in
            sni) sni="$value" ;;
            type) type="$value" ;;
        esac
    done <<< "$(echo "$params" | tr '&' '\n' | cut -d'#' -f1)"
    
    echo "trojan|$password|$host|$port|$type|$sni"
}

parse_ss() {
    local link="${1#ss://}"
    local method="" password="" host="" port=""
    
    if [[ "$link" == *"@"* ]]; then
        local encoded="${link%%@*}"
        local decoded=$(base64_decode "$encoded")
        method="${decoded%%:*}"
        password="${decoded#*:}"
        local host_part="${link#*@}"
        host="${host_part%%:*}"
        port="${host_part##*:}"
        port="${port%%#*}"
    else
        local decoded=$(base64_decode "${link%%#*}")
        method="${decoded%%:*}"
        local rest="${decoded#*:}"
        password="${rest%%@*}"
        local hp="${rest#*@}"
        host="${hp%%:*}"
        port="${hp##*:}"
    fi
    
    echo "ss|$method|$password|$host|$port"
}

parse_hysteria2() {
    local link="${1#hysteria2://}"
    link="${link#hy2://}"
    local password="${link%%@*}"
    local rest="${link#*@}"
    local host_port="${rest%%\?*}"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%/*}"
    port="${port%%#*}"
    
    local params="${rest#*\?}"
    local sni="" insecure=""
    while IFS='=' read -r key value; do
        case $key in
            sni) sni="$value" ;;
            insecure) insecure="$value" ;;
        esac
    done <<< "$(echo "$params" | tr '&' '\n' | cut -d'#' -f1)"
    
    echo "hysteria2|$password|$host|$port|$sni|$insecure"
}

parse_tuic() {
    local link="${1#tuic://}"
    local auth="${link%%@*}"
    local uuid="${auth%%:*}"
    local password="${auth#*:}"
    local rest="${link#*@}"
    local host_port="${rest%%\?*}"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%/*}"
    port="${port%%#*}"
    
    local params="${rest#*\?}"
    local sni="" alpn="" cc=""
    while IFS='=' read -r key value; do
        case $key in
            sni) sni="$value" ;;
            alpn) alpn="$value" ;;
            congestion_control) cc="$value" ;;
        esac
    done <<< "$(echo "$params" | tr '&' '\n' | cut -d'#' -f1)"
    
    echo "tuic|$uuid|$password|$host|$port|$sni|$alpn|$cc"
}

parse_socks() {
    local link="${1#socks://}"
    link="${link#socks5://}"
    local user="" pass="" host="" port=""
    
    if [[ "$link" == *"@"* ]]; then
        local auth="${link%%@*}"
        local decoded=$(base64_decode "$auth" 2>/dev/null || echo "$auth")
        user="${decoded%%:*}"
        pass="${decoded#*:}"
        local hp="${link#*@}"
        host="${hp%%:*}"
        port="${hp##*:}"
    else
        local hp="${link%%#*}"
        host="${hp%%:*}"
        port="${hp##*:}"
    fi
    port="${port%%#*}"
    
    echo "socks|$user|$pass|$host|$port"
}

# ==================== 协议识别 ====================
detect_protocol() {
    local link="$1"
    case "$link" in
        vless://*) echo "vless" ;;
        vmess://*) echo "vmess" ;;
        trojan://*) echo "trojan" ;;
        ss://*) echo "ss" ;;
        hysteria2://*|hy2://*) echo "hysteria2" ;;
        tuic://*) echo "tuic" ;;
        socks://*|socks5://*) echo "socks" ;;
        http://*) echo "http" ;;
        *) echo "unknown" ;;
    esac
}

detect_protocol_type() {
    local protocol=$1
    case "$protocol" in
        hysteria2|hy2|tuic|quic) echo "udp" ;;
        *) echo "tcp" ;;
    esac
}

parse_node() {
    local link="$1"
    local proto=$(detect_protocol "$link")
    case $proto in
        vless) parse_vless "$link" ;;
        vmess) parse_vmess "$link" ;;
        trojan) parse_trojan "$link" ;;
        ss) parse_ss "$link" ;;
        hysteria2) parse_hysteria2 "$link" ;;
        tuic) parse_tuic "$link" ;;
        socks) parse_socks "$link" ;;
        *) echo "unknown" ;;
    esac
}

get_target() {
    local proto="$1"
    local parsed="$2"
    IFS='|' read -ra p <<< "$parsed"
    
    case $proto in
        vless|vmess|trojan) echo "${p[2]}|${p[3]}" ;;
        ss) echo "${p[3]}|${p[4]}" ;;
        hysteria2) echo "${p[2]}|${p[3]}" ;;
        tuic) echo "${p[3]}|${p[4]}" ;;
        socks) echo "${p[3]}|${p[4]}" ;;
    esac
}

# ==================== 中转链接生成 ====================
generate_relay_link() {
    local proto="$1"
    local parsed="$2"
    local relay_ip="$3"
    local relay_port="$4"
    
    IFS='|' read -ra p <<< "$parsed"
    
    case $proto in
        vless)
            local link="vless://${p[1]}@${relay_ip}:${relay_port}?"
            [ -n "${p[4]}" ] && link+="type=${p[4]}&"
            [ -n "${p[5]}" ] && link+="security=${p[5]}&"
            [ -n "${p[6]}" ] && link+="sni=${p[6]}&"
            [ -n "${p[7]}" ] && link+="path=${p[7]}&"
            [ -n "${p[8]}" ] && link+="flow=${p[8]}&"
            [ -n "${p[9]}" ] && link+="fp=${p[9]}&"
            [ -n "${p[10]}" ] && link+="pbk=${p[10]}&"
            [ -n "${p[11]}" ] && link+="sid=${p[11]}&"
            echo "${link%&}#Relay-${p[2]}"
            ;;
        vmess)
            local json="{\"v\":\"2\",\"ps\":\"Relay-${p[2]}\",\"add\":\"${relay_ip}\",\"port\":\"${relay_port}\",\"id\":\"${p[1]}\",\"aid\":\"${p[8]:-0}\",\"net\":\"${p[4]:-tcp}\",\"type\":\"none\",\"host\":\"${p[6]}\",\"path\":\"${p[7]}\",\"tls\":\"${p[5]}\"}"
            echo "vmess://$(echo -n "$json" | base64 -w 0 2>/dev/null || echo -n "$json" | base64 | tr -d '\n')"
            ;;
        trojan)
            local link="trojan://${p[1]}@${relay_ip}:${relay_port}?"
            [ -n "${p[4]}" ] && link+="type=${p[4]}&"
            [ -n "${p[5]}" ] && link+="sni=${p[5]}&"
            echo "${link%&}#Relay-${p[2]}"
            ;;
        ss)
            local auth=$(echo -n "${p[1]}:${p[2]}" | base64 -w 0 2>/dev/null || echo -n "${p[1]}:${p[2]}" | base64 | tr -d '\n')
            echo "ss://${auth}@${relay_ip}:${relay_port}#Relay-${p[3]}"
            ;;
        hysteria2)
            local link="hysteria2://${p[1]}@${relay_ip}:${relay_port}?"
            [ -n "${p[4]}" ] && link+="sni=${p[4]}&"
            link+="insecure=1&"
            echo "${link%&}#Relay-${p[2]}"
            ;;
        tuic)
            local link="tuic://${p[1]}:${p[2]}@${relay_ip}:${relay_port}?"
            [ -n "${p[5]}" ] && link+="sni=${p[5]}&"
            [ -n "${p[6]}" ] && link+="alpn=${p[6]}&"
            [ -n "${p[7]}" ] && link+="congestion_control=${p[7]}&"
            link+="allow_insecure=1&"
            echo "${link%&}#Relay-${p[3]}"
            ;;
        socks)
            if [ -n "${p[1]}" ]; then
                local auth=$(echo -n "${p[1]}:${p[2]}" | base64 -w 0 2>/dev/null || echo -n "${p[1]}:${p[2]}" | base64 | tr -d '\n')
                echo "socks://${auth}@${relay_ip}:${relay_port}#Relay-${p[3]}"
            else
                echo "socks://${relay_ip}:${relay_port}#Relay-${p[3]}"
            fi
            ;;
    esac
}

# ==================== GOST 安装 ====================
install_gost() {
    init_dirs
    check_system
    
    echo -e "${Info} 正在下载 GOST v3..."
    
    local url="https://github.com/go-gost/gost/releases/download/v${gost_version}/gost_${gost_version}_linux_${ARCH}.tar.gz"
    
    cd /tmp
    
    if command -v wget &>/dev/null; then
        wget -q "$url" -O gost.tar.gz
    elif command -v curl &>/dev/null; then
        curl -sL "$url" -o gost.tar.gz
    else
        echo -e "${Error} 请安装 wget 或 curl"
        return 1
    fi
    
    tar -xzf gost.tar.gz
    mv gost "$GOST_BIN"
    chmod +x "$GOST_BIN"
    rm -f gost.tar.gz
    
    # 初始化配置
    cat > "$GOST_CONF" << 'EOF'
services: []
EOF
    
    # 创建 systemd 服务
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=GOST v3 Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=$GOST_BIN -C $GOST_CONF
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable gost >/dev/null 2>&1
    
    echo -e "${Info} GOST v3 安装完成"
    echo -e "${Info} 安装路径: $GOST_BIN"
    echo -e "${Info} 配置文件: $GOST_CONF"
}

# ==================== GOST 配置生成 ====================
generate_gost_config() {
    local port="$1"
    local host="$2"
    local dport="$3"
    local proto="${4:-tcp}"
    
    if [ "$proto" == "udp" ]; then
        cat << EOF
  - name: relay-${port}-udp
    addr: ":${port}"
    handler:
      type: udp
    listener:
      type: udp
      metadata:
        keepAlive: true
        ttl: 10s
        readBufferSize: 4096
    forwarder:
      nodes:
        - name: target
          addr: "${host}:${dport}"
EOF
    else
        cat << EOF
  - name: relay-${port}-tcp
    addr: ":${port}"
    handler:
      type: tcp
    listener:
      type: tcp
    forwarder:
      nodes:
        - name: target
          addr: "${host}:${dport}"
EOF
    fi
}

add_relay() {
    local port="$1"
    local host="$2"
    local dport="$3"
    local proto="${4:-tcp}"
    
    local config=$(generate_gost_config "$port" "$host" "$dport" "$proto")
    
    if grep -q "^services: \[\]$" "$GOST_CONF" 2>/dev/null; then
        cat > "$GOST_CONF" << EOF
services:
${config}
EOF
    else
        echo "$config" >> "$GOST_CONF"
    fi
    
    echo "gost|${proto}|${port}|${host}|${dport}" >> "$RAW_CONF"
}

# ==================== GOST 进程管理 ====================
start_gost() {
    if [ ! -f "$GOST_BIN" ]; then
        echo -e "${Error} GOST 未安装，请先安装"
        return 1
    fi
    
    systemctl start gost
    sleep 1
    if systemctl is-active gost >/dev/null 2>&1; then
        echo -e "${Info} GOST 启动成功"
    else
        echo -e "${Error} GOST 启动失败"
        journalctl -u gost --no-pager -n 20
    fi
}

stop_gost() {
    systemctl stop gost
    echo -e "${Info} GOST 已停止"
}

restart_gost() {
    systemctl restart gost
    sleep 1
    if systemctl is-active gost >/dev/null 2>&1; then
        echo -e "${Info} GOST 重启成功"
    else
        echo -e "${Error} GOST 重启失败"
    fi
}

status_gost() {
    if systemctl is-active gost >/dev/null 2>&1; then
        echo -e "${Green}运行中${Reset}"
        return 0
    else
        echo -e "${Red}已停止${Reset}"
        return 1
    fi
}

# ==================== 日志管理 ====================
show_log() {
    echo -e ""
    echo -e "${Green}========== 日志 ==========${Reset}"
    journalctl -u gost --no-pager -n 50
    echo -e "${Green}==========================${Reset}"
}

# ==================== 添加中转 ====================
add_relay_config() {
    echo -e ""
    echo -e "${Info} 请选择配置方式:"
    echo -e "[1] 粘贴节点链接 (自动解析)"
    echo -e "[2] 手动输入目标地址"
    read -p "请选择 [默认1]: " input_type
    input_type=${input_type:-1}
    
    local proto="" parsed="" port_type="tcp"
    
    if [ "$input_type" == "1" ]; then
        echo -e ""
        echo -e "${Info} 请粘贴节点链接 (支持多行粘贴):"
        
        # 读取多行输入
        local raw_input=""
        read -r first_line
        raw_input="$first_line"
        while read -r -t 1 line; do
            [ -n "$line" ] && raw_input="${raw_input}"$'\n'"$line"
        done
        
        # 提取链接
        local regex="(vless|vmess|trojan|ss|hysteria2|hy2|tuic|socks|socks5|http|https)://[][a-zA-Z0-9._~:/?#@!$&'()*+,;=%-]+"
        local node_links=()
        while IFS= read -r -d '' link; do
            node_links+=("$link")
        done < <(echo "$raw_input" | grep -oE "$regex" | tr '\n' '\0')
        
        if [ ${#node_links[@]} -eq 0 ]; then
            echo -e "${Error} 未找到有效链接"
            return 1
        fi
        
        echo -e "${Info} 共获取到 ${#node_links[@]} 个链接"
        
        # 如果多个链接，自动使用随机端口
        local auto_batch=false
        if [ ${#node_links[@]} -gt 1 ]; then
            echo -e "${Info} 检测到多个链接，将自动使用随机端口"
            auto_batch=true
        fi
        
        # 获取本机IP
        local my_ip=$(curl -s4m5 ip.sb 2>/dev/null || curl -s4m5 ifconfig.me 2>/dev/null)
        [ -z "$my_ip" ] && my_ip="YOUR_IP"
        
        local index=1
        for node_link in "${node_links[@]}"; do
            echo -e ""
            echo -e "${Green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
            echo -e "  ${Cyan}处理链接 #${index}/${#node_links[@]}${Reset}"
            echo -e "${Green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
            
            proto=$(detect_protocol "$node_link")
            if [ "$proto" == "unknown" ]; then
                echo -e "${Warning} 无法识别的协议，跳过"
                ((index++))
                continue
            fi
            
            echo -e "${Info} 协议: ${Green}${proto^^}${Reset}"
            
            port_type=$(detect_protocol_type "$proto")
            parsed=$(parse_node "$node_link")
            local target=$(get_target "$proto" "$parsed")
            IFS='|' read -r target_host target_port <<< "$target"
            
            if [ -z "$target_host" ] || [ -z "$target_port" ]; then
                echo -e "${Warning} 解析失败，跳过"
                ((index++))
                continue
            fi
            
            echo -e "${Info} 目标: ${Green}${target_host}:${target_port}${Reset}"
            
            # 端口配置
            if [ "$auto_batch" == "true" ]; then
                local_port=$(get_random_port 10000 65535)
                local retry=0
                while ! check_port $local_port && [ $retry -lt 20 ]; do
                    local_port=$(get_random_port 10000 65535)
                    ((retry++))
                done
                echo -e "${Info} 分配端口: ${Green}$local_port${Reset}"
                open_port "$local_port"
                echo "$local_port" >> "$PORT_CONF"
            else
                if ! read_port_config; then
                    ((index++))
                    continue
                fi
            fi
            
            add_relay "$local_port" "$target_host" "$target_port" "$port_type"
            
            echo -e ""
            echo -e "${Info} 配置完成: :${local_port} -> ${target_host}:${target_port}"
            
            # 生成中转链接
            local relay_link=$(generate_relay_link "$proto" "$parsed" "$my_ip" "$local_port")
            echo -e ""
            echo -e "${Info} 中转后的链接:"
            echo -e "${Cyan}${relay_link}${Reset}"
            
            ((index++))
        done
        
        restart_gost
        
    else
        read -p "目标地址: " target_host
        read -p "目标端口: " target_port
        
        if [ -z "$target_host" ] || [ -z "$target_port" ]; then
            echo -e "${Error} 目标地址和端口不能为空"
            return 1
        fi
        
        if ! read_port_config; then
            return 1
        fi
        
        local my_ip=$(curl -s4m5 ip.sb 2>/dev/null || curl -s4m5 ifconfig.me 2>/dev/null)
        [ -z "$my_ip" ] && my_ip="YOUR_IP"
        
        add_relay "$local_port" "$target_host" "$target_port"
        restart_gost
        
        echo -e ""
        echo -e "${Green}===========================================${Reset}"
        echo -e "${Info} 中转配置完成!"
        echo -e "${Green}===========================================${Reset}"
        echo -e " 本机IP:    ${Cyan}${my_ip}${Reset}"
        echo -e " 本地端口:  ${Cyan}${local_port}${Reset}"
        echo -e " 目标地址:  ${target_host}:${target_port}"
        echo -e "${Green}===========================================${Reset}"
    fi
}

# ==================== 批量添加中转 ====================
batch_add_relay() {
    echo -e ""
    echo -e "${Info} 批量添加中转配置"
    echo -e "${Tip} 请输入节点链接，每行一个，输入空行结束"
    echo -e "-----------------------------------"
    
    local links=()
    while true; do
        read -p "> " line
        if [ -z "$line" ]; then
            break
        fi
        links+=("$line")
    done
    
    if [ ${#links[@]} -eq 0 ]; then
        echo -e "${Error} 没有输入任何链接"
        return 1
    fi
    
    echo -e ""
    echo -e "${Info} 共输入 ${#links[@]} 个链接"
    
    echo -e ""
    echo -e "${Info} 端口分配方式:"
    echo -e "[1] 从指定端口开始递增"
    echo -e "[2] 随机分配"
    read -p "请选择 [默认1]: " port_mode
    port_mode=${port_mode:-1}
    
    local start_port=10000
    if [ "$port_mode" == "1" ]; then
        read -p "请输入起始端口 [默认10000]: " start_port
        start_port=${start_port:-10000}
    fi
    
    local my_ip=$(curl -s4m5 ip.sb 2>/dev/null || curl -s4m5 ifconfig.me 2>/dev/null)
    [ -z "$my_ip" ] && my_ip="YOUR_IP"
    
    local current_port=$start_port
    local success_count=0
    
    echo -e ""
    echo -e "${Info} 开始批量添加..."
    echo -e ""
    
    for link in "${links[@]}"; do
        local proto=$(detect_protocol "$link")
        if [ "$proto" == "unknown" ]; then
            echo -e "${Warning} 跳过无法识别的链接: ${link:0:50}..."
            continue
        fi
        
        local parsed=$(parse_node "$link")
        local target=$(get_target "$proto" "$parsed")
        IFS='|' read -r target_host target_port <<< "$target"
        
        if [ -z "$target_host" ] || [ -z "$target_port" ]; then
            echo -e "${Warning} 跳过解析失败的链接"
            continue
        fi
        
        local port_type=$(detect_protocol_type "$proto")
        
        # 获取可用端口
        if [ "$port_mode" == "1" ]; then
            while ! check_port $current_port; do
                ((current_port++))
            done
            local_port=$current_port
            ((current_port++))
        else
            local_port=$(get_random_port 10000 65535)
            while ! check_port $local_port; do
                local_port=$(get_random_port 10000 65535)
            done
        fi
        
        open_port "$local_port"
        echo "$local_port" >> "$PORT_CONF"
        add_relay "$local_port" "$target_host" "$target_port" "$port_type"
        
        local relay_link=$(generate_relay_link "$proto" "$parsed" "$my_ip" "$local_port")
        echo -e "${Info} [${proto^^}] ${target_host}:${target_port} -> :${local_port} (${port_type})"
        echo -e "    ${Cyan}${relay_link}${Reset}"
        echo -e ""
        
        ((success_count++))
    done
    
    if [ $success_count -gt 0 ]; then
        restart_gost
        echo -e "${Info} 批量添加完成! 成功: ${success_count}/${#links[@]}"
    else
        echo -e "${Warning} 没有成功添加任何配置"
    fi
}

# ==================== 查看配置 ====================
show_config() {
    echo -e ""
    echo -e "${Green}==================== 当前配置 ====================${Reset}"
    
    if [ ! -f "$RAW_CONF" ] || [ ! -s "$RAW_CONF" ]; then
        echo -e "${Warning} 暂无配置"
        return
    fi
    
    printf "%-4s | %-6s | %-8s | %s\n" "序号" "类型" "本地端口" "目标地址"
    echo "------------------------------------------------"
    
    local i=1
    while IFS='|' read -r type proto port host dport; do
        printf "%-4s | %-6s | %-8s | %s\n" "$i" "${proto^^}" "$port" "$host:$dport"
        ((i++))
    done < "$RAW_CONF"
    
    echo -e "${Green}==================================================${Reset}"
}

# ==================== 删除配置 ====================
delete_config() {
    show_config
    
    if [ ! -s "$RAW_CONF" ]; then
        return
    fi
    
    read -p "删除序号 (0取消): " num
    [ "$num" == "0" ] && return
    
    if ! [[ "$num" =~ ^[0-9]+$ ]]; then
        echo -e "${Error} 无效输入"
        return
    fi
    
    local line=$(sed -n "${num}p" "$RAW_CONF")
    if [ -z "$line" ]; then
        echo -e "${Error} 配置不存在"
        return
    fi
    
    IFS='|' read -ra p <<< "$line"
    local port="${p[2]}"
    
    sed -i "${num}d" "$RAW_CONF"
    sed -i "/^${port}$/d" "$PORT_CONF"
    
    # 重建配置
    cat > "$GOST_CONF" << 'EOF'
services: []
EOF
    
    while IFS='|' read -r type proto port host dport; do
        local config=$(generate_gost_config "$port" "$host" "$dport" "$proto")
        if grep -q "^services: \[\]$" "$GOST_CONF"; then
            cat > "$GOST_CONF" << EOF
services:
${config}
EOF
        else
            echo "$config" >> "$GOST_CONF"
        fi
    done < "$RAW_CONF"
    
    restart_gost
    echo -e "${Info} 已删除"
}

# ==================== 卸载 ====================
uninstall() {
    echo -e "${Warning} 确定卸载? [y/N]"
    read -p "" confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && return
    
    systemctl stop gost 2>/dev/null
    systemctl disable gost 2>/dev/null
    rm -f "$SERVICE_FILE"
    rm -f "$GOST_BIN"
    rm -rf "$GOST_DIR"
    systemctl daemon-reload
    
    echo -e "${Info} 已卸载"
}

# ==================== 快捷命令 ====================
install_shortcut() {
    local current_script=$(readlink -f "$0")
    cp "$current_script" /usr/local/bin/gost
    chmod +x /usr/local/bin/gost
    echo -e "${Info} 快捷命令安装完成！"
    echo -e "${Tip} 现在可以直接输入 ${Green}gost${Reset} 进入管理菜单"
}

# ==================== 状态显示 ====================
show_status() {
    echo -e ""
    echo -e "${Green}==================== 状态 ====================${Reset}"
    echo -n " GOST: "
    status_gost
    
    local count=0
    [ -f "$RAW_CONF" ] && count=$(wc -l < "$RAW_CONF" | tr -d ' ')
    echo -e " 中转数: ${Cyan}${count}${Reset}"
    
    local ip=$(curl -s4m3 ip.sb 2>/dev/null)
    echo -e " IP: ${Cyan}${ip:-获取中...}${Reset}"
    echo -e "${Green}================================================${Reset}"
}

# ==================== 主菜单 ====================
show_menu() {
    clear
    show_status
    
    echo -e "
${Green}========================================================${Reset}
   GOST v3 中转脚本 - 普通 VPS 版 ${Red}[${shell_version}]${Reset}
${Green}========================================================${Reset}
 ${Cyan}支持: VLESS VMess Trojan SS Hy2 TUIC Reality${Reset}
${Green}--------------------------------------------------------${Reset}
 ${Green}1.${Reset}  安装 GOST v3
 ${Green}2.${Reset}  卸载 GOST v3
${Green}--------------------------------------------------------${Reset}
 ${Green}3.${Reset}  启动 GOST
 ${Green}4.${Reset}  停止 GOST
 ${Green}5.${Reset}  重启 GOST
 ${Green}6.${Reset}  查看日志
${Green}--------------------------------------------------------${Reset}
 ${Green}7.${Reset}  添加中转配置
 ${Green}8.${Reset}  批量添加中转
 ${Green}9.${Reset}  查看当前配置
 ${Green}10.${Reset} 删除配置
${Green}--------------------------------------------------------${Reset}
 ${Green}11.${Reset} 安装快捷命令 (gost)
${Green}--------------------------------------------------------${Reset}
 ${Green}0.${Reset}  退出
${Green}========================================================${Reset}
"
    read -p " 请选择 [0-11]: " num
    
    case "$num" in
        0) exit 0 ;;
        1) install_gost ;;
        2) uninstall ;;
        3) start_gost ;;
        4) stop_gost ;;
        5) restart_gost ;;
        6) show_log ;;
        7) add_relay_config ;;
        8) batch_add_relay ;;
        9) show_config ;;
        10) delete_config ;;
        11) install_shortcut ;;
        *) echo -e "${Error} 无效选择" ;;
    esac
    
    echo -e ""
    read -p "按回车继续..."
}

# ==================== 主程序 ====================
main() {
    check_root
    init_dirs
    
    while true; do
        show_menu
    done
}

main
