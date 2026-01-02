#!/bin/bash
# Multi-EasyGost v3 - Serv00/FreeBSD 版本
# 基于 KANIKIG/Multi-EasyGost 重写，适配 GOST v3 (YAML 配置)
# 项目地址: https://github.com/go-gost/gost
# 文档: https://gost.run
# 适用于 Serv00/HostUno FreeBSD 非 root 环境

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Yellow_font_prefix="\033[33m"
Green_background_prefix="\033[42;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Warning="${Yellow_font_prefix}[警告]${Font_color_suffix}"

shell_version="3.0.0"
gost_version="3.0.0"

# 目录配置 (用户目录)
GOST_DIR="$HOME/.gost3"
GOST_BIN="$GOST_DIR/gost"
GOST_CONF="$GOST_DIR/config.yaml"
RAW_CONF="$GOST_DIR/rawconf"
CERT_DIR="$HOME/gost_cert"
PID_FILE="$GOST_DIR/gost.pid"

# ==================== 系统检测 ====================
check_sys() {
    local os=$(uname -s)
    if [[ "$os" != "FreeBSD" && "$os" != "Linux" ]]; then
        echo -e "${Warning} 当前系统: $os"
    fi
    
    local bit=$(uname -m)
    case "$bit" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        i386|i686) ARCH="386" ;;
        armv7*) ARCH="armv7" ;;
        *) 
            echo -e "${Warning} 未识别的架构: $bit"
            read -p "请输入架构 (amd64/arm64/386): " ARCH
            ;;
    esac
    
    # 检测 FreeBSD
    OS_TYPE="linux"
    if [[ "$os" == "FreeBSD" ]]; then
        OS_TYPE="freebsd"
    fi
}

# ==================== 安装 GOST ====================
install_gost() {
    check_sys
    
    echo -e "${Info} 开始安装 GOST v3..."
    
    # 创建目录
    mkdir -p "$GOST_DIR"
    
    # 下载 GOST v3
    local url="https://github.com/go-gost/gost/releases/download/v${gost_version}/gost_${gost_version}_${OS_TYPE}_${ARCH}.tar.gz"
    echo -e "${Info} 下载地址: $url"
    
    cd "$GOST_DIR"
    if command -v wget &>/dev/null; then
        wget -q --show-progress "$url" -O gost.tar.gz
    elif command -v curl &>/dev/null; then
        curl -L "$url" -o gost.tar.gz
    else
        echo -e "${Error} 请安装 wget 或 curl"
        return 1
    fi
    
    if [[ ! -f gost.tar.gz ]]; then
        echo -e "${Error} 下载失败"
        return 1
    fi
    
    tar -xzf gost.tar.gz
    chmod +x gost
    rm -f gost.tar.gz
    
    # 初始化配置
    cat > "$GOST_CONF" << 'EOF'
services: []
chains: []
EOF
    
    touch "$RAW_CONF"
    
    echo -e "${Info} GOST v3 安装完成!"
    echo -e "${Info} 二进制: $GOST_BIN"
    echo -e "${Info} 配置文件: $GOST_CONF"
}

# ==================== 卸载 GOST ====================
uninstall_gost() {
    echo -e "${Warning} 确定要卸载 GOST? [y/N]"
    read -r confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && return
    
    stop_gost
    rm -rf "$GOST_DIR"
    
    echo -e "${Info} GOST 已卸载"
}

# ==================== 进程管理 ====================
start_gost() {
    if [[ ! -f "$GOST_BIN" ]]; then
        echo -e "${Error} GOST 未安装，请先安装"
        return 1
    fi
    
    # 检查是否已运行
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${Warning} GOST 已在运行 (PID: $pid)"
            return 0
        fi
    fi
    
    # 启动 GOST
    nohup "$GOST_BIN" -C "$GOST_CONF" > "$GOST_DIR/gost.log" 2>&1 &
    echo $! > "$PID_FILE"
    
    sleep 1
    if kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo -e "${Info} GOST 启动成功 (PID: $(cat $PID_FILE))"
    else
        echo -e "${Error} GOST 启动失败"
        cat "$GOST_DIR/gost.log"
    fi
}

stop_gost() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            rm -f "$PID_FILE"
            echo -e "${Info} GOST 已停止"
        else
            rm -f "$PID_FILE"
            echo -e "${Info} GOST 未在运行"
        fi
    else
        # 尝试查找并杀死进程
        pkill -f "$GOST_BIN" 2>/dev/null
        echo -e "${Info} GOST 已停止"
    fi
}

restart_gost() {
    stop_gost
    rebuild_config
    start_gost
}

status_gost() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${Green_font_prefix}运行中${Font_color_suffix} (PID: $pid)"
            return 0
        fi
    fi
    echo -e "${Red_font_prefix}已停止${Font_color_suffix}"
    return 1
}

show_log() {
    if [[ -f "$GOST_DIR/gost.log" ]]; then
        echo -e "${Info} 最近日志:"
        tail -50 "$GOST_DIR/gost.log"
    else
        echo -e "${Warning} 日志文件不存在"
    fi
}

# ==================== Devil 端口管理 ====================
add_devil_port() {
    local port=$1
    local proto=${2:-tcp}
    
    if command -v devil &>/dev/null; then
        devil port add "$proto" "$port" 2>/dev/null
        echo -e "${Info} Devil 端口已添加: $proto/$port"
    fi
}

check_port_available() {
    local port=$1
    if command -v sockstat &>/dev/null; then
        if sockstat -4 -l | grep -q ":$port "; then
            return 1
        fi
    elif command -v ss &>/dev/null; then
        if ss -tuln | grep -q ":$port "; then
            return 1
        fi
    fi
    return 0
}

# ==================== 配置管理 ====================

# 读取转发类型
read_protocol() {
    echo -e ""
    echo -e "请问您要设置哪种功能: "
    echo -e "-----------------------------------"
    echo -e "[1] TCP+UDP 流量转发 (不加密)"
    echo -e "说明: 一般设置在国内中转机上"
    echo -e "-----------------------------------"
    echo -e "[2] 加密隧道流量转发"
    echo -e "说明: 用于转发原本加密等级较低的流量"
    echo -e "-----------------------------------"
    echo -e "[3] 解密由 GOST 传输的流量并转发"
    echo -e "说明: 对于经由 GOST 加密中转的流量进行解密"
    echo -e "-----------------------------------"
    echo -e "[4] 一键安装 SS/SOCKS5/HTTP 代理"
    echo -e "说明: 使用 GOST 内置的代理协议"
    echo -e "-----------------------------------"
    echo -e "[5] 进阶：多落地均衡负载"
    echo -e "-----------------------------------"
    echo -e "[6] 进阶：转发 CDN 自选节点"
    echo -e "-----------------------------------"
    read -p "请选择: " num_protocol

    case "$num_protocol" in
        1) flag_a="nonencrypt" ;;
        2) encrypt_menu ;;
        3) decrypt_menu ;;
        4) proxy_menu ;;
        5) peer_menu ;;
        6) cdn_menu ;;
        *) echo -e "${Error} 无效选择"; exit 1 ;;
    esac
}

# 加密隧道菜单
encrypt_menu() {
    echo -e ""
    echo -e "请问您要设置的加密传输类型: "
    echo -e "-----------------------------------"
    echo -e "[1] TLS 隧道"
    echo -e "[2] WS 隧道"
    echo -e "[3] WSS 隧道"
    echo -e "-----------------------------------"
    read -p "请选择: " num_encrypt

    case "$num_encrypt" in
        1) 
            flag_a="encrypttls"
            echo -e "${Warning} 落地机是否开启了自定义 TLS 证书？[y/n]"
            read -r is_cert
            ;;
        2) flag_a="encryptws" ;;
        3) 
            flag_a="encryptwss"
            echo -e "${Warning} 落地机是否开启了自定义 TLS 证书？[y/n]"
            read -r is_cert
            ;;
        *) echo -e "${Error} 无效选择"; exit 1 ;;
    esac
}

# 解密菜单
decrypt_menu() {
    echo -e ""
    echo -e "请问您要设置的解密传输类型: "
    echo -e "-----------------------------------"
    echo -e "[1] TLS"
    echo -e "[2] WS"
    echo -e "[3] WSS"
    echo -e "-----------------------------------"
    read -p "请选择: " num_decrypt

    case "$num_decrypt" in
        1) flag_a="decrypttls" ;;
        2) flag_a="decryptws" ;;
        3) flag_a="decryptwss" ;;
        *) echo -e "${Error} 无效选择"; exit 1 ;;
    esac
}

# 代理菜单
proxy_menu() {
    echo -e ""
    echo -e "请问您要设置的代理类型: "
    echo -e "-----------------------------------"
    echo -e "[1] Shadowsocks"
    echo -e "[2] SOCKS5"
    echo -e "[3] HTTP"
    echo -e "-----------------------------------"
    read -p "请选择: " num_proxy

    case "$num_proxy" in
        1) flag_a="ss" ;;
        2) flag_a="socks" ;;
        3) flag_a="http" ;;
        *) echo -e "${Error} 无效选择"; exit 1 ;;
    esac
}

# 均衡负载菜单
peer_menu() {
    echo -e ""
    echo -e "请问您要设置的均衡负载传输类型: "
    echo -e "-----------------------------------"
    echo -e "[1] 不加密转发"
    echo -e "[2] TLS 隧道"
    echo -e "[3] WS 隧道"
    echo -e "[4] WSS 隧道"
    echo -e "-----------------------------------"
    read -p "请选择: " num_peer

    case "$num_peer" in
        1) flag_a="peerno" ;;
        2) flag_a="peertls" ;;
        3) flag_a="peerws" ;;
        4) flag_a="peerwss" ;;
        *) echo -e "${Error} 无效选择"; exit 1 ;;
    esac
}

# CDN 菜单
cdn_menu() {
    echo -e ""
    echo -e "请问您要设置的 CDN 传输类型: "
    echo -e "-----------------------------------"
    echo -e "[1] 不加密转发"
    echo -e "[2] WS 隧道"
    echo -e "[3] WSS 隧道"
    echo -e "-----------------------------------"
    read -p "请选择: " num_cdn

    case "$num_cdn" in
        1) flag_a="cdnno" ;;
        2) flag_a="cdnws" ;;
        3) flag_a="cdnwss" ;;
        *) echo -e "${Error} 无效选择"; exit 1 ;;
    esac
}

# 读取本地端口
read_s_port() {
    if [[ "$flag_a" == "ss" ]]; then
        read -p "请输入 SS 密码: " flag_b
    elif [[ "$flag_a" == "socks" ]]; then
        read -p "请输入 SOCKS5 密码: " flag_b
    elif [[ "$flag_a" == "http" ]]; then
        read -p "请输入 HTTP 密码: " flag_b
    else
        echo -e ""
        read -p "请输入本地监听端口: " flag_b
        # 添加 Devil 端口
        add_devil_port "$flag_b" "tcp"
        add_devil_port "$flag_b" "udp"
    fi
}

# 读取目标地址
read_d_ip() {
    if [[ "$flag_a" == "ss" ]]; then
        echo -e ""
        echo -e "请选择 SS 加密方式: "
        echo -e "-----------------------------------"
        echo -e "[1] aes-256-gcm"
        echo -e "[2] aes-128-gcm"
        echo -e "[3] chacha20-ietf-poly1305"
        echo -e "[4] xchacha20-ietf-poly1305"
        echo -e "-----------------------------------"
        read -p "请选择: " ss_encrypt
        case "$ss_encrypt" in
            1) flag_c="aes-256-gcm" ;;
            2) flag_c="aes-128-gcm" ;;
            3) flag_c="chacha20-ietf-poly1305" ;;
            4) flag_c="xchacha20-ietf-poly1305" ;;
            *) flag_c="aes-256-gcm" ;;
        esac
    elif [[ "$flag_a" == "socks" ]]; then
        read -p "请输入 SOCKS5 用户名: " flag_c
    elif [[ "$flag_a" == "http" ]]; then
        read -p "请输入 HTTP 用户名: " flag_c
    elif [[ "$flag_a" == "peer"* ]]; then
        echo -e ""
        read -p "请输入落地列表文件名 (不含后缀): " flag_c
        touch "$GOST_DIR/${flag_c}.txt"
        echo -e "${Info} 请依次输入落地 IP 和端口"
        while true; do
            read -p "落地 IP: " peer_ip
            read -p "落地端口: " peer_port
            echo "$peer_ip:$peer_port" >> "$GOST_DIR/${flag_c}.txt"
            read -p "是否继续添加? [Y/n]: " add_more
            [[ ${add_more} =~ ^[Nn]$ ]] && break
        done
        echo -e "${Info} 落地列表已保存到 $GOST_DIR/${flag_c}.txt"
    elif [[ "$flag_a" == "cdn"* ]]; then
        read -p "请输入自选 CDN IP: " flag_c
        echo -e "[1] 80  [2] 443  [3] 自定义"
        read -p "请选择端口: " cdn_port_choice
        case "$cdn_port_choice" in
            1) flag_c="$flag_c:80" ;;
            2) flag_c="$flag_c:443" ;;
            3) read -p "自定义端口: " custom_port; flag_c="$flag_c:$custom_port" ;;
        esac
    else
        echo -e ""
        if [[ ${is_cert} =~ ^[Yy]$ ]]; then
            echo -e "${Warning} 落地机开启自定义 TLS 证书，请填写域名"
        fi
        read -p "请输入目标 IP/域名: " flag_c
    fi
}

# 读取目标端口
read_d_port() {
    if [[ "$flag_a" == "ss" ]]; then
        read -p "请输入 SS 服务端口: " flag_d
        add_devil_port "$flag_d" "tcp"
    elif [[ "$flag_a" == "socks" ]]; then
        read -p "请输入 SOCKS5 服务端口: " flag_d
        add_devil_port "$flag_d" "tcp"
    elif [[ "$flag_a" == "http" ]]; then
        read -p "请输入 HTTP 服务端口: " flag_d
        add_devil_port "$flag_d" "tcp"
    elif [[ "$flag_a" == "peer"* ]]; then
        echo -e ""
        echo -e "请选择均衡负载策略: "
        echo -e "[1] round - 轮询"
        echo -e "[2] random - 随机"
        echo -e "[3] fifo - 优先级"
        read -p "请选择: " num_strategy
        case "$num_strategy" in
            1) flag_d="round" ;;
            2) flag_d="random" ;;
            3) flag_d="fifo" ;;
            *) flag_d="round" ;;
        esac
    elif [[ "$flag_a" == "cdn"* ]]; then
        read -p "请输入 Host 头: " flag_d
    else
        read -p "请输入目标端口: " flag_d
        if [[ ${is_cert} =~ ^[Yy]$ ]]; then
            flag_d="$flag_d?secure=true"
        fi
    fi
}

# 保存原始配置
write_rawconf() {
    echo "$flag_a/$flag_b#$flag_c#$flag_d" >> "$RAW_CONF"
}

# 解析原始配置
parse_rawconf() {
    local line="$1"
    is_encrypt="${line%%/*}"
    local rest="${line#*/}"
    s_port="${rest%%#*}"
    rest="${rest#*#}"
    d_ip="${rest%%#*}"
    d_port="${rest#*#}"
}

# 重建配置文件
rebuild_config() {
    # 开始 YAML
    echo "services:" > "$GOST_CONF"
    local chains_content=""
    local service_idx=0
    
    [[ ! -f "$RAW_CONF" ]] && echo "chains: []" >> "$GOST_CONF" && return
    
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        parse_rawconf "$line"
        
        case "$is_encrypt" in
            nonencrypt)
                # TCP+UDP 不加密转发
                cat >> "$GOST_CONF" << EOF
  - name: relay-tcp-${service_idx}
    addr: ":${s_port}"
    handler:
      type: tcp
    listener:
      type: tcp
    forwarder:
      nodes:
        - name: target
          addr: "${d_ip}:${d_port}"
  - name: relay-udp-${service_idx}
    addr: ":${s_port}"
    handler:
      type: udp
    listener:
      type: udp
    forwarder:
      nodes:
        - name: target
          addr: "${d_ip}:${d_port}"
EOF
                ;;
            encrypttls|encryptws|encryptwss)
                # 加密隧道
                local dialer_type="${is_encrypt#encrypt}"
                local secure_opt=""
                [[ "$d_port" == *"secure=true"* ]] && secure_opt="
        metadata:
          serverName: ${d_ip}"
                d_port="${d_port%%\?*}"
                
                cat >> "$GOST_CONF" << EOF
  - name: relay-${service_idx}
    addr: ":${s_port}"
    handler:
      type: tcp
      chain: chain-${service_idx}
    listener:
      type: tcp
  - name: relay-udp-${service_idx}
    addr: ":${s_port}"
    handler:
      type: udp
      chain: chain-${service_idx}
    listener:
      type: udp
EOF
                chains_content+="
  - name: chain-${service_idx}
    hops:
      - name: hop-0
        nodes:
          - name: node-0
            addr: \"${d_ip}:${d_port}\"
            connector:
              type: relay
            dialer:
              type: ${dialer_type}${secure_opt}"
                ;;
            decrypttls|decryptws|decryptwss)
                # 解密转发
                local listener_type="${is_encrypt#decrypt}"
                local cert_opts=""
                if [[ -d "$CERT_DIR" ]]; then
                    cert_opts="
      metadata:
        certFile: ${CERT_DIR}/cert.pem
        keyFile: ${CERT_DIR}/key.pem"
                fi
                
                cat >> "$GOST_CONF" << EOF
  - name: relay-${service_idx}
    addr: ":${s_port}"
    handler:
      type: relay
    listener:
      type: ${listener_type}${cert_opts}
    forwarder:
      nodes:
        - name: target
          addr: "${d_ip}:${d_port}"
EOF
                ;;
            ss)
                # Shadowsocks 代理
                cat >> "$GOST_CONF" << EOF
  - name: ss-${service_idx}
    addr: ":${d_port}"
    handler:
      type: ss
      auth:
        username: "${d_ip}"
        password: "${s_port}"
    listener:
      type: tcp
EOF
                ;;
            socks)
                # SOCKS5 代理
                cat >> "$GOST_CONF" << EOF
  - name: socks-${service_idx}
    addr: ":${d_port}"
    handler:
      type: socks5
      auth:
        username: "${d_ip}"
        password: "${s_port}"
    listener:
      type: tcp
EOF
                ;;
            http)
                # HTTP 代理
                cat >> "$GOST_CONF" << EOF
  - name: http-${service_idx}
    addr: ":${d_port}"
    handler:
      type: http
      auth:
        username: "${d_ip}"
        password: "${s_port}"
    listener:
      type: tcp
EOF
                ;;
            peerno|peertls|peerws|peerwss)
                # 均衡负载
                local peer_file="$GOST_DIR/${d_ip}.txt"
                local nodes=""
                local node_idx=0
                if [[ -f "$peer_file" ]]; then
                    while IFS= read -r peer_line; do
                        nodes+="
        - name: target-${node_idx}
          addr: \"${peer_line}\""
                        ((node_idx++))
                    done < "$peer_file"
                fi
                
                if [[ "$is_encrypt" == "peerno" ]]; then
                    cat >> "$GOST_CONF" << EOF
  - name: peer-${service_idx}
    addr: ":${s_port}"
    handler:
      type: tcp
    listener:
      type: tcp
    forwarder:
      nodes:${nodes}
      selector:
        strategy: ${d_port}
EOF
                else
                    local dialer_type="${is_encrypt#peer}"
                    cat >> "$GOST_CONF" << EOF
  - name: peer-${service_idx}
    addr: ":${s_port}"
    handler:
      type: tcp
      chain: chain-peer-${service_idx}
    listener:
      type: tcp
EOF
                    chains_content+="
  - name: chain-peer-${service_idx}
    hops:
      - name: hop-0
        nodes:${nodes}
        selector:
          strategy: ${d_port}"
                fi
                ;;
            cdnno|cdnws|cdnwss)
                # CDN 转发
                local cdn_addr="${d_ip}"
                local host_header="${d_port}"
                
                if [[ "$is_encrypt" == "cdnno" ]]; then
                    cat >> "$GOST_CONF" << EOF
  - name: cdn-${service_idx}
    addr: ":${s_port}"
    handler:
      type: tcp
    listener:
      type: tcp
    forwarder:
      nodes:
        - name: target
          addr: "${cdn_addr}"
          http:
            host: "${host_header}"
EOF
                else
                    local dialer_type="${is_encrypt#cdn}"
                    cat >> "$GOST_CONF" << EOF
  - name: cdn-${service_idx}
    addr: ":${s_port}"
    handler:
      type: tcp
      chain: chain-cdn-${service_idx}
    listener:
      type: tcp
EOF
                    chains_content+="
  - name: chain-cdn-${service_idx}
    hops:
      - name: hop-0
        nodes:
          - name: node-0
            addr: \"${cdn_addr}\"
            connector:
              type: relay
            dialer:
              type: ${dialer_type}
              metadata:
                host: \"${host_header}\""
                fi
                ;;
        esac
        
        ((service_idx++))
    done < "$RAW_CONF"
    
    # 添加 chains
    if [[ -n "$chains_content" ]]; then
        echo "chains:$chains_content" >> "$GOST_CONF"
    else
        echo "chains: []" >> "$GOST_CONF"
    fi
}

# 添加配置
add_config() {
    read_protocol
    read_s_port
    read_d_ip
    read_d_port
    write_rawconf
    restart_gost
    echo -e "${Info} 配置已添加并生效"
    show_all_config
}

# 显示所有配置
show_all_config() {
    echo -e ""
    echo -e "                      GOST 配置                        "
    echo -e "--------------------------------------------------------"
    printf "%-4s | %-16s | %-8s | %s\n" "序号" "方法" "本地端口" "目标地址"
    echo -e "--------------------------------------------------------"
    
    [[ ! -f "$RAW_CONF" ]] && echo -e "${Warning} 暂无配置" && return
    
    local i=1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        parse_rawconf "$line"
        
        local method_str=""
        case "$is_encrypt" in
            nonencrypt) method_str="不加密中转" ;;
            encrypttls) method_str="TLS 隧道加密" ;;
            encryptws) method_str="WS 隧道加密" ;;
            encryptwss) method_str="WSS 隧道加密" ;;
            decrypttls) method_str="TLS 解密" ;;
            decryptws) method_str="WS 解密" ;;
            decryptwss) method_str="WSS 解密" ;;
            ss) method_str="SS 代理" ;;
            socks) method_str="SOCKS5 代理" ;;
            http) method_str="HTTP 代理" ;;
            peerno) method_str="不加密均衡" ;;
            peertls) method_str="TLS 均衡" ;;
            peerws) method_str="WS 均衡" ;;
            peerwss) method_str="WSS 均衡" ;;
            cdnno) method_str="CDN 不加密" ;;
            cdnws) method_str="CDN WS" ;;
            cdnwss) method_str="CDN WSS" ;;
            *) method_str="未知" ;;
        esac
        
        printf "%-4s | %-16s | %-8s | %s\n" "$i" "$method_str" "$s_port" "$d_ip:$d_port"
        echo -e "--------------------------------------------------------"
        ((i++))
    done < "$RAW_CONF"
}

# 删除配置
delete_config() {
    show_all_config
    [[ ! -s "$RAW_CONF" ]] && return
    
    read -p "请输入要删除的配置编号 (0 取消): " num_delete
    [[ "$num_delete" == "0" ]] && return
    
    if [[ "$num_delete" =~ ^[0-9]+$ ]]; then
        sed -i "${num_delete}d" "$RAW_CONF" 2>/dev/null || \
        sed -i '' "${num_delete}d" "$RAW_CONF"  # BSD sed
        restart_gost
        echo -e "${Info} 配置已删除，服务已重启"
    else
        echo -e "${Error} 请输入正确数字"
    fi
}

# ==================== 证书管理 ====================
cert_menu() {
    echo -e ""
    echo -e "证书配置: "
    echo -e "-----------------------------------"
    echo -e "[1] 手动上传证书"
    echo -e "-----------------------------------"
    read -p "请选择: " num_cert

    if [[ "$num_cert" == "1" ]]; then
        mkdir -p "$CERT_DIR"
        echo -e "${Info} 请将证书文件上传到 $CERT_DIR 目录:"
        echo -e "  - cert.pem (证书)"
        echo -e "  - key.pem (私钥)"
    fi
}

# ==================== 主菜单 ====================
show_menu() {
    clear
    echo -e ""
    echo -e "    Multi-EasyGost v3 - Serv00 版 ${Red_font_prefix}[${shell_version}]${Font_color_suffix}"
    echo -e "    基于 GOST v3 (YAML 配置)"
    echo -e "    文档: https://gost.run"
    echo -e ""
    echo -e "=========================================="
    echo -e " ${Green_font_prefix}1.${Font_color_suffix} 安装 GOST v3"
    echo -e " ${Green_font_prefix}2.${Font_color_suffix} 卸载 GOST v3"
    echo -e "=========================================="
    echo -e " ${Green_font_prefix}3.${Font_color_suffix} 启动 GOST"
    echo -e " ${Green_font_prefix}4.${Font_color_suffix} 停止 GOST"
    echo -e " ${Green_font_prefix}5.${Font_color_suffix} 重启 GOST"
    echo -e " ${Green_font_prefix}6.${Font_color_suffix} 查看日志"
    echo -e "=========================================="
    echo -e " ${Green_font_prefix}7.${Font_color_suffix} 新增转发配置"
    echo -e " ${Green_font_prefix}8.${Font_color_suffix} 查看现有配置"
    echo -e " ${Green_font_prefix}9.${Font_color_suffix} 删除一则配置"
    echo -e "=========================================="
    echo -e " ${Green_font_prefix}10.${Font_color_suffix} TLS 证书配置"
    echo -e "=========================================="
    echo -e " ${Green_font_prefix}0.${Font_color_suffix} 退出脚本"
    echo -e "=========================================="
    echo -e ""
    
    # 显示服务状态
    echo -n " GOST 状态: "
    status_gost
    
    local count=0
    [[ -f "$RAW_CONF" ]] && count=$(wc -l < "$RAW_CONF" | tr -d ' ')
    echo -e " 配置数量: ${count}"
    echo -e ""
    
    read -p " 请输入数字 [0-10]: " num
    
    case "$num" in
        0) exit 0 ;;
        1) install_gost ;;
        2) uninstall_gost ;;
        3) start_gost ;;
        4) stop_gost ;;
        5) restart_gost ;;
        6) show_log ;;
        7) add_config ;;
        8) show_all_config ;;
        9) delete_config ;;
        10) cert_menu ;;
        *) echo -e "${Error} 请输入正确数字 [0-10]" ;;
    esac
    
    echo -e ""
    read -p "按回车继续..."
}

# ==================== 主程序 ====================
main() {
    while true; do
        show_menu
    done
}

main
