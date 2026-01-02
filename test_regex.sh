#!/bin/bash

raw_input="vless://a3f82a14-68b4-4af5-b198-ed81c35510a0@171.22.79.195:50038?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.sega.com&fp=chrome&pbk=ZrPLMRSx1w5juholxKl9ncbpF6aNwu6tDXmoqnQexX0&sid=904f2e6e00bd9e5f&type=tcp&headerType=none#Misaka-Reality

hysteria2://e4ea9cf6@171.22.79.195:50036/?insecure=1&sni=www.bing.com#Misaka-Hysteria2

tuic://8c0143ee-9ac9-4cf4-8dff-1554c193d78e:967b1af7@171.22.79.195:50037?congestion_control=bbr&udp_relay_mode=quic&alpn=h3#tuicv5-misaka[信息] 检测到协议: VLESS"

echo "Raw input length: ${#raw_input}"

# Test 1: Original regex with [!-~]
echo "--- Test 1: [!-~] ---"
regex="(vless://[!-~]+|vmess://[!-~]+|trojan://[!-~]+|ss://[!-~]+|hysteria2://[!-~]+|hy2://[!-~]+|tuic://[!-~]+|socks://[!-~]+|socks5://[!-~]+|http://[!-~]+|https://[!-~]+)"
echo "$raw_input" | grep -oE "$regex"

# Test 2: Character class regex
echo "--- Test 2: Explicit character class ---"
# Standard URL characters + [ ] for IPv6
regex2="(vless://[][a-zA-Z0-9-._~:/?#@!$&'()*+,;=%]+|vmess://[][a-zA-Z0-9-._~:/?#@!$&'()*+,;=%]+|trojan://[][a-zA-Z0-9-._~:/?#@!$&'()*+,;=%]+|ss://[][a-zA-Z0-9-._~:/?#@!$&'()*+,;=%]+|hysteria2://[][a-zA-Z0-9-._~:/?#@!$&'()*+,;=%]+|hy2://[][a-zA-Z0-9-._~:/?#@!$&'()*+,;=%]+|tuic://[][a-zA-Z0-9-._~:/?#@!$&'()*+,;=%]+|socks://[][a-zA-Z0-9-._~:/?#@!$&'()*+,;=%]+|socks5://[][a-zA-Z0-9-._~:/?#@!$&'()*+,;=%]+|http://[][a-zA-Z0-9-._~:/?#@!$&'()*+,;=%]+|https://[][a-zA-Z0-9-._~:/?#@!$&'()*+,;=%]+)"
echo "$raw_input" | grep -oE "$regex2"

# Test 3: Simple non-space regex (for comparison)
echo "--- Test 3: [^[:space:]]+ ---"
regex3="(vless://[^[:space:]]+|vmess://[^[:space:]]+|tuic://[^[:space:]]+|hysteria2://[^[:space:]]+)"
echo "$raw_input" | grep -oE "$regex3"
