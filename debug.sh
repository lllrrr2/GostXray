#!/bin/bash
# 极简测试 - 只测试字符串操作

echo "===== VLESS 测试 ====="
link="vless://a3f82a14-68b4-4af5-b198-ed81c35510a0@171.22.79.195:50038?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.sega.com&fp=chrome&pbk=ZrPLMRSx1w5juholxKl9ncbpF6aNwu6tDXmoqnQexX0&sid=904f2e6e00bd9e5f&type=tcp&headerType=none#Misaka-Reality"

link="${link#vless://}"
echo "去掉前缀: $link"

uuid="${link%%@*}"
echo "UUID: $uuid"

rest="${link#*@}"
echo "Rest: $rest"

host_port="${rest%%\?*}"
echo "Host_Port: $host_port"

host="${host_port%%:*}"
echo "Host: $host"

port="${host_port##*:}"
echo "Port (raw): $port"

port="${port%%#*}"
echo "Port (clean): $port"

echo ""
echo "===== Hysteria2 测试 ====="
link2="hysteria2://e4ea9cf6@171.22.79.195:50036/?insecure=1&sni=www.bing.com#Misaka-Hysteria2"

link2="${link2#hysteria2://}"
echo "去掉前缀: $link2"

password="${link2%%@*}"
echo "Password: $password"

rest2="${link2#*@}"
echo "Rest: $rest2"

host_port2="${rest2%%\?*}"
echo "Host_Port: $host_port2"

host2="${host_port2%%:*}"
echo "Host: $host2"

port2="${host_port2##*:}"
echo "Port (raw): $port2"

port2="${port2%%/*}"
echo "Port (no slash): $port2"

port2="${port2%%#*}"
echo "Port (clean): $port2"

echo ""
echo "===== TUIC 测试 ====="
link3="tuic://8c0143ee-9ac9-4cf4-8dff-1554c193d78e:967b1af7@171.22.79.195:50037?congestion_control=bbr&udp_relay_mode=quic&alpn=h3#tuicv5-misaka"

link3="${link3#tuic://}"
echo "去掉前缀: $link3"

auth="${link3%%@*}"
echo "Auth: $auth"

uuid3="${auth%%:*}"
echo "UUID: $uuid3"

password3="${auth#*:}"
echo "Password: $password3"

rest3="${link3#*@}"
echo "Rest: $rest3"

host_port3="${rest3%%\?*}"
echo "Host_Port: $host_port3"

host3="${host_port3%%:*}"
echo "Host: $host3"

port3="${host_port3##*:}"
echo "Port (raw): $port3"

port3="${port3%%/*}"
echo "Port (no slash): $port3"

port3="${port3%%#*}"
echo "Port (clean): $port3"
