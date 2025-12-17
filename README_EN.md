# GOST v3 + Xray Relay Management Script

[中文文档](README.md)

A powerful relay/transit script supporting GOST v3 and Xray dokodemo-door with automatic proxy link parsing.

## 🚀 Quick Start

```bash
# Download script
wget -O gost.sh https://raw.githubusercontent.com/hxzlplp7/GostXray/main/gost.sh

# Run
chmod +x gost.sh && ./gost.sh
```

After installation, simply type `gost` anywhere to access the management menu!

## ✨ Features

| Feature | Description |
|---------|-------------|
| **GOST v3** | Latest GOST v3 with TCP+UDP forwarding |
| **Xray Dokodemo** | Transparent proxy relay via dokodemo-door |
| **Quick Command** | Type `gost` to access menu after installation |
| **Auto Parsing** | Automatically parse 8+ proxy protocol links |
| **Link Generation** | Auto-generate relay node links |
| **Batch Import** | Import multiple node links at once |
| **Port Management** | Random / Range / Manual port assignment |

## 📋 Supported Protocols

| Protocol | Link Format | Parse | Generate |
|----------|-------------|-------|----------|
| VLESS | `vless://...` | ✅ | ✅ |
| VMess | `vmess://...` | ✅ | ✅ |
| Trojan | `trojan://...` | ✅ | ✅ |
| Shadowsocks | `ss://...` | ✅ | ✅ |
| Hysteria2 | `hysteria2://...` / `hy2://...` | ✅ | ✅ |
| TUIC | `tuic://...` | ✅ | ✅ |
| SOCKS5 | `socks://...` / `socks5://...` | ✅ | ✅ |
| HTTP | `http://...` | ✅ | ✅ |

## 🎛️ Menu Options

```
========================================================
      GOST v3 + Xray Relay Management Script [v3.1.0]
========================================================
 Supports: VLESS VMess Trojan SS Hy2 TUIC SOCKS HTTP
--------------------------------------------------------
 1.  Install GOST v3        2.  Install Xray
 3.  Uninstall GOST v3      4.  Uninstall Xray
--------------------------------------------------------
 5.  Start GOST v3          6.  Stop GOST v3
 7.  Restart GOST v3        8.  View Logs
--------------------------------------------------------
 9.  Start Xray             10. Stop Xray
 11. Restart Xray           12. View Logs
--------------------------------------------------------
 13. Add Relay Config       14. Batch Add Relay
 15. View Current Config    16. Delete Config
--------------------------------------------------------
 17. Parse Node Link (Test) 18. Install Shortcut
--------------------------------------------------------
 0.  Exit
========================================================
```

## 📝 Usage Examples

### Single Node Relay

1. Run script: `gost` or `./gost.sh`
2. Select `13` to add relay config
3. Choose relay method (GOST or Xray)
4. Paste the node link
5. Select port assignment method
6. Copy the generated relay link

### Batch Import

1. Select `14` for batch import
2. Paste one node link per line, empty line to finish
3. Choose relay method and port assignment
4. Script will auto-add all relays and generate links

### Port Assignment Options

```
[1] Random port (10000-65535)
[2] Specify port range for auto-assignment
[3] Manual port input
```

## 🔧 Configuration Files

| File | Path | Description |
|------|------|-------------|
| GOST Config | `/etc/gost3/config.yaml` | GOST v3 YAML config |
| Xray Config | `/etc/xray/config.json` | Xray JSON config |
| Raw Records | `/etc/gost3/rawconf` | Relay config records |
| Port Records | `/etc/gost3/ports.conf` | Used ports |
| Shortcut | `/usr/local/bin/gost` | Quick launch script |

## 🌐 Use Cases

### Route Optimization
```
User → Relay Server (GOST/Xray) → Target Node
```

### Multi-hop Relay
```
User → Entry Server → Relay Server → Exit Server
```

### Load Balancing
Configure multiple relay rules pointing to different ports of the same target

## ⚙️ System Requirements

- Linux (Debian/Ubuntu/CentOS)
- Root privileges
- Firewall ports opened

## 📊 Status Display

On script start, it shows:
- GOST v3 running status
- Xray running status
- Number of relay configs
- Server public IP

## 🔄 Changelog

### v3.1.0
- ✅ Added `gost` shortcut command
- ✅ Added batch import feature
- ✅ Added service status display
- ✅ Added log viewing
- ✅ Enhanced protocol parsing
- ✅ Improved user experience
- ✅ Added installation prompts and error handling

### v3.0.0
- Full GOST v3 support
- Integrated Xray dokodemo-door
- 8 protocol parsing support
- Auto relay link generation

## 🙏 Credits

- [GOST](https://github.com/go-gost/gost) - GO Simple Tunnel
- [Xray-core](https://github.com/XTLS/Xray-core) - Xray
- [Multi-EasyGost](https://github.com/KANIKIG/Multi-EasyGost) - Original script

## 📄 License

MIT License
