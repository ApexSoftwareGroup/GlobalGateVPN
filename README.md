# 🌐 GlobalGate VPN

**GlobalGate VPN** - A powerful VPN management tool using sing-box core. **Hundreds of free VPN servers from multiple countries worldwide!**

## ✨ Key Features

- **🚀 Instant Connection** - Fast server availability testing (just 2 ping requests)
- **🌍 Global Access** - Servers in different countries to bypass geo-restrictions
- **🔒 Complete Security** - Supports all modern protocols: Shadowsocks, VMess, VLESS, Trojan, Hysteria2
- **🛡️ Dual Operation Modes** - Choose what works best for you

## 🎮 Operation Modes

### 🌊 **TUN Mode (System-wide VPN)**
- **All traffic** on your computer goes through VPN
- Works with **any application** - browsers, games, messengers
- Full system-level encryption
- **Requires administrator privileges**

### 🔌 **Proxy Mode (Local Proxy)**
- Creates local SOCKS5 proxy on 127.0.0.1:1080
- Perfect for browsers and apps with proxy support
- **No admin rights needed**
- Fine-tune routing for specific applications

## 🎯 Advantages

- **100% Free** - No subscriptions, no hidden costs
- **Auto-fallback** - If no proxy file found, uses built-in servers
- **Smart Selection** - Servers sorted by latency, shows country and response time
- **Instant Control** - Press `c` to switch servers, `q` to quit
- **Geo Detection** - Automatic server country identification

## 📦 Quick Start

1. Download **sing-box.exe** from [official releases](https://github.com/SagerNet/sing-box/releases) and place it in the program folder
2. **(Optional)** Download GeoIP database as `db.mmdb` for country detection
3. **(Optional)** Create `proxies.txt` with your proxy links
4. Run the program:

```bash
go build -o globalgate.exe
globalgate.exe
```

## 🔧 Supported Formats

- `ss://` - Shadowsocks
- `vmess://` - VMess
- `vless://` - VLESS
- `trojan://` - Trojan
- `hy2://` or `hysteria2://` - Hysteria2

## 🎮 How to Use

1. **Quick Test** - All proxies are automatically tested for connectivity
2. **Select Server** - Press the number of the server you want
3. **Choose Mode**:
   - `1` - Proxy mode (SOCKS5) - for most users
   - `2` - TUN mode (system VPN) - requires admin rights
4. **Control**:
   - `c` - change server without stopping
   - `q` - quit program

## 📁 Configuration Files

- `proxies.txt` - Your custom proxy list (optional)
- `working_proxies.txt` - List of working servers with latency
- `db.mmdb` - GeoIP database for country detection (optional)
- `sing-box.log` - VPN runtime logs

## ⚙️ System Requirements

- Windows OS
- sing-box.exe in the same folder
- Administrator privileges (TUN mode only)

## 🛠 Building from Source

```bash
go mod init globalgate
go get github.com/oschwald/geoip2-golang
go get golang.org/x/term
go build -o globalgate.exe
```

## 🌟 Why GlobalGate VPN?

- **True Freedom** - Bypass geographical restrictions
- **Two in One** - Choose between system VPN and local proxy
- **Instant** - Quick connection with no waiting
- **Simple** - Intuitive interface, all keyboard-controlled
- **Reliable** - Powered by proven sing-box core

## 📜 License

MIT License

---

**GlobalGate VPN** - Open the world without borders! 🔓🌍
