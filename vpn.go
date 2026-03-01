// proxy_checker.go
package main

import (
    "bufio"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net"
    "os"
    "os/exec"
    "path/filepath"
    "regexp"
    "sort"
    "strconv"
    "strings"
    "syscall"
    "time"
    "unsafe"
    
    "github.com/oschwald/geoip2-golang"
    "golang.org/x/term"
)

// Proxy configuration
type ProxyConfig struct {
    Type     string      `json:"type"`
    Server   string      `json:"server"`
    Port     int         `json:"port"`
    Method   string      `json:"method,omitempty"`
    Password string      `json:"password,omitempty"`
    ID       string      `json:"id,omitempty"`
    Aid      interface{} `json:"aid,omitempty"`
    Net      string      `json:"net,omitempty"`
    TLS      string      `json:"tls,omitempty"`
    Host     string      `json:"host,omitempty"`
    Path     string      `json:"path,omitempty"`
    Flow     string      `json:"flow,omitempty"`
    Security string      `json:"security,omitempty"`
    SNI      string      `json:"sni,omitempty"`
    PBK      string      `json:"pbk,omitempty"`
    SID      string      `json:"sid,omitempty"`
    FP       string      `json:"fp,omitempty"`
    Insecure bool        `json:"insecure,omitempty"`
    Raw      string      `json:"-"`
    
    // Check results
    Latency float64 `json:"-"`
    Country string  `json:"-"`
    Working bool    `json:"-"`
}

// Configuration for sing-box
type SingBoxConfig struct {
    Log      LogConfig        `json:"log"`
    DNS      DNSConfig        `json:"dns"`
    Inbounds []InboundConfig  `json:"inbounds"`
    Outbounds []OutboundConfig `json:"outbounds"`
    Route    RouteConfig      `json:"route"`
    Experimental *ExperimentalConfig `json:"experimental,omitempty"`
}

type LogConfig struct {
    Level     string `json:"level"`
    Timestamp bool   `json:"timestamp"`
    Output    string `json:"output"`
}

type DNSConfig struct {
    Servers []DNSServer `json:"servers"`
    Rules   []DNSRule   `json:"rules"`
    Strategy string     `json:"strategy"`
    Final    string     `json:"final,omitempty"`
}

type DNSServer struct {
    Tag     string `json:"tag"`
    Address string `json:"address"`
    Detour  string `json:"detour,omitempty"`
}

type DNSRule struct {
    Outbound string `json:"outbound"`
    Server   string `json:"server"`
}

type InboundConfig struct {
    Type          string   `json:"type"`
    Tag           string   `json:"tag"`
    Listen        string   `json:"listen,omitempty"`
    ListenPort    int      `json:"listen_port,omitempty"`
    InterfaceName string   `json:"interface_name,omitempty"`
    Address       []string `json:"address,omitempty"`
    MTU           int      `json:"mtu,omitempty"`
    AutoRoute     bool     `json:"auto_route,omitempty"`
    StrictRoute   bool     `json:"strict_route,omitempty"`
    Sniff         bool     `json:"sniff,omitempty"`
    Stack         string   `json:"stack,omitempty"`
    SniffOverrideDestination bool `json:"sniff_override_destination,omitempty"`
    DomainStrategy string   `json:"domain_strategy,omitempty"`
}

type OutboundConfig struct {
    Type       string           `json:"type"`
    Tag        string           `json:"tag"`
    Server     string           `json:"server,omitempty"`
    ServerPort int              `json:"server_port,omitempty"`
    Method     string           `json:"method,omitempty"`
    Password   string           `json:"password,omitempty"`
    UUID       string           `json:"uuid,omitempty"`
    AlterID    int              `json:"alter_id,omitempty"`
    Security   string           `json:"security,omitempty"`
    Flow       string           `json:"flow,omitempty"`
    Transport  *TransportConfig `json:"transport,omitempty"`
    TLS        *TLSConfig       `json:"tls,omitempty"`
}

type TransportConfig struct {
    Type    string            `json:"type"`
    Path    string            `json:"path,omitempty"`
    Headers map[string]string `json:"headers,omitempty"`
    Host    []string          `json:"host,omitempty"`
    ServiceName string        `json:"service_name,omitempty"`
}

type TLSConfig struct {
    Enabled    bool          `json:"enabled"`
    ServerName string        `json:"server_name,omitempty"`
    Insecure   bool          `json:"insecure,omitempty"`
    UTLS       *UTLSConfig   `json:"utls,omitempty"`
    Reality    *RealityConfig `json:"reality,omitempty"`
    MinVersion string        `json:"min_version,omitempty"`
    MaxVersion string        `json:"max_version,omitempty"`
    CipherSuites []string    `json:"cipher_suites,omitempty"`
}

type UTLSConfig struct {
    Enabled     bool   `json:"enabled"`
    Fingerprint string `json:"fingerprint,omitempty"`
}

type RealityConfig struct {
    Enabled   bool   `json:"enabled"`
    PublicKey string `json:"public_key,omitempty"`
    ShortID   string `json:"short_id,omitempty"`
}

type RouteConfig struct {
    Rules   []RuleConfig `json:"rules"`
    Final   string       `json:"final"`
    AutoDetectInterface bool `json:"auto_detect_interface"`
}

type RuleConfig struct {
    Protocol string `json:"protocol,omitempty"`
    Network  string `json:"network,omitempty"`
    Port     int    `json:"port,omitempty"`
    Outbound string `json:"outbound"`
}

type ExperimentalConfig struct {
    CacheFile *CacheFileConfig `json:"cache_file,omitempty"`
}

type CacheFileConfig struct {
    Enabled  bool   `json:"enabled"`
    Path     string `json:"path"`
    CacheID  string `json:"cache_id"`
}

// URL structure for parsing
type ParsedURL struct {
    Scheme string
    Host   string
    User   string
    Query  urlValues
}

type urlValues map[string][]string

func (u urlValues) Get(key string) string {
    if vals, ok := u[key]; ok && len(vals) > 0 {
        return vals[0]
    }
    return ""
}

// Global variables
var currentCmd *exec.Cmd
var currentConfigPath string
var geoIPDB *geoip2.Reader
var workingProxies []*ProxyConfig
var ansiEscape = regexp.MustCompile(`\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])`)

func cleanOutput(text string) string {
    return ansiEscape.ReplaceAllString(text, "")
}

// Function for instant key reading without Enter
func getch() (byte, error) {
    oldState, err := term.MakeRaw(int(syscall.Stdin))
    if err != nil {
        return 0, err
    }
    defer term.Restore(int(syscall.Stdin), oldState)
    
    var buf [1]byte
    _, err = syscall.Read(syscall.Stdin, buf[:])
    return buf[0], err
}

// Function for instant number input
func readNumber() (int, error) {
    var numStr string
    for {
        b, err := getch()
        if err != nil {
            return 0, err
        }
        
        if b == 13 || b == 10 { // Enter
            if numStr == "" {
                return 1, nil // Enter = select first
            }
            break
        }
        
        if b == 'q' || b == 'Q' {
            return -1, nil
        }
        
        if b == 'c' || b == 'C' {
            return -2, nil
        }
        
        if b >= '0' && b <= '9' {
            numStr += string(b)
            fmt.Print(string(b))
        }
    }
    fmt.Println()
    
    if numStr == "" {
        return 1, nil
    }
    
    return strconv.Atoi(numStr)
}

// Function for instant mode selection
func readMode() (int, error) {
    for {
        b, err := getch()
        if err != nil {
            return 0, err
        }
        
        if b == 13 || b == 10 { // Enter
            return 1, nil // Enter = mode 1
        }
        
        if b == '1' {
            return 1, nil
        }
        if b == '2' {
            return 2, nil
        }
    }
}

// Check for administrator privileges
func isAdmin() bool {
    _, err := os.Open("\\\\.\\PHYSICALDRIVE0")
    return err == nil
}

// Request administrator rights via Shell32.dll
func requestAdmin() {
    shell32 := syscall.NewLazyDLL("shell32.dll")
    procShellExecuteW := shell32.NewProc("ShellExecuteW")
    
    hwnd := uintptr(0)
    operation := uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("runas")))
    file := uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(os.Args[0])))
    parameters := uintptr(0)
    directory := uintptr(0)
    showCmd := uintptr(1)
    
    ret, _, _ := procShellExecuteW.Call(
        hwnd,
        operation,
        file,
        parameters,
        directory,
        showCmd,
    )
    
    if ret <= 32 {
        fmt.Printf("[!] Failed to request admin rights (error code: %d)\n", ret)
    }
    
    os.Exit(0)
}

func main() {
    fmt.Println("\n" + strings.Repeat("=", 60))
    fmt.Println("PROXY CHECKER AND LAUNCHER WITH SING-BOX")
    fmt.Println("(Press number keys instantly - no Enter needed)")
    fmt.Println(strings.Repeat("=", 60))
    
    loadGeoIPDB()
    
    // Check administrator privileges
    admin := isAdmin()
    if admin {
        fmt.Println("[✓] Running with administrator privileges")
    } else {
        fmt.Println("[!] Running with user privileges")
        fmt.Println("[!] TUN mode will require administrator privileges")
    }
    
    fmt.Println("\nCommands:")
    fmt.Println("  Numbers: select proxy")
    fmt.Println("  'c': change proxy while running")
    fmt.Println("  'q': quit")
    fmt.Println(strings.Repeat("-", 60))
    
    allProxies := loadProxiesFromFile("proxies.txt")
    if len(allProxies) == 0 {
        fmt.Println("[!] No proxies to check. Add them to proxies.txt")
        return
    }
    
    fmt.Printf("\n[*] Checking %d proxies (timeout 5s)...\n", len(allProxies))
    workingProxies = checkAllProxies(allProxies)
    
    sort.Slice(workingProxies, func(i, j int) bool {
        return workingProxies[i].Latency < workingProxies[j].Latency
    })
    
    fmt.Printf("\n[✓] Found %d working proxies\n", len(workingProxies))
    
    if len(workingProxies) == 0 {
        fmt.Println("[!] No working proxies found. Check your proxies.txt file.")
        return
    }
    
    saveWorkingProxies(workingProxies)
    fmt.Println("[✓] Working proxies list saved to working_proxies.txt")
    
    // Main loop
    for {
        // Select proxy
        selectedProxy := selectProxyInstant(workingProxies)
        if selectedProxy == nil {
            fmt.Println("\n[!] No proxy selected. Exiting.")
            return
        }
        
        // Select mode
        useTUN := selectModeInstant()
        
        // Check privileges for TUN mode
        if useTUN && !admin {
            fmt.Println("\n" + strings.Repeat("=", 50))
            fmt.Println("TUN MODE REQUIRES ADMINISTRATOR PRIVILEGES")
            fmt.Println(strings.Repeat("=", 50))
            fmt.Println("\nThe program will now request administrator access.")
            fmt.Println("Please click 'Yes' in the UAC prompt that appears.")
            fmt.Println("\nAfter granting admin rights, the program will restart.")
            fmt.Print("\nPress Enter to continue...")
            bufio.NewReader(os.Stdin).ReadBytes('\n')
            
            requestAdmin()
            return
        }
        
        fmt.Printf("\n[✓] Selected: %s://%s:%d\n", selectedProxy.Type, selectedProxy.Server, selectedProxy.Port)
        fmt.Printf("[✓] Country: %s, Latency: %.0fms\n", selectedProxy.Country, selectedProxy.Latency)
        
        config := generateSingBoxConfig(selectedProxy, useTUN)
        if config == nil {
            fmt.Println("[!] Failed to generate config")
            continue
        }
        
        fmt.Println("\n[*] Launching proxy...")
        if runSingBox(config) {
            fmt.Println("[✓] Sing-box started successfully")
            if useTUN {
                fmt.Println("[*] TUN interface created - system-wide VPN active")
            } else {
                fmt.Println("[*] SOCKS5/HTTP proxy running on 127.0.0.1:1080")
            }
            fmt.Println("[*] Press 'c' to change proxy, 'q' to quit")
            
            // Monitor output and wait for command
            shouldChange := monitorSingBoxOutputInstant()
            
            if shouldChange {
                fmt.Println("\n[*] Ready to select new proxy...\n")
                time.Sleep(500 * time.Millisecond)
                continue
            } else {
                break
            }
        } else {
            fmt.Println("[!] Failed to start sing-box")
            fmt.Println("[*] Press any key to try another proxy...")
            getch()
            continue
        }
    }
    
    if geoIPDB != nil {
        geoIPDB.Close()
    }
}

// Load GeoIP database
func loadGeoIPDB() {
    if _, err := os.Stat("db.mmdb"); err == nil {
        db, err := geoip2.Open("db.mmdb")
        if err == nil {
            geoIPDB = db
            fmt.Println("[✓] GeoIP database loaded")
        } else {
            fmt.Println("[!] Failed to load GeoIP database:", err)
        }
    } else {
        fmt.Println("[!] GeoIP database not found (db.mmdb)")
    }
}

// Load proxies from file
func loadProxiesFromFile(filename string) []*ProxyConfig {
    file, err := os.Open(filename)
    if err != nil {
        fmt.Printf("[!] File %s not found. Creating empty file.\n", filename)
        os.Create(filename)
        return []*ProxyConfig{}
    }
    defer file.Close()
    
    var proxies []*ProxyConfig
    scanner := bufio.NewScanner(file)
    
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
            continue
        }
        
        proxy := parseProxyLine(line)
        if proxy != nil {
            proxies = append(proxies, proxy)
        }
    }
    
    fmt.Printf("[✓] Loaded %d proxies from file\n", len(proxies))
    return proxies
}

// Parse proxy line
func parseProxyLine(line string) *ProxyConfig {
    switch {
    case strings.HasPrefix(line, "ss://"):
        return parseSS(line)
    case strings.HasPrefix(line, "vmess://"):
        return parseVMess(line)
    case strings.HasPrefix(line, "vless://"):
        return parseVLess(line)
    case strings.HasPrefix(line, "trojan://"):
        return parseTrojan(line)
    case strings.HasPrefix(line, "hy2://"):
        return parseHy2(line)
    default:
        return nil
    }
}

// Base64 decode
func base64Decode(s string) ([]byte, error) {
    s = strings.ReplaceAll(s, "_", "/")
    s = strings.ReplaceAll(s, "-", "+")
    
    if len(s)%4 != 0 {
        s += strings.Repeat("=", 4-len(s)%4)
    }
    
    return base64.StdEncoding.DecodeString(s)
}

// Parse Shadowsocks
func parseSS(link string) *ProxyConfig {
    if idx := strings.Index(link, "#"); idx != -1 {
        link = link[:idx]
    }
    
    // Support different ss:// formats
    if strings.Contains(link, "@") {
        re := regexp.MustCompile(`ss://([^@]+)@([^:]+):(\d+)`)
        matches := re.FindStringSubmatch(link)
        if len(matches) == 4 {
            userInfo := matches[1]
            server := matches[2]
            port, _ := strconv.Atoi(matches[3])
            
            var method, password string
            
            decoded, err := base64Decode(userInfo)
            if err == nil {
                parts := strings.SplitN(string(decoded), ":", 2)
                if len(parts) == 2 {
                    method, password = parts[0], parts[1]
                }
            } else {
                parts := strings.SplitN(userInfo, ":", 2)
                if len(parts) == 2 {
                    method, password = parts[0], parts[1]
                }
            }
            
            return &ProxyConfig{
                Type:     "ss",
                Server:   server,
                Port:     port,
                Method:   method,
                Password: password,
                Raw:      link,
            }
        }
    }
    
    return nil
}

// Parse VMess
func parseVMess(link string) *ProxyConfig {
    b64Str := strings.TrimPrefix(link, "vmess://")
    
    if idx := strings.Index(b64Str, "#"); idx != -1 {
        b64Str = b64Str[:idx]
    }
    
    decoded, err := base64Decode(b64Str)
    if err != nil {
        return nil
    }
    
    var data map[string]interface{}
    err = json.Unmarshal(decoded, &data)
    if err != nil {
        return nil
    }
    
    port := 0
    if p, ok := data["port"].(float64); ok {
        port = int(p)
    }
    
    return &ProxyConfig{
        Type:     "vmess",
        Server:   getString(data, "add"),
        Port:     port,
        ID:       getString(data, "id"),
        Aid:      data["aid"],
        Net:      getString(data, "net"),
        TLS:      getString(data, "tls"),
        Host:     getString(data, "host"),
        Path:     getString(data, "path"),
        Raw:      link,
    }
}

// Parse VLESS
func parseVLess(link string) *ProxyConfig {
    parsed, _ := urlparse(link)
    if parsed == nil || parsed.Scheme != "vless" {
        return nil
    }
    
    params := parsed.Query
    host := parsed.Host
    user := parsed.User
    
    server := host
    port := 443
    if strings.Contains(host, ":") {
        parts := strings.Split(host, ":")
        server = parts[0]
        port, _ = strconv.Atoi(parts[1])
    }
    
    // Get parameters
    fp := params.Get("fp")
    security := params.Get("security")
    sni := params.Get("sni")
    if sni == "" {
        sni = params.Get("servername")
    }
    
    // For Reality get public key
    pbk := params.Get("pbk")
    if pbk == "" {
        pbk = params.Get("publickey")
    }
    if pbk == "" {
        pbk = params.Get("key")
    }
    
    sid := params.Get("sid")
    if sid == "" {
        sid = params.Get("shortid")
    }
    if sid == "" {
        sid = params.Get("id")
    }
    
    flow := params.Get("flow")
    
    // For reality set default fingerprint
    if security == "reality" && fp == "" {
        fp = "chrome"
    }
    
    // Check for required Reality parameters
    if security == "reality" {
        if pbk == "" {
            fmt.Printf("[!] Warning: Reality proxy missing public key: %s...\n", link[:min(50, len(link))])
        }
        if sni == "" {
            sni = server
        }
    }
    
    return &ProxyConfig{
        Type:     "vless",
        Server:   server,
        Port:     port,
        ID:       user,
        Flow:     flow,
        Security: security,
        SNI:      sni,
        PBK:      pbk,
        SID:      sid,
        FP:       fp,
        Net:      params.Get("type"),
        Raw:      link,
    }
}

// Parse Trojan
func parseTrojan(link string) *ProxyConfig {
    parsed, _ := urlparse(link)
    if parsed == nil || parsed.Scheme != "trojan" {
        return nil
    }
    
    params := parsed.Query
    host := parsed.Host
    password := parsed.User
    
    server := host
    port := 443
    if strings.Contains(host, ":") {
        parts := strings.Split(host, ":")
        server = parts[0]
        port, _ = strconv.Atoi(parts[1])
    }
    
    return &ProxyConfig{
        Type:     "trojan",
        Server:   server,
        Port:     port,
        Password: password,
        SNI:      params.Get("sni"),
        Raw:      link,
    }
}

// Parse Hysteria2
func parseHy2(link string) *ProxyConfig {
    parsed, _ := urlparse(link)
    if parsed == nil || parsed.Scheme != "hy2" {
        return nil
    }
    
    params := parsed.Query
    host := parsed.Host
    password := parsed.User
    
    server := host
    port := 443
    if strings.Contains(host, ":") {
        parts := strings.Split(host, ":")
        server = parts[0]
        port, _ = strconv.Atoi(parts[1])
    }
    
    insecure := params.Get("insecure") == "1" || params.Get("insecure") == "true"
    
    return &ProxyConfig{
        Type:     "hy2",
        Server:   server,
        Port:     port,
        Password: password,
        SNI:      params.Get("sni"),
        Insecure: insecure,
        Raw:      link,
    }
}

func urlparse(rawurl string) (*ParsedURL, error) {
    result := &ParsedURL{
        Query: make(urlValues),
    }
    
    parts := strings.SplitN(rawurl, "://", 2)
    if len(parts) != 2 {
        return nil, fmt.Errorf("invalid url")
    }
    result.Scheme = parts[0]
    rest := parts[1]
    
    if idx := strings.Index(rest, "?"); idx != -1 {
        queryStr := rest[idx+1:]
        rest = rest[:idx]
        
        for _, pair := range strings.Split(queryStr, "&") {
            if idx := strings.Index(pair, "="); idx != -1 {
                key := pair[:idx]
                value := pair[idx+1:]
                result.Query[key] = []string{value}
            }
        }
    }
    
    if idx := strings.Index(rest, "@"); idx != -1 {
        result.User = rest[:idx]
        rest = rest[idx+1:]
    }
    
    result.Host = rest
    
    return result, nil
}

func getString(data map[string]interface{}, key string) string {
    if val, ok := data[key]; ok {
        return fmt.Sprintf("%v", val)
    }
    return ""
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// Check all proxies
func checkAllProxies(proxies []*ProxyConfig) []*ProxyConfig {
    results := make(chan *ProxyConfig, len(proxies))
    
    for _, proxy := range proxies {
        go func(p *ProxyConfig) {
            start := time.Now()
            
            conn, err := net.DialTimeout("tcp", 
                fmt.Sprintf("%s:%d", p.Server, p.Port), 
                5*time.Second)
            
            if err == nil {
                conn.Close()
                latency := float64(time.Since(start).Nanoseconds()) / 1e6
                p.Latency = latency
                p.Working = true
                p.Country = getCountry(p.Server)
                results <- p
            } else {
                results <- nil
            }
        }(proxy)
    }
    
    var working []*ProxyConfig
    for i := 0; i < len(proxies); i++ {
        if result := <-results; result != nil {
            working = append(working, result)
        }
    }
    
    return working
}

// Get country by IP
func getCountry(ip string) string {
    if geoIPDB != nil {
        parsedIP := net.ParseIP(ip)
        if parsedIP != nil {
            record, err := geoIPDB.Country(parsedIP)
            if err == nil && record.Country.IsoCode != "" {
                return record.Country.IsoCode
            }
        }
    }
    return "??"
}

// Save working proxies
func saveWorkingProxies(proxies []*ProxyConfig) {
    file, err := os.Create("working_proxies.txt")
    if err != nil {
        return
    }
    defer file.Close()
    
    for _, p := range proxies {
        fmt.Fprintf(file, "%s # %s %.0fms\n", p.Raw, p.Country, p.Latency)
    }
}

// Instant proxy selection
func selectProxyInstant(proxies []*ProxyConfig) *ProxyConfig {
    fmt.Println("\n=== Available proxies (", len(proxies), ") ===")
    fmt.Printf("%-4s %-6s %-8s %-8s %-30s %-10s\n", 
        "#", "Country", "Latency", "Type", "Server", "Transport")
    fmt.Println(strings.Repeat("-", 70))
    
    for i, p := range proxies {
        transport := "tcp"
        if p.Type == "vmess" && p.Net != "" {
            transport = p.Net
        } else if p.Type == "vless" && p.Net != "" {
            transport = p.Net
        }
        
        fmt.Printf("%-4d %-6s %-8.0fms %-8s %-30s %-10s\n",
            i+1, p.Country, p.Latency, strings.ToUpper(p.Type), p.Server, transport)
    }
    fmt.Println(strings.Repeat("-", 70))
    fmt.Print("\nPress number (or Enter for #1): ")
    
    num, err := readNumber()
    if err != nil {
        return proxies[0]
    }
    
    if num == -1 { // q
        return nil
    }
    
    if num < 1 || num > len(proxies) {
        fmt.Println("Invalid, using #1")
        return proxies[0]
    }
    
    return proxies[num-1]
}

// Instant mode selection
func selectModeInstant() bool {
    fmt.Println("\n=== Select Mode ===")
    fmt.Println("1. Proxy mode (local SOCKS5/HTTP)")
    fmt.Println("2. TUN mode (system-wide VPN - requires admin)")
    fmt.Println(strings.Repeat("-", 30))
    fmt.Print("\nPress 1 or 2 (Enter for 1): ")
    
    mode, err := readMode()
    if err != nil {
        return false
    }
    
    return mode == 2
}

// Helper function to get transport
func getTransport(proxy *ProxyConfig) string {
    if proxy.Type == "vmess" && proxy.Net != "" {
        return proxy.Net
    }
    if proxy.Type == "vless" && proxy.Net != "" {
        return proxy.Net
    }
    return "tcp"
}

// Generate configuration for sing-box
func generateSingBoxConfig(proxy *ProxyConfig, useTUN bool) *SingBoxConfig {
    fmt.Printf("[*] Generating config for %s proxy with %s transport\n", 
        proxy.Type, getTransport(proxy))
    
    config := &SingBoxConfig{
        Log: LogConfig{
            Level:     "info",
            Timestamp: true,
            Output:    "sing-box.log",
        },
        DNS: DNSConfig{
            Servers: []DNSServer{
                {
                    Tag:     "google-dns",
                    Address: "tls://8.8.8.8",
                    Detour:  "direct",
                },
                {
                    Tag:     "cloudflare-dns",
                    Address: "https://1.1.1.1/dns-query",
                    Detour:  "direct",
                },
            },
            Rules: []DNSRule{
                {
                    Outbound: "any",
                    Server:   "google-dns",
                },
            },
            Strategy: "prefer_ipv4",
            Final:    "google-dns",
        },
        Inbounds: []InboundConfig{},
        Outbounds: []OutboundConfig{
            {
                Type: "dns",
                Tag:  "dns-out",
            },
        },
        Route: RouteConfig{
            Rules: []RuleConfig{
                {
                    Protocol: "dns",
                    Outbound: "dns-out",
                },
                {
                    Network:  "udp",
                    Port:     53,
                    Outbound: "dns-out",
                },
            },
            AutoDetectInterface: true,
            Final:               "proxy",
        },
    }
    
    // Add inbounds based on mode
    if useTUN {
        config.Inbounds = append(config.Inbounds, InboundConfig{
            Type:          "tun",
            Tag:           "tun-in",
            InterfaceName: "sing-box-tun",
            Address:       []string{"172.19.0.1/30"},
            MTU:           1500,
            AutoRoute:     true,
            StrictRoute:   true,
            Sniff:         true,
            SniffOverrideDestination: true,
            Stack:         "system",
            DomainStrategy: "prefer_ipv4",
        })
        fmt.Println("[*] TUN mode enabled - system-wide VPN")
    } else {
        config.Inbounds = append(config.Inbounds, InboundConfig{
            Type:       "mixed",
            Tag:        "mixed-in",
            Listen:     "127.0.0.1",
            ListenPort: 1080,
            Sniff:      true,
            SniffOverrideDestination: true,
            DomainStrategy: "prefer_ipv4",
        })
        fmt.Println("[*] Proxy mode - mixed proxy on 127.0.0.1:1080")
    }
    
    // Configure outbound based on proxy type
    var outbound OutboundConfig
    
    switch proxy.Type {
    case "ss":
        outbound = OutboundConfig{
            Type:       "shadowsocks",
            Tag:        "proxy",
            Server:     proxy.Server,
            ServerPort: proxy.Port,
            Method:     proxy.Method,
            Password:   proxy.Password,
        }
        
    case "vmess":
        outbound = OutboundConfig{
            Type:       "vmess",
            Tag:        "proxy",
            Server:     proxy.Server,
            ServerPort: proxy.Port,
            UUID:       proxy.ID,
        }
        
        if proxy.Aid != nil {
            switch v := proxy.Aid.(type) {
            case float64:
                outbound.AlterID = int(v)
            case string:
                outbound.AlterID, _ = strconv.Atoi(v)
            }
        }
        
        outbound.Security = "auto"
        
        // Configure transport
        transportType := proxy.Net
        if transportType == "" {
            transportType = "tcp"
        }
        
        fmt.Printf("[*] Configuring VMess transport: %s\n", transportType)
        
        if transportType == "ws" {
            transport := &TransportConfig{
                Type: "ws",
                Path: proxy.Path,
            }
            if proxy.Path == "" {
                transport.Path = "/"
            }
            
            if proxy.Host != "" {
                transport.Headers = map[string]string{
                    "Host": proxy.Host,
                }
            }
            outbound.Transport = transport
            
        } else if transportType == "http" {
            transport := &TransportConfig{
                Type: "http",
                Path: proxy.Path,
            }
            if proxy.Path == "" {
                transport.Path = "/"
            }
            if proxy.Host != "" {
                transport.Host = []string{proxy.Host}
            }
            outbound.Transport = transport
            
        } else if transportType == "grpc" {
            transport := &TransportConfig{
                Type: "grpc",
            }
            if proxy.Path != "" {
                transport.ServiceName = strings.TrimPrefix(proxy.Path, "/")
            }
            outbound.Transport = transport
        }
        
        // Configure TLS
        if proxy.TLS == "tls" {
            outbound.TLS = &TLSConfig{
                Enabled:    true,
                ServerName: proxy.Host,
                Insecure:   false,
                MinVersion: "1.2",
                MaxVersion: "1.3",
            }
            if proxy.Host == "" {
                outbound.TLS.ServerName = proxy.Server
            }
        }
        
    case "trojan":
        outbound = OutboundConfig{
            Type:       "trojan",
            Tag:        "proxy",
            Server:     proxy.Server,
            ServerPort: proxy.Port,
            Password:   proxy.Password,
        }
        
        tlsConfig := &TLSConfig{
            Enabled:    true,
            ServerName: proxy.SNI,
            Insecure:   false,
            MinVersion: "1.2",
            MaxVersion: "1.3",
        }
        if proxy.SNI == "" {
            tlsConfig.ServerName = proxy.Server
        }
        outbound.TLS = tlsConfig
        
    case "vless":
        outbound = OutboundConfig{
            Type:       "vless",
            Tag:        "proxy",
            Server:     proxy.Server,
            ServerPort: proxy.Port,
            UUID:       proxy.ID,
        }
        
        if proxy.Flow != "" {
            outbound.Flow = proxy.Flow
        }
        
        // Configure transport
        transportType := proxy.Net
        if transportType == "ws" {
            outbound.Transport = &TransportConfig{
                Type: "ws",
                Path: "/",
                Headers: map[string]string{},
            }
        } else if transportType == "grpc" {
            outbound.Transport = &TransportConfig{
                Type: "grpc",
                ServiceName: "",
            }
        }
        
        // Configure TLS/Reality
        if proxy.Security == "reality" {
            // Check for public key
            if proxy.PBK == "" {
                fmt.Println("[!] Warning: Missing public key for Reality proxy, using TLS without Reality")
                tlsConfig := &TLSConfig{
                    Enabled:    true,
                    ServerName: proxy.SNI,
                    Insecure:   false,
                    MinVersion: "1.2",
                    MaxVersion: "1.3",
                }
                if proxy.SNI == "" {
                    tlsConfig.ServerName = proxy.Server
                }
                outbound.TLS = tlsConfig
            } else {
                tlsConfig := &TLSConfig{
                    Enabled:    true,
                    ServerName: proxy.SNI,
                    Reality: &RealityConfig{
                        Enabled:   true,
                        PublicKey: proxy.PBK,
                        ShortID:   proxy.SID,
                    },
                    Insecure:   false,
                    MinVersion: "1.2",
                    MaxVersion: "1.3",
                }
                
                // Add uTLS with fingerprint
                fp := proxy.FP
                if fp == "" {
                    fp = "chrome"
                }
                
                tlsConfig.UTLS = &UTLSConfig{
                    Enabled:     true,
                    Fingerprint: fp,
                }
                
                if proxy.SNI == "" {
                    tlsConfig.ServerName = proxy.Server
                }
                outbound.TLS = tlsConfig
            }
            
        } else if proxy.Security == "tls" {
            tlsConfig := &TLSConfig{
                Enabled:    true,
                ServerName: proxy.SNI,
                Insecure:   false,
                MinVersion: "1.2",
                MaxVersion: "1.3",
            }
            if proxy.SNI == "" {
                tlsConfig.ServerName = proxy.Server
            }
            outbound.TLS = tlsConfig
        }
        
    case "hy2":
        outbound = OutboundConfig{
            Type:       "hysteria2",
            Tag:        "proxy",
            Server:     proxy.Server,
            ServerPort: proxy.Port,
            Password:   proxy.Password,
        }
        
        tlsConfig := &TLSConfig{
            Enabled:    true,
            ServerName: proxy.SNI,
            Insecure:   proxy.Insecure,
            MinVersion: "1.2",
            MaxVersion: "1.3",
        }
        if proxy.SNI == "" {
            tlsConfig.ServerName = proxy.Server
        }
        outbound.TLS = tlsConfig
    }
    
    config.Outbounds = append(config.Outbounds, outbound)
    config.Outbounds = append(config.Outbounds, OutboundConfig{Type: "direct", Tag: "direct"})
    config.Outbounds = append(config.Outbounds, OutboundConfig{Type: "block", Tag: "block"})
    
    if useTUN {
        config.Experimental = &ExperimentalConfig{
            CacheFile: &CacheFileConfig{
                Enabled: true,
                Path:    "sing-box-cache.db",
                CacheID: "default",
            },
        }
    }
    
    return config
}

// Stop current sing-box
func stopCurrentSingbox() {
    if currentCmd != nil && currentCmd.Process != nil {
        fmt.Println("[*] Stopping current sing-box...")
        currentCmd.Process.Kill()
        currentCmd.Wait()
        fmt.Println("[✓] Stopped")
    }
    
    if currentConfigPath != "" {
        os.Remove(currentConfigPath)
        currentConfigPath = ""
    }
    
    currentCmd = nil
}

// Start sing-box
func runSingBox(config *SingBoxConfig) bool {
    stopCurrentSingbox()
    
    configData, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        fmt.Println("[!] Failed to marshal config:", err)
        return false
    }
    
    tempFile, err := os.CreateTemp("", "singbox_config_*.json")
    if err != nil {
        fmt.Println("[!] Failed to create temp file:", err)
        return false
    }
    currentConfigPath = tempFile.Name()
    
    _, err = tempFile.Write(configData)
    if err != nil {
        fmt.Println("[!] Failed to write config:", err)
        tempFile.Close()
        return false
    }
    tempFile.Close()
    
    fmt.Printf("[+] Config saved to temporary file: %s\n", currentConfigPath)
    
    currentDir, err := os.Getwd()
    if err != nil {
        fmt.Println("[!] Failed to get current directory:", err)
        return false
    }
    
    singBoxPath := filepath.Join(currentDir, "sing-box.exe")
    
    if _, err := os.Stat(singBoxPath); os.IsNotExist(err) {
        fmt.Printf("[!] Error: sing-box.exe not found at '%s'\n", singBoxPath)
        return false
    }
    
    cmd := exec.Command(singBoxPath, "run", "-c", currentConfigPath)
    cmd.Dir = currentDir
    
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        fmt.Println("[!] Failed to create stdout pipe:", err)
        return false
    }
    
    stderr, err := cmd.StderrPipe()
    if err != nil {
        fmt.Println("[!] Failed to create stderr pipe:", err)
        return false
    }
    
    err = cmd.Start()
    if err != nil {
        fmt.Printf("[!] Failed to start sing-box: %v\n", err)
        return false
    }
    
    currentCmd = cmd
    
    go func() {
        scanner := bufio.NewScanner(stdout)
        for scanner.Scan() {
            line := cleanOutput(scanner.Text())
            if line != "" {
                // Suppress too frequent errors
                if strings.Contains(line, "context deadline exceeded") {
                    // Show only every 5th error
                    if time.Now().Unix()%5 == 0 {
                        fmt.Printf("[sing-box] %s\n", line)
                    }
                } else if strings.Contains(line, "tls") || strings.Contains(line, "certificate") {
                    // Show TLS errors
                    fmt.Printf("[sing-box] TLS: %s\n", line)
                } else {
                    fmt.Printf("[sing-box] %s\n", line)
                }
            }
        }
    }()
    
    go func() {
        scanner := bufio.NewScanner(stderr)
        for scanner.Scan() {
            line := cleanOutput(scanner.Text())
            if line != "" {
                if strings.Contains(line, "context deadline exceeded") {
                    if time.Now().Unix()%5 == 0 {
                        fmt.Printf("[sing-box] %s\n", line)
                    }
                } else if strings.Contains(line, "tls") || strings.Contains(line, "certificate") {
                    fmt.Printf("[sing-box] TLS: %s\n", line)
                } else {
                    fmt.Printf("[sing-box] %s\n", line)
                }
            }
        }
    }()
    
    return true
}

// Monitor with instant reaction to 'c' and 'q'
func monitorSingBoxOutputInstant() bool {
    if currentCmd == nil {
        return false
    }
    
    // Channel for process completion signal
    done := make(chan bool)
    
    // Goroutine to monitor process
    go func() {
        currentCmd.Wait()
        done <- true
    }()
    
    // Channel for keys
    keyChan := make(chan byte)
    
    // Goroutine for reading keys
    go func() {
        for {
            b, err := getch()
            if err != nil {
                close(keyChan)
                return
            }
            select {
            case keyChan <- b:
            case <-done:
                return
            }
        }
    }()
    
    // Timer for periodic state check
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    
    errorCount := 0
    lastErrorTime := time.Now()
    
    for {
        select {
        case <-done:
            fmt.Println("\n[!] Sing-box stopped")
            return false
            
        case <-ticker.C:
            // Check for too many errors
            if time.Since(lastErrorTime) < 30*time.Second && errorCount > 10 {
                fmt.Println("\n[!] Too many errors, proxy might be unstable")
                fmt.Println("[!] Press 'c' to change proxy")
            }
            
        case key, ok := <-keyChan:
            if !ok {
                return false
            }
            if key == 'q' || key == 'Q' {
                fmt.Println("\n[!] Quitting...")
                stopCurrentSingbox()
                os.Exit(0)
                return false
            } else if key == 'c' || key == 'C' {
                fmt.Println("\n[!] Changing proxy...")
                stopCurrentSingbox()
                time.Sleep(500 * time.Millisecond)
                return true
            }
        }
    }
}
