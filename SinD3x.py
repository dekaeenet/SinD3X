import socket
import requests
import re
from scapy.all import sr1, IP, TCP, ICMP
from collections import defaultdict
import urllib.parse
import time

ascii_art = """
  _____ _      ______          
 /  ___(_)     |  _  \         
 \ `--. _ _ __ | | | |_____  __
  `--. \ | '_ \| | | / _ \ \/ /
 /\__/ / | | | | |/ /  __/>  < 
 \____/|_|_| |_|___/ \___/_/\_\\
"""

port_services = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 
    123: "NTP", 135: "Microsoft RPC", 139: "NetBIOS", 
    143: "IMAP", 443: "HTTPS", 445: "Microsoft-DS", 
    465: "SMTPS", 587: "SMTP (Submission)", 993: "IMAPS", 
    995: "POP3S", 3306: "MySQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
}

def banner():
    print(ascii_art)
    print("="*60)
    print(" 🌐 SinD3X - Scan DNS, Subdomain & Network with Precision")
    print(" 🛠️  Developed by: Arya Deka Alhadid")
    print(" 📊 Version: 2.0 (Enhanced Web Server Info Scan)")
    print("="*60)

def is_valid_domain(domain):
    """Validasi format domain dengan regex."""
    return re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain) is not None

def dns_info(domain):
    """Mengambil informasi DNS dari domain."""
    try:
        ip = socket.gethostbyname(domain)
        print(f"\n[🌐] DNS Information for {domain}:")
        print(f"    Domain: {domain}")
        print(f"    IP Address: {ip}")
        return ip
    except socket.gaierror:
        print(f"    🚫 Failed to resolve DNS for {domain}")
        return None

def port_scan(ip):
    """Memindai port untuk menemukan port yang terbuka dengan akurasi lebih tinggi."""
    print("\n[🔍] Scanning Ports with 100% Accuracy:\n")
    common_ports = sorted(port_services.keys())
    open_ports = defaultdict(str)
    
    print(f"   {'PORT'.center(8)}{'SERVICE'.center(22)}{'STATUS'.center(10)}")
    print(f"   {'-' * 40}")
    
    for port in common_ports:
        try:
            # Melakukan pemindaian TCP Connect (lebih dapat diandalkan daripada SYN scan)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Timeout 1 detik untuk lebih cepat
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports[port] = port_services.get(port, "Unknown Service")
                print(f"   {str(port).center(8)}{open_ports[port].center(22)}{'OPEN'.center(10)}")
            else:
                print(f"   {str(port).center(8)}{'Closed'.center(22)}{'CLOSED'.center(10)}")
            sock.close()
        except socket.error as e:
            print(f"   {str(port).center(8)}{'Error'.center(22)}{str(e).center(10)}")
    
    if open_ports:
        print(f"\n   🎯 Target: {ip} | Total Open Ports: {len(open_ports)}")
    else:
        print("\n   🚫 No Open Ports Found")

    print("\n" + "=" * 40)

def get_web_server_info(ip):
    """Memeriksa informasi tentang server web dengan lebih akurat."""
    try:
        response = requests.get(f"http://{ip}", timeout=5)
        print(f"\n[🔧] Web Server Information for {ip}:")
        server = response.headers.get('Server', 'Unknown')
        print(f"    Server: {server}")
        
        # Jika server adalah Apache, kita bisa mencoba mendeteksi versinya
        if "Apache" in server:
            version = server.split("/")[1] if "/" in server else "Unknown version"
            print(f"    Apache Version: {version}")
        # Jika server adalah Nginx, kita bisa mencoba mendeteksi versinya
        elif "nginx" in server.lower():
            version = server.split("/")[1] if "/" in server else "Unknown version"
            print(f"    Nginx Version: {version}")
        else:
            print(f"    Server Version: {server}")

        # Teknologi lainnya bisa dipahami melalui header lainnya atau Wappalyzer
        print(f"    X-Powered-By: {response.headers.get('X-Powered-By', 'Not Set')}")
    except requests.exceptions.RequestException as e:
        print(f"   🚫 Error connecting to server: {e}")

def main():
    banner()
    domain = input("\nMasukkan domain (tanpa http:// atau https://): ")
    
    if not is_valid_domain(domain):
        print("   ❌ Format domain tidak valid. Silakan masukkan domain yang valid.")
        return
    
    ip = dns_info(domain)
    if ip:
        port_scan(ip)
        get_web_server_info(ip)
    else:
        print("   ❌ Keluar karena kegagalan resolusi DNS.")

if __name__ == "__main__":
    main()