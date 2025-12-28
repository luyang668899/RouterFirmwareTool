import socket
import time
import requests
import subprocess
import re

# 尝试导入scapy，如果失败则跳过ARP扫描
try:
    from scapy.all import ARP, Ether, srp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("警告: 未安装scapy模块，将跳过ARP扫描")

# 尝试导入netifaces，如果失败则使用备用方法
try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False
    print("警告: 未安装netifaces模块，将使用备用方法获取网络信息")

try:
    from ssdp import discover
    HAS_SSDP = True
except ImportError:
    HAS_SSDP = False
    print("警告: 未安装python-ssdp模块，将跳过SSDP设备发现")

# 配置requests不使用代理
requests.packages.urllib3.disable_warnings()
# 创建一个不使用代理的会话
session = requests.Session()
session.trust_env = False  # 不使用环境变量中的代理

class DeviceDiscovery:
    def __init__(self):
        self.common_router_ips = [
            "192.168.1.1", "192.168.0.1", "192.168.2.1",
            "192.168.3.1", "10.0.0.1", "10.0.1.1"
        ]
        self.common_ports = [80, 8080, 8443]
    
    def get_gateway_ip(self):
        """获取当前网络的网关IP"""
        if HAS_NETIFACES:
            try:
                gateways = netifaces.gateways()
                default_gateway = gateways.get('default', {})
                if netifaces.AF_INET in default_gateway:
                    return default_gateway[netifaces.AF_INET][0]
            except Exception as e:
                print(f"netifaces获取网关失败: {e}")
        
        # 备用方法：使用系统命令
        try:
            # macOS/Linux
            if hasattr(subprocess, 'check_output'):
                result = subprocess.check_output(['route', 'get', 'default']).decode('utf-8')
                gateway_match = re.search(r'gateway:\s+(\d+\.\d+\.\d+\.\d+)', result)
                if gateway_match:
                    return gateway_match.group(1)
        except Exception as e:
            print(f"系统命令获取网关失败: {e}")
        
        return None
    
    def get_local_network(self):
        """获取本地网络范围，如192.168.1.0/24"""
        if HAS_NETIFACES:
            try:
                gateways = netifaces.gateways()
                default_gateway = gateways.get('default', {})
                if netifaces.AF_INET in default_gateway:
                    gateway_ip = default_gateway[netifaces.AF_INET][0]
                    interface = default_gateway[netifaces.AF_INET][1]
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        ip_info = addrs[netifaces.AF_INET][0]
                        ip = ip_info['addr']
                        netmask = ip_info['netmask']
                        # 计算网络地址
                        ip_parts = list(map(int, ip.split('.')))
                        mask_parts = list(map(int, netmask.split('.')))
                        network_parts = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]
                        network = '.'.join(network_parts) + '/24'  # 简化为/24子网
                        return network
            except Exception as e:
                print(f"netifaces获取本地网络失败: {e}")
        
        # 备用方法：从网关IP推断网络
        gateway_ip = self.get_gateway_ip()
        if gateway_ip:
            # 假设网关IP是x.x.x.1，网络是x.x.x.0/24
            ip_parts = gateway_ip.split('.')
            if len(ip_parts) == 4:
                network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                return network
        
        return "192.168.1.0/24"  # 默认值
    
    def scan_arp(self, network):
        """使用ARP扫描局域网设备"""
        devices = []
        if not HAS_SCAPY:
            print("scapy模块未安装，跳过ARP扫描")
            return devices
            
        try:
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3, verbose=0)[0]
            
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'hostname': self.get_hostname(received.psrc)
                })
        except Exception as e:
            print(f"ARP扫描失败: {e}")
        return devices
    
    def get_hostname(self, ip):
        """根据IP获取主机名"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def discover_ssdp_devices(self):
        """使用SSDP协议发现设备"""
        devices = []
        if not HAS_SSDP:
            print("SSDP模块未安装，跳过SSDP设备发现")
            return devices
            
        try:
            for service in discover("upnp:rootdevice", timeout=5):
                devices.append({
                    'location': service.location,
                    'server': service.server,
                    'usn': service.usn
                })
        except Exception as e:
            print(f"SSDP发现失败: {e}")
        return devices
    
    def check_router_port(self, ip, port):
        """检查设备是否开放指定端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception as e:
            print(f"端口检查失败: {e}")
            return False
    
    def get_router_info(self, ip, port=80):
        """获取路由器信息"""
        try:
            url = f"http://{ip}:{port}"
            response = requests.get(url, timeout=3)
            headers = dict(response.headers)
            return {
                'ip': ip,
                'port': port,
                'status_code': response.status_code,
                'headers': headers,
                'content_length': len(response.content)
            }
        except Exception as e:
            print(f"获取路由器信息失败: {e}")
            return None
    
    def discover_routers(self):
        """综合发现路由器设备"""
        routers = []
        print("=== 开始搜索路由器 ===")
        
        # 1. 检查网关IP
        gateway_ip = self.get_gateway_ip()
        print(f"检测到网关IP: {gateway_ip}")
        if gateway_ip:
            for port in self.common_ports:
                print(f"检查网关 {gateway_ip}:{port}...")
                if self.check_router_port(gateway_ip, port):
                    info = self.get_router_info(gateway_ip, port)
                    if info:
                        print(f"✓ 发现路由器: {gateway_ip}:{port}")
                        routers.append(info)
        
        # 2. SSDP发现
        ssdp_devices = self.discover_ssdp_devices()
        print(f"SSDP发现 {len(ssdp_devices)} 个设备")
        for device in ssdp_devices:
            if 'location' in device:
                # 解析location URL获取IP
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(device['location'])
                    ip = parsed.netloc.split(':')[0]
                    print(f"检查SSDP设备 {ip}...")
                    info = self.get_router_info(ip)
                    if info and info not in routers:
                        print(f"✓ 发现路由器: {ip}")
                        routers.append(info)
                except Exception as e:
                    print(f"SSDP设备解析失败: {e}")
        
        # 3. ARP扫描+端口检查
        network = self.get_local_network()
        print(f"正在ARP扫描网络: {network}")
        arp_devices = self.scan_arp(network)
        print(f"ARP扫描发现 {len(arp_devices)} 个设备")
        
        for device in arp_devices:
            ip = device['ip']
            hostname = device['hostname']
            print(f"检查ARP设备 {ip} ({hostname})...")
            
            # 跳过已发现的路由器
            if any(router['ip'] == ip for router in routers):
                continue
            
            for port in self.common_ports:
                if self.check_router_port(ip, port):
                    info = self.get_router_info(ip, port)
                    if info:
                        print(f"✓ 发现路由器: {ip}:{port}")
                        routers.append(info)
                    break
        
        # 4. 检查常见路由器IP
        print("检查常见路由器IP...")
        for common_ip in self.common_router_ips:
            if not any(router['ip'] == common_ip for router in routers):
                for port in self.common_ports:
                    print(f"检查常见IP {common_ip}:{port}...")
                    if self.check_router_port(common_ip, port):
                        info = self.get_router_info(common_ip, port)
                        if info:
                            print(f"✓ 发现路由器: {common_ip}:{port}")
                            routers.append(info)
                        break
        
        print(f"=== 搜索完成，共发现 {len(routers)} 台路由器 ===")
        for router in routers:
            print(f"- {router['ip']}:{router['port']}")
        
        return routers
    
    def get_router_info(self, ip, port=80):
        """获取路由器信息"""
        try:
            url = f"http://{ip}:{port}"
            # 使用配置好的session对象，避免代理问题
            response = session.get(url, timeout=3, verify=False)
            headers = dict(response.headers)
            return {
                'ip': ip,
                'port': port,
                'status_code': response.status_code,
                'headers': headers,
                'content_length': len(response.content)
            }
        except Exception as e:
            print(f"获取路由器信息失败 {ip}:{port}: {e}")
            return None
