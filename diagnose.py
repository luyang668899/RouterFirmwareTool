#!/usr/bin/env python3
"""路由器搜索诊断脚本"""

import os
import sys
import socket
import subprocess
import re
import requests

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def print_title(title):
    """打印标题"""
    print(f"\n=== {title} ===")

def check_network_connection():
    """检查网络连接"""
    print_title("网络连接检查")
    
    # 检查是否连接到网络
    try:
        socket.create_connection(("www.baidu.com", 80), timeout=5)
        print("✓ 已连接到互联网")
    except OSError:
        print("✗ 未连接到互联网")
    
    # 获取当前IP地址
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        print(f"✓ 本地IP地址: {local_ip}")
    except Exception as e:
        print(f"✗ 获取本地IP失败: {e}")

def check_gateway():
    """检查网关设置"""
    print_title("网关设置检查")
    
    try:
        # macOS/Linux 获取网关
        result = subprocess.check_output(['route', 'get', 'default']).decode('utf-8')
        gateway_match = re.search(r'gateway:\s+(\d+\.\d+\.\d+\.\d+)', result)
        if gateway_match:
            gateway_ip = gateway_match.group(1)
            print(f"✓ 网关IP地址: {gateway_ip}")
            return gateway_ip
        else:
            print("✗ 未找到网关IP")
    except Exception as e:
        print(f"✗ 获取网关失败: {e}")
    
    return None

def check_common_routers():
    """检查常见路由器IP"""
    print_title("常见路由器检查")
    
    common_router_ips = [
        "192.168.1.1", "192.168.0.1", "192.168.2.1",
        "192.168.3.1", "10.0.0.1", "10.0.1.1",
        "192.168.10.1", "192.168.199.1", "192.168.8.1"
    ]
    
    common_ports = [80, 8080, 8443]
    
    found_routers = []
    
    for ip in common_router_ips:
        print(f"\n检查路由器: {ip}")
        
        # 检查ICMP可达性
        try:
            subprocess.check_output(['ping', '-c', '2', ip], stderr=subprocess.STDOUT)
            print(f"  ✓ ICMP可达")
        except subprocess.CalledProcessError:
            print(f"  ✗ ICMP不可达")
        
        # 检查Web端口
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    print(f"  ✓ 端口 {port} 开放")
                    # 尝试获取HTTP响应
                    try:
                        url = f"http://{ip}:{port}"
                        response = requests.get(url, timeout=3)
                        print(f"  ✓ HTTP响应: {response.status_code}")
                        # 检查响应头
                        if 'Server' in response.headers:
                            print(f"  ✓ 服务器信息: {response.headers['Server']}")
                        found_routers.append((ip, port))
                    except Exception as e:
                        print(f"  ✗ HTTP访问失败: {e}")
                else:
                    print(f"  ✗ 端口 {port} 关闭")
            except Exception as e:
                print(f"  ✗ 端口检查失败: {e}")
    
    return found_routers

def check_arp_table():
    """检查ARP表"""
    print_title("ARP表检查")
    
    try:
        # macOS获取ARP表
        result = subprocess.check_output(['arp', '-a']).decode('utf-8')
        print("ARP表内容:")
        print(result)
        
        # 解析ARP表
        arp_entries = []
        lines = result.strip().split('\n')
        for line in lines:
            # 匹配MAC地址格式
            mac_match = re.search(r'(?:[0-9a-fA-F]:?){12}', line)
            if mac_match:
                arp_entries.append(line.strip())
        
        print(f"\n✓ 找到 {len(arp_entries)} 个ARP条目")
        return arp_entries
    
    except Exception as e:
        print(f"✗ 获取ARP表失败: {e}")
        return []

def test_router_discovery():
    """测试路由器发现模块"""
    print_title("路由器发现模块测试")
    
    try:
        from src.communication.device_discovery import DeviceDiscovery
        
        discovery = DeviceDiscovery()
        print("✓ 成功加载设备发现模块")
        
        # 测试网关获取
        gateway_ip = discovery.get_gateway_ip()
        print(f"✓ 网关IP: {gateway_ip}")
        
        # 测试本地网络获取
        local_network = discovery.get_local_network()
        print(f"✓ 本地网络: {local_network}")
        
        # 测试端口检查
        if gateway_ip:
            port_status = discovery.check_router_port(gateway_ip, 80)
            print(f"✓ 网关80端口状态: {'开放' if port_status else '关闭'}")
        
        # 运行完整的路由器发现
        print("\n开始完整的路由器搜索...")
        routers = discovery.discover_routers()
        print(f"✓ 搜索完成，发现 {len(routers)} 台路由器")
        
        return routers
        
    except Exception as e:
        print(f"✗ 设备发现模块测试失败: {e}")
        import traceback
        traceback.print_exc()
        return []

def main():
    """主函数"""
    print("路由器搜索诊断工具")
    print("==================")
    print("此工具将帮助您排查路由器搜索失败的问题")
    
    # 运行各项检查
    check_network_connection()
    gateway_ip = check_gateway()
    arp_entries = check_arp_table()
    found_routers = check_common_routers()
    discovered_routers = test_router_discovery()
    
    # 总结
    print_title("诊断总结")
    
    if found_routers or discovered_routers:
        print("✓ 成功发现路由器！")
        all_routers = set()
        
        for router in found_routers:
            all_routers.add(f"{router[0]}:{router[1]}")
        
        for router in discovered_routers:
            all_routers.add(f"{router['ip']}:{router['port']}")
        
        print("发现的路由器列表:")
        for router in all_routers:
            print(f"  - {router}")
        
        print("\n您可以尝试在应用程序中手动添加这些IP地址")
    else:
        print("✗ 未发现路由器")
        print("\n可能的原因:")
        print("1. 电脑未连接到路由器的WiFi网络")
        print("2. 路由器的Web管理界面已关闭")
        print("3. 路由器使用了非标准IP地址或端口")
        print("4. 防火墙或安全软件阻止了扫描")
        
        print("\n解决方案:")
        print("1. 确保电脑已连接到路由器的WiFi")
        print("2. 查看路由器说明书，确认管理IP和端口")
        print("3. 在应用程序中手动输入路由器IP地址")
        print("4. 暂时关闭防火墙或安全软件后重试")
    
    print("\n诊断完成！")

if __name__ == "__main__":
    main()
