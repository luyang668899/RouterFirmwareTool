#!/usr/bin/env python3
"""测试设备发现功能的简单脚本"""

import sys
import os

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from communication.device_discovery import DeviceDiscovery
    print("✓ 成功导入DeviceDiscovery模块")
    
    # 测试设备发现
    discovery = DeviceDiscovery()
    print("✓ 成功创建DeviceDiscovery实例")
    
    # 测试获取网关IP
    gateway_ip = discovery.get_gateway_ip()
    print(f"✓ 网关IP: {gateway_ip}")
    
    # 测试获取本地网络
    network = discovery.get_local_network()
    print(f"✓ 本地网络: {network}")
    
    print("\n设备发现功能测试成功！")
    
except Exception as e:
    print(f"✗ 测试失败: {e}")
    import traceback
    traceback.print_exc()
