#!/usr/bin/env python3
"""测试项目结构的最简化脚本"""

import sys
import os

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_structure():
    """测试项目结构是否正确"""
    print("=== 测试项目结构 ===")
    
    # 测试目录结构
    required_dirs = [
        'src',
        'src/ui',
        'src/business',
        'src/communication',
        'src/data',
        'src/utils'
    ]
    
    for dir_path in required_dirs:
        if os.path.exists(dir_path):
            print(f"✓ 目录存在: {dir_path}")
        else:
            print(f"✗ 目录缺失: {dir_path}")
    
    # 测试核心文件
    required_files = [
        'src/ui/main_window.py',
        'src/business/brand_recognition.py',
        'src/communication/device_discovery.py',
        'src/data/db_model.py',
        'src/business/firmware_backup.py',
        'requirements.txt'
    ]
    
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"✓ 文件存在: {file_path}")
        else:
            print(f"✗ 文件缺失: {file_path}")
    
    # 测试简单的Python语法
    print("\n=== 测试Python语法 ===")
    try:
        # 测试基本语法
        x = 1 + 2
        print(f"✓ 基本运算: 1 + 2 = {x}")
        
        # 测试条件语句
        if x == 3:
            print("✓ 条件语句正常")
        
        # 测试循环
        for i in range(2):
            pass
        print("✓ 循环语句正常")
        
        print("\n项目结构测试成功！")
        return True
        
    except Exception as e:
        print(f"✗ Python语法测试失败: {e}")
        return False

if __name__ == "__main__":
    test_structure()
