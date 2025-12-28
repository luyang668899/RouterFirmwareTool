#!/usr/bin/env python3
"""简化版测试脚本，只测试基本逻辑"""

import sys
import os

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    # 测试数据库初始化
    from data.db_model import init_db, DeviceFeature
    print("✓ 成功导入数据库模块")
    
    session = init_db()
    print("✓ 成功初始化数据库")
    
    # 测试品牌识别模块
    from business.brand_recognition import BrandRecognition
    print("✓ 成功导入品牌识别模块")
    
    recognizer = BrandRecognition()
    print("✓ 成功创建品牌识别实例")
    
    # 测试默认特征库
    features = session.query(DeviceFeature).all()
    print(f"✓ 特征库中有 {len(features)} 条记录")
    
    for feature in features:
        print(f"  - {feature.brand}: {feature.model} (MAC: {feature.mac_prefix})")
    
    print("\n简化版测试成功！")
    
except Exception as e:
    print(f"✗ 测试失败: {e}")
    import traceback
    traceback.print_exc()
