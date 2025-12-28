from src.data.db_model import init_db, DeviceFeature

class BrandRecognition:
    def __init__(self):
        self.session = init_db()
        self.init_default_features()
    
    def init_default_features(self):
        """初始化默认设备特征库"""
        default_features = [
            {
                'brand': 'TP-Link',
                'model': 'Generic',
                'mac_prefix': '00:0C:43',
                'web_header': 'TP-LINK',
                'default_username': 'admin',
                'default_password': 'admin'
            },
            {
                'brand': 'ASUS',
                'model': 'Generic',
                'mac_prefix': '00:1D:73',
                'web_header': 'ASUS',
                'default_username': 'admin',
                'default_password': 'admin'
            },
            {
                'brand': 'Xiaomi',
                'model': 'Generic',
                'mac_prefix': '5C:8B:76',
                'web_header': 'MiWiFi',
                'default_username': 'admin',
                'default_password': 'admin'
            },
            {
                'brand': 'Huawei',
                'model': 'Generic',
                'mac_prefix': '00:18:82',
                'web_header': 'Huawei',
                'default_username': 'admin',
                'default_password': 'admin'
            },
            {
                'brand': 'Tenda',
                'model': 'Generic',
                'mac_prefix': '00:50:7F',
                'web_header': 'Tenda',
                'default_username': 'admin',
                'default_password': 'admin'
            },
            {
                'brand': 'Mercury',
                'model': 'Generic',
                'mac_prefix': '00:0C:43',
                'web_header': 'Mercury',
                'default_username': 'admin',
                'default_password': 'admin'
            }
        ]
        
        # 只添加不存在的特征
        for feature in default_features:
            existing = self.session.query(DeviceFeature).filter_by(
                brand=feature['brand'],
                mac_prefix=feature['mac_prefix']
            ).first()
            if not existing:
                new_feature = DeviceFeature(**feature)
                self.session.add(new_feature)
        self.session.commit()
    
    def recognize_by_mac(self, mac_address):
        """通过MAC地址前缀识别品牌"""
        if not mac_address:
            return None
        
        # 提取前3段MAC地址（XX:XX:XX）
        mac_prefix = ':'.join(mac_address.split(':')[:3]).upper()
        
        # 查询数据库
        feature = self.session.query(DeviceFeature).filter(
            DeviceFeature.mac_prefix == mac_prefix
        ).first()
        
        if feature:
            return {
                'brand': feature.brand,
                'model': feature.model,
                'source': 'mac'
            }
        return None
    
    def recognize_by_web_header(self, headers):
        """通过Web响应头识别品牌"""
        if not headers:
            return None
        
        # 转换所有头信息为小写便于匹配
        lowercase_headers = {k.lower(): v.lower() for k, v in headers.items()}
        
        # 查询所有特征
        features = self.session.query(DeviceFeature).all()
        
        for feature in features:
            if feature.web_header:
                web_header_lower = feature.web_header.lower()
                # 检查头信息中是否包含特征字符串
                for header_value in lowercase_headers.values():
                    if web_header_lower in header_value:
                        return {
                            'brand': feature.brand,
                            'model': feature.model,
                            'source': 'web_header'
                        }
        return None
    
    def recognize_by_content(self, content):
        """通过网页内容识别品牌"""
        if not content:
            return None
        
        lowercase_content = content.lower()
        features = self.session.query(DeviceFeature).all()
        
        for feature in features:
            if feature.web_header:
                web_header_lower = feature.web_header.lower()
                if web_header_lower in lowercase_content:
                    return {
                        'brand': feature.brand,
                        'model': feature.model,
                        'source': 'content'
                    }
        return None
    
    def recognize_brand(self, router_info, mac_address=None, content=None):
        """综合识别路由器品牌型号"""
        # 1. 优先通过MAC地址识别
        if mac_address:
            result = self.recognize_by_mac(mac_address)
            if result:
                return result
        
        # 2. 通过Web响应头识别
        if router_info and 'headers' in router_info:
            result = self.recognize_by_web_header(router_info['headers'])
            if result:
                return result
        
        # 3. 通过网页内容识别
        if content:
            result = self.recognize_by_content(content)
            if result:
                return result
        
        # 4. 默认返回未知
        return {
            'brand': 'Unknown',
            'model': 'Unknown',
            'source': 'default'
        }
    
    def get_default_credentials(self, brand):
        """获取默认账号密码"""
        feature = self.session.query(DeviceFeature).filter_by(
            brand=brand
        ).first()
        
        if feature:
            return {
                'username': feature.default_username,
                'password': feature.default_password
            }
        return {
            'username': 'admin',
            'password': 'admin'
        }
    
    def add_custom_feature(self, feature_data):
        """添加自定义设备特征"""
        try:
            new_feature = DeviceFeature(**feature_data)
            self.session.add(new_feature)
            self.session.commit()
            return True
        except Exception as e:
            print(f"添加自定义特征失败: {e}")
            self.session.rollback()
            return False
