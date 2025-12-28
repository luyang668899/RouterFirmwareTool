import os
import time
import requests
import hashlib
import paramiko
from datetime import datetime
from src.data.db_model import init_db, BackupRecord

# 尝试导入telnetlib3，如果失败则跳过Telnet功能
try:
    import telnetlib3
    HAS_TELNET = True
except ImportError:
    try:
        # 尝试导入旧的telnetlib（Python 3.12及以下）
        import telnetlib
        HAS_TELNET = True
    except ImportError:
        HAS_TELNET = False
        print("警告: 未找到telnetlib或telnetlib3模块，将跳过Telnet备份功能")

class FirmwareBackup:
    def __init__(self):
        self.session = init_db()
        self.default_backup_dir = os.path.expanduser("~/RouterFlasher/Backups")
        os.makedirs(self.default_backup_dir, exist_ok=True)
    
    def calculate_md5(self, file_path):
        """计算文件MD5值"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def generate_backup_filename(self, brand, model, firmware_version):
        """生成备份文件名"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        version_str = firmware_version.replace(".", "_") if firmware_version else "unknown"
        filename = f"{brand}_{model}_{version_str}_{timestamp}.bin"
        return filename
    
    def backup_via_web(self, router_info, credentials):
        """通过Web管理接口备份固件"""
        try:
            ip = router_info['ip']
            port = router_info['port']
            brand = router_info.get('brand', 'Unknown')
            print(f"=== 开始Web备份 ===")
            print(f"路由器信息: {brand} {ip}:{port}")
            print(f"登录凭据: {credentials['username']}/{'*' * len(credentials['password'])}")
            
            # 创建会话
            session = requests.Session()
            session.trust_env = False  # 不使用代理
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': '*/*',
                'Accept-Language': 'zh-CN,zh;q=0.9',
                'Connection': 'keep-alive'
            })
            
            # 1. 检查是否能访问路由器
            test_url = f"http://{ip}:{port}"
            print(f"测试连接: {test_url}")
            response = session.get(test_url, timeout=5)
            print(f"初始响应: {response.status_code}")
            print(f"初始响应头: {dict(response.headers)}")
            print(f"初始响应内容长度: {len(response.content)} 字节")
            
            # 检查是否需要重定向
            if response.is_redirect:
                print(f"检测到重定向: {response.headers.get('Location')}")
                # 跟随重定向
                response = session.get(response.headers.get('Location'), timeout=5)
                print(f"重定向后响应: {response.status_code}")
            
            # 检查是否是小米路由器（通过响应头）
            if 'MiCGI' in str(response.headers):
                print(f"检测到小米路由器官方固件（MiCGI）")
                brand = 'Xiaomi_Stock'
            elif 'miwifi' in response.text.lower() or '小米' in response.text:
                print(f"检测到小米路由器（HTML内容）")
                brand = 'Xiaomi_Stock'
            
            # 2. 尝试登录
            login_data = {
                'username': credentials['username'],
                'password': credentials['password']
            }
            
            # 根据品牌使用不同的登录路径和数据格式
            brand_configs = {
                'TP-Link': {
                    'login_path': '/login.cgi',
                    'login_data': login_data,
                    'backup_path': '/backup-config.bin',
                    'backup_method': 'GET'
                },
                'ASUS': {
                    'login_path': '/login.asp',
                    'login_data': login_data,
                    'backup_path': '/backup_setting.cgi',
                    'backup_method': 'POST',
                    'backup_data': {'action': 'backup'}
                },
                'Xiaomi': {
                    # 小米路由器官方固件登录路径
                    'login_path': '/cgi-bin/luci/api/auth',
                    'login_data': {'username': credentials['username'], 'password': credentials['password']},
                    'login_json': True,
                    'backup_path': '/cgi-bin/luci/admin/system/backup',
                    'backup_method': 'POST',
                    'backup_data': {'backup': '1', 'archive': '1'}
                },
                'Xiaomi_Stock': {
                    # 小米路由器原生固件登录路径
                    'login_path': '/cgi-bin/luci/api/misystem/auth',
                    'login_data': {'username': credentials['username'], 'password': credentials['password']},
                    'login_json': True,
                    'backup_path': '/cgi-bin/luci/admin/system/backup',
                    'backup_method': 'POST',
                    'backup_data': {'backup': '1'}
                },
                'Huawei': {
                    'login_path': '/login.cgi',
                    'login_data': login_data,
                    'backup_path': '/backupconf.cgi',
                    'backup_method': 'GET'
                },
                'Tenda': {
                    'login_path': '/login.html',
                    'login_data': login_data,
                    'backup_path': '/goform/saveConfig',
                    'backup_method': 'POST',
                    'backup_data': {'action': 'backup'}
                },
                'Mercury': {
                    'login_path': '/login.cgi',
                    'login_data': login_data,
                    'backup_path': '/backup-config.bin',
                    'backup_method': 'GET'
                },
                'Netgear': {
                    'login_path': '/login.cgi',
                    'login_data': login_data,
                    'backup_path': '/backup_settings.cgi',
                    'backup_method': 'POST',
                    'backup_data': {'action': 'backup'}
                },
                'D-Link': {
                    'login_path': '/login.html',
                    'login_data': login_data,
                    'backup_path': '/tools_backup.html',
                    'backup_method': 'POST',
                    'backup_data': {'action': 'backup'}
                },
                'Linksys': {
                    'login_path': '/login.cgi',
                    'login_data': login_data,
                    'backup_path': '/backup.cgi',
                    'backup_method': 'POST',
                    'backup_data': {'submit_button': 'Backup Settings'}
                },
                'Unknown': {
                    'login_path': '/login.cgi',
                    'login_data': login_data,
                    'backup_path': '/backup-config.bin',
                    'backup_method': 'GET'
                }
            }
            
            config = brand_configs.get(brand, brand_configs['Unknown'])
            login_url = f"http://{ip}:{port}{config['login_path']}"
            
            print(f"登录URL: {login_url}")
            print(f"登录数据格式: {'JSON' if config.get('login_json', False) else 'Form Data'}")
            print(f"登录数据: {{'username': '{credentials['username']}', 'password': '****'}}")
            
            # 发送登录请求
            if config.get('login_json', False):
                login_response = session.post(login_url, json=config['login_data'], timeout=5)
            else:
                login_response = session.post(login_url, data=config['login_data'], timeout=5)
            
            print(f"登录响应: {login_response.status_code}")
            print(f"登录响应头: {dict(login_response.headers)}")
            print(f"登录响应内容长度: {len(login_response.content)} 字节")
            
            # 检查登录是否成功（通常通过响应状态码、重定向或内容判断）
            login_success = False
            if login_response.status_code in [200, 302, 301]:
                # 检查是否有会话cookie
                if session.cookies:
                    print(f"登录成功，获取到会话cookie: {session.cookies}")
                    login_success = True
                # 检查响应内容是否包含登录成功标识
                elif "success" in login_response.text.lower() or "登录" in login_response.text or "welcome" in login_response.text.lower():
                    print(f"登录成功，响应内容包含成功标识")
                    login_success = True
            
            if not login_success:
                # 尝试备选登录路径
                alternative_paths = {
                    '/index.html', '/login.htm', '/admin/login.html', '/webpages/login.html'
                }
                
                # 为小米路由器添加特定的备选登录路径
                if brand in ['Xiaomi', 'Xiaomi_Stock'] or 'MiCGI' in str(response.headers):
                    print("添加小米路由器特定备选登录路径")
                    alternative_paths.update([
                        '/cgi-bin/luci',
                        '/cgi-bin/luci/',
                        '/cgi-bin/luci/login',
                        '/login',
                        '/cgi-bin/login',
                        '/api/login',
                        '/misystem/login',
                        '/cgi-bin/misystem/login',
                        '/cgi-bin/luci/api/misystem/login'
                    ])
                
                for alt_path in alternative_paths:
                    try:
                        alt_login_url = f"http://{ip}:{port}{alt_path}"
                        print(f"尝试备选登录路径: {alt_login_url}")
                        
                        # 针对小米路由器使用不同的登录方法
                        if brand in ['Xiaomi', 'Xiaomi_Stock'] or 'MiCGI' in str(response.headers):
                            # 小米路由器可能需要不同的登录数据格式
                            if alt_path.endswith('/auth') or alt_path.endswith('/login'):
                                try:
                                    # 尝试JSON格式
                                    alt_response = session.post(alt_login_url, json=login_data, timeout=5)
                                    if alt_response.status_code in [200, 302, 301] or session.cookies:
                                        print(f"备选登录路径成功（JSON）: {alt_path}")
                                        login_success = True
                                        break
                                except:
                                    # 如果JSON失败，尝试表单格式
                                    alt_response = session.post(alt_login_url, data=login_data, timeout=5)
                                    if alt_response.status_code in [200, 302, 301] and session.cookies:
                                        print(f"备选登录路径成功（Form）: {alt_path}")
                                        login_success = True
                                        break
                        else:
                            # 普通路由器使用表单格式
                            alt_response = session.post(alt_login_url, data=login_data, timeout=5)
                            if alt_response.status_code in [200, 302, 301] and session.cookies:
                                print(f"备选登录路径成功: {alt_path}")
                                login_success = True
                                break
                    except Exception as e:
                        print(f"尝试备选路径 {alt_path} 失败: {e}")
                        continue
            
            if not login_success:
                error = f"登录失败，无法获取有效会话。状态码: {login_response.status_code}"
                print(f"备份失败: {error}")
                return {
                    'success': False,
                    'error': error,
                    'login_response_status': login_response.status_code,
                    'login_response_headers': dict(login_response.headers)
                }
            
            # 3. 尝试获取备份
            backup_url = f"http://{ip}:{port}{config['backup_path']}"
            print(f"备份URL: {backup_url}")
            print(f"备份方法: {config['backup_method']}")
            
            if config['backup_method'] == 'GET':
                backup_response = session.get(backup_url, timeout=10, stream=True)
            else:
                backup_data = config.get('backup_data', {})
                print(f"备份数据: {backup_data}")
                backup_response = session.post(backup_url, data=backup_data, timeout=10, stream=True)
            
            print(f"备份响应: {backup_response.status_code}")
            print(f"备份响应头: {dict(backup_response.headers)}")
            print(f"备份内容长度: {len(backup_response.content)} 字节")
            
            # 检查是否需要重定向
            if backup_response.is_redirect:
                print(f"备份请求重定向到: {backup_response.headers.get('Location')}")
                backup_response = session.get(backup_response.headers.get('Location'), timeout=10, stream=True)
                print(f"重定向后备份响应: {backup_response.status_code}")
            
            # 尝试多种内容类型判断
            is_binary = False
            content_type = backup_response.headers.get('Content-Type', '')
            print(f"备份内容类型: {content_type}")
            
            # 更宽松的二进制文件判断
            if (backup_response.status_code in [200, 302] and len(backup_response.content) > 1024):
                # 检查Content-Type
                if any(keyword in content_type.lower() for keyword in ['application', 'binary', 'octet-stream', 'firmware', 'config', 'backup']):
                    is_binary = True
                # 检查文件扩展名（如果有）
                elif 'content-disposition' in backup_response.headers:
                    disposition = backup_response.headers['Content-Disposition']
                    if any(ext in disposition.lower() for ext in ['.bin', '.cfg', '.backup', '.conf', '.gz', '.tar']):
                        is_binary = True
                # 如果内容类型是text但包含二进制数据，也视为二进制
                elif 'text' in content_type.lower():
                    try:
                        # 尝试解码为UTF-8，如果失败则视为二进制
                        backup_response.content.decode('utf-8')
                        # 如果是配置文件，可能是文本格式的JSON/XML/YAML
                        if any(ext in content_type.lower() for ext in ['json', 'xml', 'yaml', 'text/plain']) and len(backup_response.content) > 1024:
                            is_binary = True
                    except UnicodeDecodeError:
                        is_binary = True
                # 作为最后的尝试，直接判断是否包含大量不可打印字符
                else:
                    import string
                    printable = set(string.printable)
                    non_printable = sum(1 for c in backup_response.content if chr(c) not in printable)
                    if non_printable / len(backup_response.content) > 0.3:  # 超过30%不可打印字符
                        is_binary = True
            
            if is_binary:
                # 生成文件名
                filename = self.generate_backup_filename(
                    brand, 
                    router_info.get('model', 'Generic'),
                    router_info.get('firmware_version', 'unknown')
                )
                
                backup_path = os.path.join(self.default_backup_dir, filename)
                
                # 保存备份文件
                with open(backup_path, 'wb') as f:
                    f.write(backup_response.content)
                
                print(f"备份文件已保存: {backup_path}")
                
                # 计算MD5
                md5_sum = self.calculate_md5(backup_path)
                print(f"备份文件MD5: {md5_sum}")
                
                # 记录备份
                backup_record = BackupRecord(
                    device_brand=brand,
                    device_model=router_info.get('model', 'Generic'),
                    firmware_version=router_info.get('firmware_version', 'unknown'),
                    backup_path=backup_path,
                    md5_sum=md5_sum,
                    size=len(backup_response.content)
                )
                self.session.add(backup_record)
                self.session.commit()
                
                print(f"=== Web备份成功 ===")
                return {
                    'success': True,
                    'backup_path': backup_path,
                    'md5': md5_sum,
                    'size': len(backup_response.content),
                    'content_type': content_type
                }
            else:
                error = f"获取的内容不是有效的固件或配置文件，Content-Type: {content_type}，内容长度: {len(backup_response.content)} 字节"
                print(f"备份失败: {error}")
                # 保存响应内容以便调试
                debug_path = os.path.join(self.default_backup_dir, f"debug_{brand}_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                with open(debug_path, 'wb') as f:
                    f.write(backup_response.content)
                print(f"调试信息已保存到: {debug_path}")
                return {
                    'success': False,
                    'error': error,
                    'debug_file': debug_path,
                    'content_type': content_type,
                    'content_length': len(backup_response.content)
                }
        
        except requests.exceptions.ConnectionError as e:
            print(f"Web备份失败 - 连接错误: {e}")
            return {
                'success': False,
                'error': f"无法连接到路由器: {str(e)}",
                'suggestion': "请检查路由器IP地址是否正确，网络连接是否正常，以及路由器是否在线"
            }
        except requests.exceptions.Timeout as e:
            print(f"Web备份失败 - 超时错误: {e}")
            return {
                'success': False,
                'error': f"连接到路由器超时: {str(e)}",
                'suggestion': "请检查网络连接是否稳定，或尝试增加超时时间"
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Web备份失败: {e}")
            return {
                'success': False,
                'error': f"Web备份失败: {str(e)}",
                'detail': traceback.format_exc(),
                'suggestion': "请检查路由器是否支持Web管理，以及登录凭据是否正确"
            }
    
    def backup_via_ssh(self, ip, credentials):
        """通过SSH备份固件"""
        try:
            print(f"=== 开始SSH备份 ===")
            print(f"路由器IP: {ip}")
            print(f"登录凭据: {credentials['username']}/{'*' * len(credentials['password'])}")
            
            # 创建SSH客户端
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # 连接SSH
            print(f"连接到SSH服务器: {ip}:22")
            client.connect(
                hostname=ip,
                username=credentials['username'],
                password=credentials['password'],
                timeout=10
            )
            print(f"SSH连接成功")
            
            # 品牌特定的固件分区路径
            brand_partitions = {
                'TP-Link': ['/dev/mtdblock2', '/dev/mtd/2', '/dev/mtd2'],
                'ASUS': ['/dev/mtdblock3', '/dev/mtd/3', '/dev/mtd3'],
                'Xiaomi': ['/dev/mtdblock4', '/dev/mtd/4', '/dev/mtd4'],
                'Huawei': ['/dev/mtdblock1', '/dev/mtd/1', '/dev/mtd1'],
                'Tenda': ['/dev/mtdblock2', '/dev/mtd/2', '/dev/mtd2'],
                'Mercury': ['/dev/mtdblock2', '/dev/mtd/2', '/dev/mtd2'],
                'Netgear': ['/dev/mtdblock5', '/dev/mtd/5', '/dev/mtd5'],
                'D-Link': ['/dev/mtdblock2', '/dev/mtd/2', '/dev/mtd2'],
                'Linksys': ['/dev/mtdblock0', '/dev/mtd/0', '/dev/mtd0']
            }
            
            # 通用分区路径（如果无法识别品牌）
            default_partitions = [
                '/dev/mtdblock2', '/dev/mtdblock3', '/dev/mtdblock4',
                '/dev/mtd/2', '/dev/mtd/3', '/dev/mtd/4',
                '/dev/mtd2', '/dev/mtd3', '/dev/mtd4',
                '/rom', '/etc/config', '/overlay'
            ]
            
            # 尝试获取品牌信息（通过SSH命令）
            brand = 'Unknown'
            model = 'Generic'
            firmware_version = 'unknown'
            
            # 尝试获取品牌和型号信息
            brand_commands = [
                "cat /proc/cpuinfo | grep -i 'model name'",
                "cat /etc/openwrt_release | grep -i 'DISTRIB_ID'",
                "nvram get productid",
                "nvram get model",
                "cat /tmp/sysinfo/model"
            ]
            
            for cmd in brand_commands:
                try:
                    print(f"执行命令获取品牌信息: {cmd}")
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
                    output = stdout.read().decode('utf-8', errors='ignore').strip()
                    error = stderr.read().decode('utf-8', errors='ignore').strip()
                    
                    if output and not error:
                        print(f"命令输出: {output}")
                        # 尝试从输出中提取品牌
                        for brand_name in brand_partitions.keys():
                            if brand_name.lower() in output.lower():
                                brand = brand_name
                                print(f"识别到品牌: {brand}")
                                break
                        
                        # 尝试提取型号
                        if 'model' in cmd.lower() and model == 'Generic':
                            model = output.split(':')[-1].strip() if ':' in output else output
                            print(f"识别到型号: {model}")
                    
                    if brand != 'Unknown' and model != 'Generic':
                        break
                except:
                    continue
            
            # 尝试获取固件版本
            version_commands = [
                "cat /etc/openwrt_release | grep -i 'DISTRIB_RELEASE'",
                "nvram get firmware_version",
                "nvram get version",
                "cat /proc/version"
            ]
            
            for cmd in version_commands:
                try:
                    print(f"执行命令获取固件版本: {cmd}")
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
                    output = stdout.read().decode('utf-8', errors='ignore').strip()
                    if output:
                        print(f"命令输出: {output}")
                        firmware_version = output.split(':')[-1].strip() if ':' in output else output
                        firmware_version = firmware_version.replace('"', '').replace("'", '')
                        print(f"识别到固件版本: {firmware_version}")
                        break
                except:
                    continue
            
            # 选择分区路径
            partitions_to_try = brand_partitions.get(brand, default_partitions)
            print(f"使用分区路径: {partitions_to_try}")
            
            backup_content = b''
            
            # 尝试读取固件分区
            for partition in partitions_to_try:
                try:
                    print(f"尝试读取分区: {partition}")
                    stdin, stdout, stderr = client.exec_command(f"cat {partition}")
                    content = stdout.read()
                    error = stderr.read().decode('utf-8', errors='ignore').strip()
                    
                    if error:
                        print(f"读取分区 {partition} 失败: {error}")
                        continue
                    
                    print(f"读取分区 {partition} 成功，大小: {len(content)} 字节")
                    
                    if len(content) > 1024:
                        backup_content = content
                        print(f"找到有效固件内容，大小: {len(content)} 字节")
                        break
                except Exception as e:
                    print(f"读取分区 {partition} 异常: {e}")
                    continue
            
            # 如果找不到有效分区，尝试使用dd命令备份整个flash
            if not backup_content:
                print("尝试使用dd命令备份整个flash")
                try:
                    dd_commands = [
                        "dd if=/dev/mtdblock0 of=/tmp/firmware.bin",
                        "dd if=/dev/mtd0 of=/tmp/firmware.bin"
                    ]
                    
                    for cmd in dd_commands:
                        try:
                            print(f"执行dd命令: {cmd}")
                            stdin, stdout, stderr = client.exec_command(cmd, timeout=10)
                            stdout.read()
                            stderr.read()
                            
                            # 检查文件是否生成
                            stdin, stdout, stderr = client.exec_command("ls -l /tmp/firmware.bin")
                            output = stdout.read().decode('utf-8', errors='ignore').strip()
                            if "/tmp/firmware.bin" in output:
                                print("dd命令执行成功，正在读取生成的文件")
                                stdin, stdout, stderr = client.exec_command("cat /tmp/firmware.bin")
                                backup_content = stdout.read()
                                print(f"读取dd备份内容成功，大小: {len(backup_content)} 字节")
                                break
                        except Exception as e:
                            print(f"执行dd命令异常: {e}")
                            continue
                except:
                    pass
            
            if not backup_content:
                error = "无法读取任何固件分区或生成备份文件"
                print(f"SSH备份失败: {error}")
                client.close()
                return {
                    'success': False,
                    'error': error,
                    'suggestion': "请检查SSH连接权限，以及路由器是否支持SSH固件访问"
                }
            
            # 生成文件名
            filename = self.generate_backup_filename(
                brand,
                model,
                firmware_version
            )
            
            backup_path = os.path.join(self.default_backup_dir, filename)
            
            # 保存备份文件
            with open(backup_path, 'wb') as f:
                f.write(backup_content)
            
            print(f"备份文件已保存: {backup_path}")
            
            # 计算MD5
            md5_sum = self.calculate_md5(backup_path)
            print(f"备份文件MD5: {md5_sum}")
            
            # 记录备份
            backup_record = BackupRecord(
                device_brand=brand,
                device_model=model,
                firmware_version=firmware_version,
                backup_path=backup_path,
                md5_sum=md5_sum,
                size=len(backup_content)
            )
            self.session.add(backup_record)
            self.session.commit()
            
            client.close()
            
            print(f"=== SSH备份成功 ===")
            return {
                'success': True,
                'backup_path': backup_path,
                'md5': md5_sum,
                'size': len(backup_content),
                'brand': brand,
                'model': model,
                'firmware_version': firmware_version
            }
        
        except paramiko.AuthenticationException:
            error = "SSH认证失败，请检查用户名和密码"
            print(f"SSH备份失败: {error}")
            return {
                'success': False,
                'error': error,
                'suggestion': "请确保SSH服务已开启，并且用户名和密码正确"
            }
        except paramiko.SSHException as e:
            error = f"SSH连接失败: {str(e)}"
            print(f"SSH备份失败: {error}")
            return {
                'success': False,
                'error': error,
                'suggestion': "请检查SSH服务是否已开启，以及网络连接是否正常"
            }
        except Exception as e:
            print(f"SSH备份失败: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f"SSH备份失败: {str(e)}",
                'detail': traceback.format_exc(),
                'suggestion': "请检查路由器是否支持SSH，以及是否有足够的权限"
            }
    
    def backup_via_telnet(self, ip, credentials):
        """通过Telnet备份固件"""
        if not HAS_TELNET:
            return {
                'success': False,
                'error': 'Telnet模块未安装，无法使用Telnet备份功能',
                'suggestion': "请安装telnetlib3或telnetlib模块"
            }
        
        try:
            print(f"=== 开始Telnet备份 ===")
            print(f"路由器IP: {ip}")
            print(f"登录凭据: {credentials['username']}/{'*' * len(credentials['password'])}")
            
            # 连接Telnet
            print(f"连接到Telnet服务器: {ip}:23")
            tn = telnetlib.Telnet(ip, timeout=10)
            print(f"Telnet连接成功")
            
            # 登录
            print("等待登录提示符...")
            tn.read_until(b"login: ", timeout=5)
            print(f"发送用户名: {credentials['username']}")
            tn.write(credentials['username'].encode('ascii') + b"\n")
            
            tn.read_until(b"Password: ", timeout=5)
            print(f"发送密码: {'*' * len(credentials['password'])}")
            tn.write(credentials['password'].encode('ascii') + b"\n")
            
            # 等待命令提示符
            prompt = tn.read_until(b"$ ", timeout=5)
            if b"$ " not in prompt:
                # 尝试其他常见提示符
                prompt = tn.read_until(b"> ", timeout=5)
                if b"> " not in prompt:
                    error = "登录失败，未找到命令提示符"
                    print(f"Telnet备份失败: {error}")
                    tn.close()
                    return {
                        'success': False,
                        'error': error,
                        'suggestion': "请检查用户名和密码是否正确"
                    }
            
            print(f"Telnet登录成功，提示符: {prompt.decode('utf-8', errors='ignore').strip()}")
            
            # 品牌特定的固件分区路径
            brand_partitions = {
                'TP-Link': ['/dev/mtdblock2', '/dev/mtd/2', '/dev/mtd2'],
                'ASUS': ['/dev/mtdblock3', '/dev/mtd/3', '/dev/mtd3'],
                'Xiaomi': ['/dev/mtdblock4', '/dev/mtd/4', '/dev/mtd4'],
                'Huawei': ['/dev/mtdblock1', '/dev/mtd/1', '/dev/mtd1'],
                'Tenda': ['/dev/mtdblock2', '/dev/mtd/2', '/dev/mtd2'],
                'Mercury': ['/dev/mtdblock2', '/dev/mtd/2', '/dev/mtd2'],
                'Netgear': ['/dev/mtdblock5', '/dev/mtd/5', '/dev/mtd5'],
                'D-Link': ['/dev/mtdblock2', '/dev/mtd/2', '/dev/mtd2'],
                'Linksys': ['/dev/mtdblock0', '/dev/mtd/0', '/dev/mtd0']
            }
            
            # 通用分区路径（如果无法识别品牌）
            default_partitions = [
                '/dev/mtdblock2', '/dev/mtdblock3', '/dev/mtdblock4',
                '/dev/mtd/2', '/dev/mtd/3', '/dev/mtd/4',
                '/dev/mtd2', '/dev/mtd3', '/dev/mtd4',
                '/rom', '/etc/config', '/overlay'
            ]
            
            # 尝试获取品牌信息（通过Telnet命令）
            brand = 'Unknown'
            model = 'Generic'
            firmware_version = 'unknown'
            
            # 尝试获取品牌和型号信息
            brand_commands = [
                "cat /proc/cpuinfo | grep -i 'model name'",
                "cat /etc/openwrt_release | grep -i 'DISTRIB_ID'",
                "nvram get productid",
                "nvram get model",
                "cat /tmp/sysinfo/model"
            ]
            
            for cmd in brand_commands:
                try:
                    print(f"执行命令获取品牌信息: {cmd}")
                    tn.write(cmd.encode('ascii') + b"\n")
                    output = tn.read_until(b"$ ", timeout=5)
                    
                    # 过滤掉命令本身和提示符
                    output_lines = output.split(b"\n")
                    if len(output_lines) > 1:
                        result = b"\n".join(output_lines[1:-1])
                        result_str = result.decode('utf-8', errors='ignore').strip()
                        print(f"命令输出: {result_str}")
                        
                        # 尝试从输出中提取品牌
                        for brand_name in brand_partitions.keys():
                            if brand_name.lower() in result_str.lower():
                                brand = brand_name
                                print(f"识别到品牌: {brand}")
                                break
                        
                        # 尝试提取型号
                        if 'model' in cmd.lower() and model == 'Generic':
                            model = result_str.split(':')[-1].strip() if ':' in result_str else result_str
                            print(f"识别到型号: {model}")
                    
                    if brand != 'Unknown' and model != 'Generic':
                        break
                except Exception as e:
                    print(f"执行命令 {cmd} 异常: {e}")
                    continue
            
            # 尝试获取固件版本
            version_commands = [
                "cat /etc/openwrt_release | grep -i 'DISTRIB_RELEASE'",
                "nvram get firmware_version",
                "nvram get version",
                "cat /proc/version"
            ]
            
            for cmd in version_commands:
                try:
                    print(f"执行命令获取固件版本: {cmd}")
                    tn.write(cmd.encode('ascii') + b"\n")
                    output = tn.read_until(b"$ ", timeout=5)
                    
                    output_lines = output.split(b"\n")
                    if len(output_lines) > 1:
                        result = b"\n".join(output_lines[1:-1])
                        result_str = result.decode('utf-8', errors='ignore').strip()
                        if result_str:
                            print(f"命令输出: {result_str}")
                            firmware_version = result_str.split(':')[-1].strip() if ':' in result_str else result_str
                            firmware_version = firmware_version.replace('"', '').replace("'", '')
                            print(f"识别到固件版本: {firmware_version}")
                            break
                except Exception as e:
                    print(f"执行命令 {cmd} 异常: {e}")
                    continue
            
            # 选择分区路径
            partitions_to_try = brand_partitions.get(brand, default_partitions)
            print(f"使用分区路径: {partitions_to_try}")
            
            backup_content = b''
            
            # 尝试读取固件分区
            for partition in partitions_to_try:
                try:
                    print(f"尝试读取分区: {partition}")
                    tn.write(f"cat {partition}\n".encode('ascii'))
                    content = tn.read_until(b"$ ", timeout=10)
                    
                    # 过滤掉命令本身和提示符
                    output_lines = content.split(b"\n")
                    if len(output_lines) > 1:
                        result = b"\n".join(output_lines[1:-1])
                        print(f"读取分区 {partition} 成功，大小: {len(result)} 字节")
                        
                        if len(result) > 1024:
                            backup_content = result
                            print(f"找到有效固件内容，大小: {len(result)} 字节")
                            break
                except Exception as e:
                    print(f"读取分区 {partition} 异常: {e}")
                    continue
            
            if not backup_content:
                error = "无法读取任何固件分区"
                print(f"Telnet备份失败: {error}")
                tn.close()
                return {
                    'success': False,
                    'error': error,
                    'suggestion': "请检查Telnet连接权限，以及路由器是否支持Telnet固件访问"
                }
            
            # 生成文件名
            filename = self.generate_backup_filename(
                brand,
                model,
                firmware_version
            )
            
            backup_path = os.path.join(self.default_backup_dir, filename)
            
            # 保存备份文件
            with open(backup_path, 'wb') as f:
                f.write(backup_content)
            
            print(f"备份文件已保存: {backup_path}")
            
            # 计算MD5
            md5_sum = self.calculate_md5(backup_path)
            print(f"备份文件MD5: {md5_sum}")
            
            # 记录备份
            backup_record = BackupRecord(
                device_brand=brand,
                device_model=model,
                firmware_version=firmware_version,
                backup_path=backup_path,
                md5_sum=md5_sum,
                size=len(backup_content)
            )
            self.session.add(backup_record)
            self.session.commit()
            
            tn.close()
            
            print(f"=== Telnet备份成功 ===")
            return {
                'success': True,
                'backup_path': backup_path,
                'md5': md5_sum,
                'size': len(backup_content),
                'brand': brand,
                'model': model,
                'firmware_version': firmware_version
            }
        
        except ConnectionRefusedError:
            error = "Telnet连接被拒绝，请检查路由器是否开启了Telnet服务"
            print(f"Telnet备份失败: {error}")
            return {
                'success': False,
                'error': error,
                'suggestion': "请在路由器管理界面开启Telnet服务，或使用其他备份方式"
            }
        except TimeoutError:
            error = "Telnet连接超时，请检查网络连接是否正常"
            print(f"Telnet备份失败: {error}")
            return {
                'success': False,
                'error': error,
                'suggestion': "请检查网络连接，或尝试使用其他备份方式"
            }
        except Exception as e:
            print(f"Telnet备份失败: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f"Telnet备份失败: {str(e)}",
                'detail': traceback.format_exc(),
                'suggestion': "请检查路由器是否支持Telnet，以及是否有足够的权限"
            }
    
    def backup_firmware(self, router_info, credentials):
        """综合备份固件，按优先级尝试不同方法"""
        # 1. 尝试Web备份
        result = self.backup_via_web(router_info, credentials)
        if result['success']:
            return result
        
        # 2. 尝试SSH备份
        ip = router_info['ip']
        result = self.backup_via_ssh(ip, credentials)
        if result['success']:
            return result
        
        # 3. 尝试Telnet备份
        result = self.backup_via_telnet(ip, credentials)
        if result['success']:
            return result
        
        # 4. 所有方法都失败
        return {
            'success': False,
            'error': '所有备份方法都失败，请尝试手动备份'
        }
    
    def flash_via_web(self, router_info, credentials, firmware_path):
        """通过Web管理接口刷机"""
        try:
            ip = router_info['ip']
            port = router_info['port']
            brand = router_info.get('brand', 'Unknown')
            
            print(f"=== 开始Web刷机 ===")
            print(f"路由器信息: {brand} {ip}:{port}")
            print(f"登录凭据: {credentials['username']}/{'*' * len(credentials['password'])}")
            print(f"固件文件: {firmware_path}")
            
            # 检查固件文件
            if not os.path.exists(firmware_path):
                error = f"固件文件不存在: {firmware_path}"
                print(f"刷机失败: {error}")
                return {'success': False, 'error': error}
            
            # 获取固件大小
            firmware_size = os.path.getsize(firmware_path)
            print(f"固件大小: {firmware_size} 字节 ({firmware_size / (1024*1024):.2f} MB)")
            
            if firmware_size < 1024 * 1024:  # 至少1MB
                error = f"固件文件太小，可能不是有效的固件 (仅 {firmware_size / (1024*1024):.2f} MB)"
                print(f"刷机失败: {error}")
                return {'success': False, 'error': error}
            
            # 创建会话
            session = requests.Session()
            session.trust_env = False  # 不使用代理
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': '*/*',
                'Accept-Language': 'zh-CN,zh;q=0.9',
                'Connection': 'keep-alive'
            })
            
            # 1. 检查是否能访问路由器
            test_url = f"http://{ip}:{port}"
            print(f"测试连接: {test_url}")
            response = session.get(test_url, timeout=5)
            print(f"初始响应: {response.status_code}")
            print(f"初始响应头: {dict(response.headers)}")
            print(f"初始响应内容长度: {len(response.content)} 字节")
            
            # 检查是否需要重定向
            if response.is_redirect:
                print(f"检测到重定向: {response.headers.get('Location')}")
                response = session.get(response.headers.get('Location'), timeout=5)
                print(f"重定向后响应: {response.status_code}")
            
            # 检查是否是小米路由器（通过响应头或内容）
            if 'MiCGI' in str(response.headers):
                print(f"检测到小米路由器官方固件（MiCGI）")
                brand = 'Xiaomi_Stock'
            elif 'miwifi' in response.text.lower() or '小米' in response.text:
                print(f"检测到小米路由器（HTML内容）")
                brand = 'Xiaomi_Stock'
            
            # 2. 尝试登录
            login_data = {
                'username': credentials['username'],
                'password': credentials['password']
            }
            
            # 根据品牌使用不同的登录路径和数据格式
            brand_configs = {
                'TP-Link': {
                    'login_path': '/login.cgi',
                    'login_data': login_data,
                    'flash_path': '/upload_firmware.cgi',
                    'flash_method': 'POST',
                    'flash_data': {'action': 'upgrade'},
                    'firmware_field': 'firmware'
                },
                'ASUS': {
                    'login_path': '/login.asp',
                    'login_data': login_data,
                    'flash_path': '/upload_firmware.asp',
                    'flash_method': 'POST',
                    'flash_data': {'action': 'upload'},
                    'firmware_field': 'firmware_file'
                },
                'Xiaomi': {
                    'login_path': '/cgi-bin/luci/api/auth',
                    'login_data': {'username': credentials['username'], 'password': credentials['password']},
                    'login_json': True,
                    'flash_path': '/cgi-bin/luci/admin/system/flash',
                    'flash_method': 'POST',
                    'flash_data': {'action': 'flash', 'force': '1'},
                    'firmware_field': 'image'
                },
                'Xiaomi_Stock': {
                    # 小米路由器原生固件配置
                    'login_path': '/cgi-bin/luci/api/misystem/auth',
                    'login_data': {'username': credentials['username'], 'password': credentials['password']},
                    'login_json': True,
                    'flash_path': '/cgi-bin/luci/api/misystem/upgrade',
                    'flash_method': 'POST',
                    'firmware_field': 'image'
                },
                'Huawei': {
                    'login_path': '/login.cgi',
                    'login_data': login_data,
                    'flash_path': '/upgrade.cgi',
                    'flash_method': 'POST',
                    'flash_data': {'upgrade': '1'},
                    'firmware_field': 'file'
                },
                'Tenda': {
                    'login_path': '/login.html',
                    'login_data': login_data,
                    'flash_path': '/goform/setUpgrade',
                    'flash_method': 'POST',
                    'flash_data': {'action': 'upgrade'},
                    'firmware_field': 'upgradeFile'
                },
                'Mercury': {
                    'login_path': '/login.cgi',
                    'login_data': login_data,
                    'flash_path': '/upload_firmware.cgi',
                    'flash_method': 'POST',
                    'flash_data': {'action': 'upgrade'},
                    'firmware_field': 'firmware'
                },
                'Netgear': {
                    'login_path': '/login.cgi',
                    'login_data': login_data,
                    'flash_path': '/firmware_update.cgi',
                    'flash_method': 'POST',
                    'flash_data': {'action': 'apply'},
                    'firmware_field': 'firmware'
                },
                'D-Link': {
                    'login_path': '/login.html',
                    'login_data': login_data,
                    'flash_path': '/tools_firmware.html',
                    'flash_method': 'POST',
                    'flash_data': {'action': 'update'},
                    'firmware_field': 'firmware_file'
                },
                'Linksys': {
                    'login_path': '/login.cgi',
                    'login_data': login_data,
                    'flash_path': '/upload_firmware.cgi',
                    'flash_method': 'POST',
                    'flash_data': {'submit_button': 'Upgrade Firmware'},
                    'firmware_field': 'firmware_image'
                },
                'Unknown': {
                    'login_path': '/login.cgi',
                    'login_data': login_data,
                    'flash_path': '/upload_firmware.cgi',
                    'flash_method': 'POST',
                    'flash_data': {'action': 'upgrade'},
                    'firmware_field': 'firmware'
                }
            }
            
            config = brand_configs.get(brand, brand_configs['Unknown'])
            login_url = f"http://{ip}:{port}{config['login_path']}"
            
            print(f"登录URL: {login_url}")
            print(f"登录数据格式: {'JSON' if config.get('login_json', False) else 'Form Data'}")
            print(f"登录数据: {{'username': '{credentials['username']}', 'password': '****'}}")
            
            # 发送登录请求
            if config.get('login_json', False):
                login_response = session.post(login_url, json=config['login_data'], timeout=5)
            else:
                login_response = session.post(login_url, data=config['login_data'], timeout=5)
            
            print(f"登录响应: {login_response.status_code}")
            print(f"登录响应头: {dict(login_response.headers)}")
            print(f"登录响应内容长度: {len(login_response.content)} 字节")
            
            # 检查登录是否成功
            login_success = False
            if login_response.status_code in [200, 302, 301]:
                if session.cookies:
                    print(f"登录成功，获取到会话cookie: {session.cookies}")
                    login_success = True
                elif "success" in login_response.text.lower() or "登录" in login_response.text or "welcome" in login_response.text.lower():
                    print(f"登录成功，响应内容包含成功标识")
                    login_success = True
            
            if not login_success:
                # 尝试备选登录路径
                alternative_paths = {
                    '/index.html', '/login.htm', '/admin/login.html', '/webpages/login.html'
                }
                
                # 为小米路由器添加特定的备选登录路径
                if brand in ['Xiaomi', 'Xiaomi_Stock'] or 'MiCGI' in str(response.headers):
                    print("添加小米路由器特定备选登录路径")
                    alternative_paths.update([
                        '/cgi-bin/luci',
                        '/cgi-bin/luci/',
                        '/cgi-bin/luci/login',
                        '/login',
                        '/cgi-bin/login',
                        '/api/login',
                        '/misystem/login',
                        '/cgi-bin/misystem/login',
                        '/cgi-bin/luci/api/misystem/login'
                    ])
                
                for alt_path in alternative_paths:
                    try:
                        alt_login_url = f"http://{ip}:{port}{alt_path}"
                        print(f"尝试备选登录路径: {alt_login_url}")
                        
                        # 针对小米路由器使用不同的登录方法
                        if brand in ['Xiaomi', 'Xiaomi_Stock'] or 'MiCGI' in str(response.headers):
                            # 小米路由器可能需要不同的登录数据格式
                            if alt_path.endswith('/auth') or alt_path.endswith('/login'):
                                try:
                                    # 尝试JSON格式
                                    alt_response = session.post(alt_login_url, json=login_data, timeout=5)
                                    if alt_response.status_code in [200, 302, 301] or session.cookies:
                                        print(f"备选登录路径成功（JSON）: {alt_path}")
                                        login_success = True
                                        break
                                except:
                                    # 如果JSON失败，尝试表单格式
                                    alt_response = session.post(alt_login_url, data=login_data, timeout=5)
                                    if alt_response.status_code in [200, 302, 301] and session.cookies:
                                        print(f"备选登录路径成功（Form）: {alt_path}")
                                        login_success = True
                                        break
                        else:
                            # 普通路由器使用表单格式
                            alt_response = session.post(alt_login_url, data=login_data, timeout=5)
                            if alt_response.status_code in [200, 302, 301] and session.cookies:
                                print(f"备选登录路径成功: {alt_path}")
                                login_success = True
                                break
                    except Exception as e:
                        print(f"尝试备选路径 {alt_path} 失败: {e}")
                        continue
            
            if not login_success:
                error = f"登录失败，无法获取有效会话。状态码: {login_response.status_code}"
                print(f"刷机失败: {error}")
                return {
                    'success': False,
                    'error': error,
                    'login_response_status': login_response.status_code
                }
            
            # 3. 准备刷机
            flash_url = f"http://{ip}:{port}{config['flash_path']}"
            print(f"刷机URL: {flash_url}")
            print(f"刷机方法: {config['flash_method']}")
            print(f"刷机数据: {config['flash_data']}")
            print(f"固件字段名: {config['firmware_field']}")
            
            # 4. 上传固件
            print(f"开始上传固件，大小: {firmware_size} 字节")
            with open(firmware_path, 'rb') as f:
                files = {
                    config['firmware_field']: (os.path.basename(firmware_path), f, 'application/octet-stream')
                }
                
                # 设置更长的超时时间，因为固件上传可能需要较长时间
                try:
                    response = session.post(
                        flash_url, 
                        files=files, 
                        data=config['flash_data'], 
                        timeout=60  # 60秒超时
                    )
                except requests.exceptions.Timeout:
                    error = "固件上传超时，请检查网络连接是否稳定，或尝试使用更小的固件文件"
                    print(f"刷机失败: {error}")
                    return {
                        'success': False,
                        'error': error,
                        'suggestion': "请确保网络连接稳定，或尝试使用有线连接"
                    }
            
            print(f"固件上传响应: {response.status_code}")
            print(f"上传响应头: {dict(response.headers)}")
            print(f"上传响应内容长度: {len(response.content)} 字节")
            
            # 检查上传是否成功
            # 不同品牌可能有不同的成功标识
            flash_success = False
            
            # 检查状态码
            if response.status_code in [200, 302, 301]:
                # 检查响应内容中的成功标识
                response_text = response.text.lower()
                if any(keyword in response_text for keyword in [
                    "success", "successful", "upgrade", "升级", "正在更新", 
                    "正在升级", "刷机成功", "update", "flashed", "completed"
                ]):
                    flash_success = True
                    print(f"检测到成功标识，刷机可能成功")
                # 检查是否有重定向到成功页面
                elif 'location' in response.headers:
                    location = response.headers['location']
                    if any(keyword in location.lower() for keyword in ["success", "upgrade", "update"]):
                        flash_success = True
                        print(f"检测到重定向到成功页面: {location}")
                # 对于某些品牌，200状态码可能表示成功，即使没有明确的成功标识
                elif brand in ['TP-Link', 'ASUS', 'Xiaomi']:
                    flash_success = True
                    print(f"品牌 {brand}，状态码 {response.status_code}，假设刷机成功")
            
            if flash_success:
                print(f"=== Web刷机成功 ===")
                return {
                    'success': True,
                    'message': f'固件上传成功，路由器正在刷机中，请耐心等待5-10分钟。\n品牌: {brand}\n状态码: {response.status_code}',
                    'response_status': response.status_code
                }
            else:
                error = f"刷机失败，HTTP状态码: {response.status_code}"
                print(f"刷机失败: {error}")
                # 保存响应内容以便调试
                debug_path = os.path.join(self.default_backup_dir, f"flash_debug_{brand}_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                with open(debug_path, 'wb') as f:
                    f.write(response.content)
                print(f"调试信息已保存到: {debug_path}")
                
                return {
                    'success': False,
                    'error': error,
                    'debug_file': debug_path,
                    'response_status': response.status_code,
                    'response_content': response.text[:500] + '...' if len(response.text) > 500 else response.text,
                    'suggestion': "请检查固件文件是否与路由器兼容，以及登录凭据是否正确"
                }
        
        except requests.exceptions.ConnectionError as e:
            print(f"Web刷机失败 - 连接错误: {e}")
            return {
                'success': False,
                'error': f"无法连接到路由器: {str(e)}",
                'suggestion': "请检查路由器IP地址是否正确，网络连接是否正常，以及路由器是否在线"
            }
        except requests.exceptions.Timeout as e:
            print(f"Web刷机失败 - 超时错误: {e}")
            return {
                'success': False,
                'error': f"连接到路由器超时: {str(e)}",
                'suggestion': "请检查网络连接是否稳定，或尝试增加超时时间"
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Web刷机失败: {e}")
            return {
                'success': False,
                'error': f"Web刷机失败: {str(e)}",
                'detail': traceback.format_exc(),
                'suggestion': "请检查路由器是否支持Web刷机，以及固件文件是否正确"
            }
    
    def flash_via_ssh(self, ip, credentials, firmware_path):
        """通过SSH刷机"""
        try:
            print(f"=== 开始SSH刷机 ===")
            print(f"路由器IP: {ip}")
            print(f"登录凭据: {credentials['username']}/{'*' * len(credentials['password'])}")
            print(f"固件文件: {firmware_path}")
            
            # 检查固件文件
            if not os.path.exists(firmware_path):
                error = f"固件文件不存在: {firmware_path}"
                print(f"SSH刷机失败: {error}")
                return {'success': False, 'error': error}
            
            # 获取固件大小
            firmware_size = os.path.getsize(firmware_path)
            print(f"固件大小: {firmware_size} 字节 ({firmware_size / (1024*1024):.2f} MB)")
            
            if firmware_size < 1024 * 1024:  # 至少1MB
                error = f"固件文件太小，可能不是有效的固件 (仅 {firmware_size / (1024*1024):.2f} MB)"
                print(f"SSH刷机失败: {error}")
                return {'success': False, 'error': error}
            
            # 创建SSH客户端
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # 连接SSH
            print(f"连接到SSH服务器: {ip}:22")
            client.connect(
                hostname=ip,
                username=credentials['username'],
                password=credentials['password'],
                timeout=10
            )
            print(f"SSH连接成功")
            
            # 尝试获取品牌信息
            brand = 'Unknown'
            model = 'Generic'
            
            # 尝试获取品牌和型号信息
            brand_commands = [
                "cat /proc/cpuinfo | grep -i 'model name'",
                "cat /etc/openwrt_release | grep -i 'DISTRIB_ID'",
                "nvram get productid",
                "nvram get model",
                "cat /tmp/sysinfo/model"
            ]
            
            for cmd in brand_commands:
                try:
                    print(f"执行命令获取品牌信息: {cmd}")
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
                    output = stdout.read().decode('utf-8', errors='ignore').strip()
                    if output:
                        print(f"命令输出: {output}")
                        # 尝试从输出中提取品牌
                        common_brands = ['TP-Link', 'ASUS', 'Xiaomi', 'Huawei', 'Tenda', 'Mercury', 'Netgear', 'D-Link', 'Linksys']
                        for brand_name in common_brands:
                            if brand_name.lower() in output.lower():
                                brand = brand_name
                                print(f"识别到品牌: {brand}")
                                break
                        
                        # 尝试提取型号
                        if 'model' in cmd.lower() and model == 'Generic':
                            model = output.split(':')[-1].strip() if ':' in output else output
                            print(f"识别到型号: {model}")
                    
                    if brand != 'Unknown' and model != 'Generic':
                        break
                except:
                    continue
            
            # 1. 将固件上传到路由器临时目录
            remote_path = '/tmp/firmware.bin'
            print(f"上传固件到路由器临时目录: {remote_path}")
            
            sftp = client.open_sftp()
            sftp.put(firmware_path, remote_path)
            sftp.close()
            print(f"固件上传成功")
            
            # 2. 执行刷机命令
            # 品牌特定的刷机命令
            brand_flash_commands = {
                'TP-Link': [
                    f"mtd write {remote_path} firmware",
                    f"nvram commit && mtd -r write {remote_path} firmware"
                ],
                'ASUS': [
                    f"mtd write {remote_path} linux",
                    f"flashrom -w {remote_path} -p internal"
                ],
                'Xiaomi': [
                    f"sysupgrade -v {remote_path}",
                    f"mtd -r write {remote_path} firmware"
                ],
                'Huawei': [
                    f"flash write {remote_path} firmware",
                    f"update_firmware {remote_path}"
                ],
                'Tenda': [
                    f"mtd write {remote_path} firmware",
                    f"sysupgrade {remote_path}"
                ],
                'Mercury': [
                    f"mtd write {remote_path} firmware",
                    f"nvram commit && mtd -r write {remote_path} firmware"
                ],
                'Netgear': [
                    f"flash -noheader :{remote_path} flash0",
                    f"sysupgrade {remote_path}"
                ],
                'D-Link': [
                    f"mtd write {remote_path} linux",
                    f"sysupgrade {remote_path}"
                ],
                'Linksys': [
                    f"mtd write {remote_path} linux",
                    f"nvram commit && reboot"
                ]
            }
            
            # 通用刷机命令（如果无法识别品牌）
            default_flash_commands = [
                f"sysupgrade {remote_path}",
                f"mtd write {remote_path} firmware",
                f"flash write {remote_path} firmware",
                f"nvram commit && mtd -r write {remote_path} firmware",
                f"dd if={remote_path} of=/dev/mtdblock0 && reboot"
            ]
            
            # 选择刷机命令
            flash_commands = brand_flash_commands.get(brand, default_flash_commands)
            print(f"使用品牌: {brand} 的刷机命令")
            
            result = None
            for cmd in flash_commands:
                try:
                    print(f"执行刷机命令: {cmd}")
                    # 对于可能导致设备重启的命令，设置更长的超时时间
                    if any(keyword in cmd for keyword in ['reboot', 'sysupgrade', '-r']):
                        timeout = 120
                    else:
                        timeout = 60
                    
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                    output = stdout.read().decode('utf-8', errors='ignore')
                    error = stderr.read().decode('utf-8', errors='ignore')
                    
                    print(f"命令输出: {output}")
                    if error:
                        print(f"命令错误: {error}")
                    
                    # 检查命令是否成功执行
                    if (output and any(keyword in output.lower() for keyword in ["success", "ok", "upgrade", "完成", "成功"])) or \
                       ("sysupgrade" in cmd and "timeout" in str(type(e))):  # sysupgrade会导致连接断开，所以超时是正常的
                        result = {"success": True, "message": f"执行命令成功: {cmd}"}
                        print(f"命令执行成功: {cmd}")
                        break
                    elif error and any(keyword in error.lower() for keyword in ["error", "fail", "invalid", "not found"]):
                        print(f"命令执行失败: {cmd}")
                        continue
                    else:
                        # 有些命令可能没有输出，但执行成功
                        result = {"success": True, "message": f"执行命令成功: {cmd}"}
                        print(f"命令执行成功（无输出）: {cmd}")
                        break
                except Exception as e:
                    # 对于sysupgrade等会导致设备重启的命令，超时是正常的
                    if "sysupgrade" in cmd and isinstance(e, paramiko.ssh_exception.SSHException):
                        result = {"success": True, "message": f"执行命令成功（设备正在重启）: {cmd}"}
                        print(f"命令执行成功（设备正在重启）: {cmd}")
                        break
                    print(f"执行命令异常: {e}")
                    continue
            
            client.close()
            
            if result:
                print(f"=== SSH刷机成功 ===")
                return {
                    **result,
                    'brand': brand,
                    'model': model
                }
            else:
                error = '所有刷机命令都执行失败，请检查固件是否兼容'
                print(f"SSH刷机失败: {error}")
                return {
                    'success': False,
                    'error': error,
                    'brand': brand,
                    'model': model,
                    'suggestion': "请检查固件文件是否与路由器兼容，以及是否有足够的权限"
                }
        
        except paramiko.AuthenticationException:
            error = "SSH认证失败，请检查用户名和密码"
            print(f"SSH刷机失败: {error}")
            return {
                'success': False,
                'error': error,
                'suggestion': "请确保SSH服务已开启，并且用户名和密码正确"
            }
        except paramiko.SSHException as e:
            error = f"SSH连接失败: {str(e)}"
            print(f"SSH刷机失败: {error}")
            return {
                'success': False,
                'error': error,
                'suggestion': "请检查SSH服务是否已开启，以及网络连接是否正常"
            }
        except Exception as e:
            print(f"SSH刷机失败: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f"SSH刷机失败: {str(e)}",
                'detail': traceback.format_exc(),
                'suggestion': "请检查路由器是否支持SSH，以及是否有足够的权限"
            }
    
    def flash_firmware(self, router_info, credentials, firmware_path):
        """综合刷机，按优先级尝试不同方法"""
        brand = router_info.get('brand', 'Unknown')
        ip = router_info['ip']
        print(f"=== 开始综合刷机 ===")
        print(f"路由器信息: {brand} {ip}")
        print(f"固件文件: {firmware_path}")
        
        # 1. 尝试Web刷机
        print(f"\n1. 尝试Web刷机...")
        result = self.flash_via_web(router_info, credentials, firmware_path)
        if result['success']:
            print(f"Web刷机成功: {result['message']}")
            return result
        else:
            print(f"Web刷机失败: {result['error']}")
        
        # 2. 检查是否是小米路由器，提供特殊处理建议
        is_xiaomi = brand.lower() == 'xiaomi' or 'miwifi' in firmware_path.lower() or 'Xiaomi' in str(router_info)
        
        if is_xiaomi:
            print(f"\n2. 检测到小米路由器，提供特殊处理...")
            
            # 检查是否是小米官方固件（MiCGI）
            try:
                import requests
                test_url = f"http://{ip}:80"
                response = requests.get(test_url, timeout=5)
                is_micgi = 'MiCGI' in str(response.headers)
                print(f"检测到MiCGI: {is_micgi}")
                
                if is_micgi:
                    # 小米官方固件处理
                    print("\n3. 尝试小米官方固件（MiCGI）刷机方法...")
                    print("注意：小米官方固件可能需要特殊的刷机方式")
                    
                    # 提供小米官方固件的刷机建议
                    return {
                        'success': False,
                        'error': '小米官方固件需要特殊处理',
                        'suggestion': f"小米官方固件（MiCGI）无法直接刷机。请尝试以下方法：\n1. 手动登录路由器管理界面（http://{ip}）\n2. 在'系统升级'页面选择固件文件\n3. 点击'升级'按钮\n4. 等待刷机完成",
                        'detail': "已尝试Web刷机，小米官方固件需要手动刷机"
                    }
                
            except Exception as e:
                print(f"检测MiCGI失败: {e}")
        
        # 3. 尝试SSH刷机（仅当不是小米官方固件时）
        if not (is_xiaomi and is_micgi):
            print(f"\n3. 尝试SSH刷机...")
            result = self.flash_via_ssh(ip, credentials, firmware_path)
            if result['success']:
                print(f"SSH刷机成功: {result['message']}")
                return result
            else:
                print(f"SSH刷机失败: {result['error']}")
        
        # 4. 尝试其他小米路由器特殊方法
        if is_xiaomi:
            print(f"\n4. 尝试小米路由器特殊刷机方法...")
            try:
                # 尝试使用TFTP或其他方法
                print("尝试TFTP刷机（小米路由器常用方法）...")
                print("注意：TFTP刷机需要在路由器启动时进入特定模式")
                
                return {
                    'success': False,
                    'error': '所有自动刷机方法都失败',
                    'suggestion': f"请尝试手动刷机方法：\n1. 断开路由器电源\n2. 按住Reset按钮，重新连接电源，等待指示灯闪烁\n3. 使用TFTP工具上传固件到192.168.31.1\n4. 等待刷机完成\n\n或使用Web界面手动升级：\n1. 登录路由器管理界面（http://{ip}）\n2. 进入'系统升级'页面\n3. 选择固件文件，点击'升级'",
                    'detail': "已尝试Web刷机、SSH刷机，建议手动刷机"
                }
            except Exception as e:
                print(f"小米特殊刷机失败: {e}")
        
        # 5. 所有方法都失败
        print(f"\n=== 所有刷机方法都失败 ===")
        return {
            'success': False,
            'error': '所有刷机方法都失败，请尝试手动刷机',
            'suggestion': f"请尝试以下方法：\n1. 确保路由器与电脑在同一局域网\n2. 检查登录凭据是否正确\n3. 尝试手动登录路由器管理界面（http://{ip}）进行刷机\n4. 检查固件文件是否与路由器型号兼容",
            'detail': f"已尝试方法: Web刷机{'、SSH刷机' if not (is_xiaomi and is_micgi) else ''}{'、小米特殊刷机' if is_xiaomi else ''}"
        }
    
    def verify_backup(self, backup_path):
        """验证备份文件完整性"""
        try:
            if not os.path.exists(backup_path):
                return {'valid': False, 'error': '备份文件不存在'}
            
            # 检查文件大小
            file_size = os.path.getsize(backup_path)
            if file_size < 1024:
                return {'valid': False, 'error': '备份文件太小，可能损坏'}
            
            # 计算MD5并与记录比较
            record = self.session.query(BackupRecord).filter_by(
                backup_path=backup_path
            ).first()
            
            if record:
                current_md5 = self.calculate_md5(backup_path)
                if current_md5 == record.md5_sum:
                    return {'valid': True, 'md5': current_md5}
                else:
                    return {
                        'valid': False, 
                        'error': 'MD5校验失败，文件可能已损坏'
                    }
            
            # 没有记录但文件存在且大小正常
            return {'valid': True, 'md5': self.calculate_md5(backup_path)}
        
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def get_backup_records(self):
        """获取所有备份记录"""
        records = self.session.query(BackupRecord).order_by(
            BackupRecord.backup_date.desc()
        ).all()
        
        return [{
            'id': record.id,
            'device_brand': record.device_brand,
            'device_model': record.device_model,
            'firmware_version': record.firmware_version,
            'backup_path': record.backup_path,
            'backup_date': record.backup_date.strftime("%Y-%m-%d %H:%M:%S"),
            'md5_sum': record.md5_sum,
            'size': record.size
        } for record in records]
