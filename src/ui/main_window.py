import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QPushButton, QLabel, QTextEdit, QProgressBar,
    QLineEdit, QComboBox, QFileDialog, QMessageBox, QGroupBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QGridLayout
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon

from src.communication.device_discovery import DeviceDiscovery
from src.business.brand_recognition import BrandRecognition
from src.business.firmware_backup import FirmwareBackup

class DiscoveryThread(QThread):
    """设备发现线程"""
    result_signal = pyqtSignal(list)
    status_signal = pyqtSignal(str)
    
    def run(self):
        self.status_signal.emit("正在搜索路由器...")
        discovery = DeviceDiscovery()
        routers = discovery.discover_routers()
        self.result_signal.emit(routers)
        self.status_signal.emit("搜索完成")

class BackupThread(QThread):
    """固件备份线程"""
    result_signal = pyqtSignal(dict)
    status_signal = pyqtSignal(str)
    
    def __init__(self, router_info, credentials):
        super().__init__()
        self.router_info = router_info
        self.credentials = credentials
    
    def run(self):
        self.status_signal.emit("正在备份原厂固件...")
        backup = FirmwareBackup()
        result = backup.backup_firmware(self.router_info, self.credentials)
        self.result_signal.emit(result)
        if result['success']:
            self.status_signal.emit("备份完成")
        else:
            self.status_signal.emit(f"备份失败: {result['error']}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("路由器刷机工具")
        self.setGeometry(100, 100, 800, 600)
        
        # 初始化业务逻辑
        self.brand_recognizer = BrandRecognition()
        self.firmware_backup = FirmwareBackup()
        
        # 变量初始化
        self.discovered_routers = []
        self.selected_router = None
        
        # 创建主布局
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # 创建标签页
        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)
        
        # 创建各功能标签页
        self.create_device_tab()
        self.create_backup_tab()
        self.create_flash_tab()
        self.create_log_tab()
        
        # 创建状态栏
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")
        
        # 初始化日志
        self.log_text_edit.append("路由器刷机工具已启动")
    
    def create_device_tab(self):
        """设备发现标签页"""
        self.device_tab = QWidget()
        self.tab_widget.addTab(self.device_tab, "设备发现")
        
        layout = QVBoxLayout(self.device_tab)
        
        # 搜索区域
        search_layout = QHBoxLayout()
        
        # 搜索按钮
        self.search_button = QPushButton("搜索路由器")
        self.search_button.clicked.connect(self.start_discovery)
        search_layout.addWidget(self.search_button)
        
        # 手动输入区域
        self.manual_ip_label = QLabel("手动输入IP:")
        search_layout.addWidget(self.manual_ip_label)
        
        self.manual_ip_edit = QLineEdit()
        self.manual_ip_edit.setPlaceholderText("例如: 192.168.1.1")
        search_layout.addWidget(self.manual_ip_edit)
        
        self.add_manual_button = QPushButton("添加")
        self.add_manual_button.clicked.connect(self.add_manual_router)
        search_layout.addWidget(self.add_manual_button)
        
        search_layout.addStretch()
        layout.addLayout(search_layout)
        
        # 状态标签
        self.discovery_status_label = QLabel("就绪")
        self.discovery_status_label.setStyleSheet("color: blue;")
        layout.addWidget(self.discovery_status_label)
        
        # 设备列表
        self.device_group = QGroupBox("发现的路由器")
        device_layout = QVBoxLayout(self.device_group)
        
        self.device_table = QTableWidget(0, 4)
        self.device_table.setHorizontalHeaderLabels(["IP地址", "端口", "品牌", "型号"])
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.device_table.clicked.connect(self.on_device_selected)
        device_layout.addWidget(self.device_table)
        
        # 没有发现设备时的提示
        self.no_devices_label = QLabel("未发现路由器，请尝试点击'搜索路由器'按钮，或手动输入路由器IP地址")
        self.no_devices_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.no_devices_label.setStyleSheet("color: gray; font-style: italic;")
        self.no_devices_label.hide()
        device_layout.addWidget(self.no_devices_label)
        
        layout.addWidget(self.device_group)
        
        # 设备详情
        self.detail_group = QGroupBox("设备详情")
        detail_layout = QGridLayout(self.detail_group)
        
        detail_layout.addWidget(QLabel("IP地址:"), 0, 0)
        self.ip_label = QLabel("- - -")
        detail_layout.addWidget(self.ip_label, 0, 1)
        
        detail_layout.addWidget(QLabel("端口:"), 0, 2)
        self.port_label = QLabel("- - -")
        detail_layout.addWidget(self.port_label, 0, 3)
        
        detail_layout.addWidget(QLabel("品牌:"), 1, 0)
        self.brand_label = QLabel("- - -")
        detail_layout.addWidget(self.brand_label, 1, 1)
        
        detail_layout.addWidget(QLabel("型号:"), 1, 2)
        self.model_label = QLabel("- - -")
        detail_layout.addWidget(self.model_label, 1, 3)
        
        detail_layout.addWidget(QLabel("固件版本:"), 2, 0)
        self.firmware_label = QLabel("- - -")
        detail_layout.addWidget(self.firmware_label, 2, 1)
        
        detail_layout.addWidget(QLabel("管理地址:"), 2, 2)
        self.management_label = QLabel("- - -")
        detail_layout.addWidget(self.management_label, 2, 3)
        
        layout.addWidget(self.detail_group)
    
    def create_backup_tab(self):
        """固件备份标签页"""
        self.backup_tab = QWidget()
        self.tab_widget.addTab(self.backup_tab, "固件备份")
        
        layout = QVBoxLayout(self.backup_tab)
        
        # 备份设置
        settings_group = QGroupBox("备份设置")
        settings_layout = QGridLayout(settings_group)
        
        settings_layout.addWidget(QLabel("路由器IP:"), 0, 0)
        self.backup_ip_edit = QLineEdit()
        settings_layout.addWidget(self.backup_ip_edit, 0, 1)
        
        settings_layout.addWidget(QLabel("用户名:"), 1, 0)
        self.backup_username_edit = QLineEdit()
        self.backup_username_edit.setText("admin")
        settings_layout.addWidget(self.backup_username_edit, 1, 1)
        
        settings_layout.addWidget(QLabel("密码:"), 1, 2)
        self.backup_password_edit = QLineEdit()
        self.backup_password_edit.setText("admin")
        self.backup_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        settings_layout.addWidget(self.backup_password_edit, 1, 3)
        
        settings_layout.addWidget(QLabel("备份路径:"), 2, 0)
        self.backup_path_edit = QLineEdit()
        self.backup_path_edit.setText(os.path.expanduser("~/RouterFlasher/Backups"))
        settings_layout.addWidget(self.backup_path_edit, 2, 1, 1, 2)
        
        browse_button = QPushButton("浏览")
        browse_button.clicked.connect(self.browse_backup_path)
        settings_layout.addWidget(browse_button, 2, 3)
        
        layout.addWidget(settings_group)
        
        # 备份按钮
        button_layout = QHBoxLayout()
        self.backup_button = QPushButton("开始备份")
        self.backup_button.clicked.connect(self.start_backup)
        button_layout.addWidget(self.backup_button)
        
        self.load_backup_button = QPushButton("加载备份记录")
        self.load_backup_button.clicked.connect(self.load_backup_records)
        button_layout.addWidget(self.load_backup_button)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # 备份进度
        self.progress_group = QGroupBox("备份进度")
        progress_layout = QVBoxLayout(self.progress_group)
        
        self.backup_progress = QProgressBar()
        progress_layout.addWidget(self.backup_progress)
        
        self.backup_status_label = QLabel("就绪")
        progress_layout.addWidget(self.backup_status_label)
        
        layout.addWidget(self.progress_group)
        
        # 备份记录
        self.backup_table = QTableWidget(0, 5)
        self.backup_table.setHorizontalHeaderLabels(["品牌", "型号", "固件版本", "备份日期", "文件路径"])
        self.backup_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.backup_table)
    
    def create_flash_tab(self):
        """固件刷标签页"""
        self.flash_tab = QWidget()
        self.tab_widget.addTab(self.flash_tab, "固件刷机")
        
        layout = QVBoxLayout(self.flash_tab)
        
        # 刷机设置
        settings_group = QGroupBox("刷机设置")
        settings_layout = QGridLayout(settings_group)
        
        settings_layout.addWidget(QLabel("路由器IP:"), 0, 0)
        self.flash_ip_edit = QLineEdit()
        settings_layout.addWidget(self.flash_ip_edit, 0, 1)
        
        settings_layout.addWidget(QLabel("用户名:"), 1, 0)
        self.flash_username_edit = QLineEdit()
        self.flash_username_edit.setText("admin")
        settings_layout.addWidget(self.flash_username_edit, 1, 1)
        
        settings_layout.addWidget(QLabel("密码:"), 1, 2)
        self.flash_password_edit = QLineEdit()
        self.flash_password_edit.setText("admin")
        self.flash_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        settings_layout.addWidget(self.flash_password_edit, 1, 3)
        
        settings_layout.addWidget(QLabel("固件文件:"), 2, 0)
        self.firmware_path_edit = QLineEdit()
        settings_layout.addWidget(self.firmware_path_edit, 2, 1, 1, 2)
        
        browse_button = QPushButton("浏览")
        browse_button.clicked.connect(self.browse_firmware_file)
        settings_layout.addWidget(browse_button, 2, 3)
        
        layout.addWidget(settings_group)
        
        # 刷机按钮
        button_layout = QHBoxLayout()
        self.flash_button = QPushButton("开始刷机")
        self.flash_button.clicked.connect(self.start_flash)
        button_layout.addWidget(self.flash_button)
        
        self.verify_button = QPushButton("验证固件")
        self.verify_button.clicked.connect(self.verify_firmware)
        button_layout.addWidget(self.verify_button)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # 刷机进度
        self.flash_progress_group = QGroupBox("刷机进度")
        flash_progress_layout = QVBoxLayout(self.flash_progress_group)
        
        self.flash_progress = QProgressBar()
        flash_progress_layout.addWidget(self.flash_progress)
        
        self.flash_status_label = QLabel("就绪")
        flash_progress_layout.addWidget(self.flash_status_label)
        
        layout.addWidget(self.flash_progress_group)
        
        # 刷机说明
        note_group = QGroupBox("刷机注意事项")
        note_layout = QVBoxLayout(note_group)
        
        note_text = QLabel("1. 刷机前请确保已备份原厂固件\n" 
                         "2. 刷机过程中请勿断开电源或网络连接\n" 
                         "3. 请使用与设备兼容的固件文件\n" 
                         "4. 刷机有风险，操作需谨慎")
        note_text.setWordWrap(True)
        note_layout.addWidget(note_text)
        
        layout.addWidget(note_group)
    
    def create_log_tab(self):
        """日志标签页"""
        self.log_tab = QWidget()
        self.tab_widget.addTab(self.log_tab, "操作日志")
        
        layout = QVBoxLayout(self.log_tab)
        
        self.log_text_edit = QTextEdit()
        self.log_text_edit.setReadOnly(True)
        layout.addWidget(self.log_text_edit)
        
        button_layout = QHBoxLayout()
        self.clear_log_button = QPushButton("清空日志")
        self.clear_log_button.clicked.connect(self.clear_log)
        button_layout.addWidget(self.clear_log_button)
        
        self.export_log_button = QPushButton("导出日志")
        self.export_log_button.clicked.connect(self.export_log)
        button_layout.addWidget(self.export_log_button)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
    
    def start_discovery(self):
        """开始设备发现"""
        self.search_button.setEnabled(False)
        self.device_table.setRowCount(0)
        
        # 启动发现线程
        self.discovery_thread = DiscoveryThread()
        self.discovery_thread.result_signal.connect(self.on_discovery_complete)
        self.discovery_thread.status_signal.connect(self.update_status)
        self.discovery_thread.start()
    
    def add_manual_router(self):
        """手动添加路由器"""
        manual_ip = self.manual_ip_edit.text().strip()
        if not manual_ip:
            QMessageBox.warning(self, "警告", "请输入有效的IP地址")
            return
        
        # 验证IP格式
        import re
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if not re.match(ip_pattern, manual_ip):
            QMessageBox.warning(self, "警告", "请输入有效的IP地址格式")
            return
        
        self.discovery_status_label.setText(f"正在检查手动添加的IP: {manual_ip}")
        self.log(f"正在检查手动添加的路由器: {manual_ip}")
        
        # 检查该IP是否已存在
        for i in range(self.device_table.rowCount()):
            if self.device_table.item(i, 0).text() == manual_ip:
                QMessageBox.information(self, "提示", "该路由器已经在列表中")
                return
        
        # 检查设备是否可访问
        from src.communication.device_discovery import DeviceDiscovery
        discovery = DeviceDiscovery()
        
        # 检查常见端口
        found = False
        for port in [80, 8080, 8443]:
            if discovery.check_router_port(manual_ip, port):
                router_info = discovery.get_router_info(manual_ip, port)
                if router_info:
                    # 添加到设备列表
                    self.discovered_routers.append(router_info)
                    
                    # 识别品牌
                    brand_info = self.brand_recognizer.recognize_brand(router_info)
                    
                    row_position = self.device_table.rowCount()
                    self.device_table.insertRow(row_position)
                    
                    self.device_table.setItem(row_position, 0, QTableWidgetItem(manual_ip))
                    self.device_table.setItem(row_position, 1, QTableWidgetItem(str(port)))
                    self.device_table.setItem(row_position, 2, QTableWidgetItem(brand_info['brand']))
                    self.device_table.setItem(row_position, 3, QTableWidgetItem(brand_info['model']))
                    
                    self.log(f"手动添加路由器成功: {manual_ip}:{port}")
                    self.discovery_status_label.setText(f"手动添加路由器成功: {manual_ip}:{port}")
                    
                    # 显示详情
                    self.on_device_selected()
                    found = True
                    break
        
        if not found:
            # 即使无法访问，也允许用户添加，以便后续操作
            router_info = {'ip': manual_ip, 'port': 80}
            self.discovered_routers.append(router_info)
            
            brand_info = {'brand': 'Unknown', 'model': 'Manual'}
            
            row_position = self.device_table.rowCount()
            self.device_table.insertRow(row_position)
            
            self.device_table.setItem(row_position, 0, QTableWidgetItem(manual_ip))
            self.device_table.setItem(row_position, 1, QTableWidgetItem('80'))
            self.device_table.setItem(row_position, 2, QTableWidgetItem(brand_info['brand']))
            self.device_table.setItem(row_position, 3, QTableWidgetItem(brand_info['model']))
            
            self.log(f"手动添加路由器: {manual_ip} (无法验证可达性)")
            self.discovery_status_label.setText(f"手动添加路由器: {manual_ip} (无法验证可达性)")
            QMessageBox.information(self, "提示", f"已添加路由器 {manual_ip}，但无法验证其可达性")
        
        # 清空输入框
        self.manual_ip_edit.clear()
        self.update_no_devices_label()
    
    def on_discovery_complete(self, routers):
        """设备发现完成"""
        self.search_button.setEnabled(True)
        self.discovered_routers = routers
        
        # 清空现有列表
        self.device_table.setRowCount(0)
        
        # 更新设备列表
        for router in routers:
            # 识别品牌
            brand_info = self.brand_recognizer.recognize_brand(router)
            
            row_position = self.device_table.rowCount()
            self.device_table.insertRow(row_position)
            
            self.device_table.setItem(row_position, 0, QTableWidgetItem(router['ip']))
            self.device_table.setItem(row_position, 1, QTableWidgetItem(str(router['port'])))
            self.device_table.setItem(row_position, 2, QTableWidgetItem(brand_info['brand']))
            self.device_table.setItem(row_position, 3, QTableWidgetItem(brand_info['model']))
        
        self.discovery_status_label.setText(f"搜索完成，发现 {len(routers)} 台路由器")
        self.log(f"发现了 {len(routers)} 台路由器")
        
        # 更新无设备提示
        self.update_no_devices_label()
    
    def update_no_devices_label(self):
        """更新无设备提示"""
        if self.device_table.rowCount() == 0:
            self.no_devices_label.show()
        else:
            self.no_devices_label.hide()
    
    def on_device_selected(self):
        """选择设备"""
        selected_row = self.device_table.currentRow()
        if selected_row >= 0 and selected_row < len(self.discovered_routers):
            router = self.discovered_routers[selected_row]
            self.selected_router = router
            
            # 识别品牌
            brand_info = self.brand_recognizer.recognize_brand(router)
            
            # 更新详情
            self.ip_label.setText(router['ip'])
            self.port_label.setText(str(router['port']))
            self.brand_label.setText(brand_info['brand'])
            self.model_label.setText(brand_info['model'])
            self.firmware_label.setText("未知")  # 需要进一步获取
            self.management_label.setText(f"http://{router['ip']}:{router['port']}")
            
            # 更新备份和刷机标签页的IP
            self.backup_ip_edit.setText(router['ip'])
            self.flash_ip_edit.setText(router['ip'])
            
            # 设置默认账号密码
            credentials = self.brand_recognizer.get_default_credentials(brand_info['brand'])
            self.backup_username_edit.setText(credentials['username'])
            self.backup_password_edit.setText(credentials['password'])
            self.flash_username_edit.setText(credentials['username'])
            self.flash_password_edit.setText(credentials['password'])
    
    def browse_backup_path(self):
        """浏览备份路径"""
        path = QFileDialog.getExistingDirectory(self, "选择备份路径")
        if path:
            self.backup_path_edit.setText(path)
    
    def browse_firmware_file(self):
        """浏览固件文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择固件文件", "", "固件文件 (*.bin)"
        )
        if file_path:
            self.firmware_path_edit.setText(file_path)
    
    def start_backup(self):
        """开始备份"""
        if not self.backup_ip_edit.text():
            QMessageBox.warning(self, "警告", "请输入路由器IP")
            return
        
        router_info = {
            'ip': self.backup_ip_edit.text(),
            'port': 80,  # 默认端口
            'brand': self.brand_label.text(),
            'model': self.model_label.text()
        }
        
        credentials = {
            'username': self.backup_username_edit.text(),
            'password': self.backup_password_edit.text()
        }
        
        # 启动备份线程
        self.backup_thread = BackupThread(router_info, credentials)
        self.backup_thread.result_signal.connect(self.on_backup_complete)
        self.backup_thread.status_signal.connect(self.update_backup_status)
        self.backup_thread.start()
        
        self.backup_button.setEnabled(False)
        self.backup_progress.setValue(0)
    
    def on_backup_complete(self, result):
        """备份完成"""
        self.backup_button.setEnabled(True)
        self.backup_progress.setValue(100)
        
        if result['success']:
            QMessageBox.information(self, "成功", f"固件备份成功！\n文件路径: {result['backup_path']}")
            self.log(f"固件备份成功: {result['backup_path']}")
            self.load_backup_records()
        else:
            QMessageBox.critical(self, "失败", f"固件备份失败: {result['error']}")
            self.log(f"固件备份失败: {result['error']}")
    
    def update_backup_status(self, status):
        """更新备份状态"""
        self.backup_status_label.setText(status)
        self.log(status)
        
        # 更新进度条
        if "准备" in status:
            self.backup_progress.setValue(10)
        elif "备份" in status:
            self.backup_progress.setValue(50)
        elif "完成" in status:
            self.backup_progress.setValue(100)
    
    def load_backup_records(self):
        """加载备份记录"""
        records = self.firmware_backup.get_backup_records()
        
        self.backup_table.setRowCount(0)
        for record in records:
            row_position = self.backup_table.rowCount()
            self.backup_table.insertRow(row_position)
            
            self.backup_table.setItem(row_position, 0, QTableWidgetItem(record['device_brand']))
            self.backup_table.setItem(row_position, 1, QTableWidgetItem(record['device_model']))
            self.backup_table.setItem(row_position, 2, QTableWidgetItem(record['firmware_version']))
            self.backup_table.setItem(row_position, 3, QTableWidgetItem(record['backup_date']))
            self.backup_table.setItem(row_position, 4, QTableWidgetItem(record['backup_path']))
    
    def start_flash(self):
        """开始刷机"""
        if not self.flash_ip_edit.text():
            QMessageBox.warning(self, "警告", "请输入路由器IP")
            return
        
        firmware_path = self.firmware_path_edit.text()
        if not firmware_path:
            QMessageBox.warning(self, "警告", "请选择固件文件")
            return
        
        # 确认刷机
        reply = QMessageBox.question(
            self, "确认刷机", "刷机过程中请勿断开电源或网络连接，否则可能导致设备变砖。\n\n确定要继续吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.No:
            return
        
        # 准备刷机参数
        router_info = {
            'ip': self.flash_ip_edit.text(),
            'port': 80,  # 默认端口
            'brand': self.brand_label.text(),
            'model': self.model_label.text()
        }
        
        credentials = {
            'username': self.flash_username_edit.text(),
            'password': self.flash_password_edit.text()
        }
        
        # 开始刷机
        self.log("开始刷机...")
        self.flash_status_label.setText("正在准备刷机...")
        self.flash_progress.setValue(10)
        
        # 创建刷机线程
        self.flash_thread = FlashThread(router_info, credentials, firmware_path)
        self.flash_thread.result_signal.connect(self.on_flash_complete)
        self.flash_thread.status_signal.connect(self.update_flash_status)
        self.flash_thread.start()
        
        self.flash_button.setEnabled(False)
        self.verify_button.setEnabled(False)
    
    def on_flash_complete(self, result):
        """刷机完成"""
        self.flash_button.setEnabled(True)
        self.verify_button.setEnabled(True)
        self.flash_progress.setValue(100)
        
        if result['success']:
            self.log(f"刷机成功: {result['message']}")
            QMessageBox.information(self, "成功", f"刷机成功！\n{result['message']}")
        else:
            self.log(f"刷机失败: {result['error']}")
            QMessageBox.critical(self, "失败", f"刷机失败: {result['error']}")
    
    def update_flash_status(self, status):
        """更新刷机状态"""
        self.flash_status_label.setText(status)
        self.log(status)
        
        # 更新进度条
        if "准备" in status:
            self.flash_progress.setValue(10)
        elif "检查" in status:
            self.flash_progress.setValue(20)
        elif "执行" in status:
            self.flash_progress.setValue(50)
        elif "完成" in status:
            self.flash_progress.setValue(100)
    
    def verify_firmware(self):
        """验证固件"""
        firmware_path = self.firmware_path_edit.text()
        if not firmware_path:
            QMessageBox.warning(self, "警告", "请选择固件文件")
            return
        
        # 这里添加固件验证逻辑
        self.log(f"验证固件: {firmware_path}")
        QMessageBox.information(self, "提示", "固件验证功能正在开发中...")
    
    def update_status(self, status):
        """更新状态栏"""
        self.status_bar.showMessage(status)
        self.log(status)
    
    def log(self, message):
        """记录日志"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text_edit.append(f"[{timestamp}] {message}")
        # 自动滚动到底部
        self.log_text_edit.verticalScrollBar().setValue(
            self.log_text_edit.verticalScrollBar().maximum()
        )
    
    def clear_log(self):
        """清空日志"""
        self.log_text_edit.clear()
    
    def export_log(self):
        """导出日志"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出日志", "", "日志文件 (*.txt)"
        )
        if file_path:
            with open(file_path, 'w') as f:
                f.write(self.log_text_edit.toPlainText())
            QMessageBox.information(self, "成功", f"日志导出成功！\n文件路径: {file_path}")

class FlashThread(QThread):
    """刷机线程"""
    result_signal = pyqtSignal(dict)
    status_signal = pyqtSignal(str)
    
    def __init__(self, router_info, credentials, firmware_path):
        super().__init__()
        self.router_info = router_info
        self.credentials = credentials
        self.firmware_path = firmware_path
    
    def run(self):
        self.status_signal.emit("正在准备刷机...")
        self.status_signal.emit("正在检查固件文件...")
        
        from src.business.firmware_backup import FirmwareBackup
        backup = FirmwareBackup()
        
        self.status_signal.emit("正在执行刷机...")
        result = backup.flash_firmware(self.router_info, self.credentials, self.firmware_path)
        self.result_signal.emit(result)
        
        if result['success']:
            self.status_signal.emit("刷机完成！")
        else:
            self.status_signal.emit(f"刷机失败: {result['error']}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
