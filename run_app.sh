#!/bin/bash

# 路由器刷机工具启动脚本
echo "=== 路由器刷机工具 ==="
echo "正在准备运行环境..."

# 检查是否已创建虚拟环境
if [ ! -d "venv" ]; then
    echo "正在创建虚拟环境..."
    # 使用env -i清除所有环境变量，只保留必要的PATH
    env -i PATH="$PATH" python3 -m venv venv
    echo "虚拟环境创建成功！"
fi

# 激活虚拟环境
echo "正在激活虚拟环境..."
source venv/bin/activate

# 创建pip配置文件，使用国内镜像
echo "创建pip配置，使用国内镜像源..."
mkdir -p ~/.config/pip
echo "[global]\nindex-url = https://pypi.tuna.tsinghua.edu.cn/simple\ntrusted-host = pypi.tuna.tsinghua.edu.cn" > ~/.config/pip/pip.conf

# 安装核心依赖，使用env -i确保没有代理环境变量
install_pkg() {
    local pkg="$1"
    echo "正在安装: $pkg"
    # 使用env -i清除所有环境变量，只保留必要的变量
    env -i PATH="$PATH" HOME="$HOME" VIRTUAL_ENV="$VIRTUAL_ENV" python3 -m pip install --no-cache-dir "$pkg"
    if [ $? -eq 0 ]; then
        echo "✓ $pkg 安装成功！"
        return 0
    else
        echo "✗ $pkg 安装失败！"
        return 1
    fi
}

# 安装依赖
echo "=== 安装依赖包（使用国内镜像） ==="

# 先安装pysocks，解决SOCKS依赖问题
echo "先安装pysocks，解决SOCKS依赖问题..."
env -i PATH="$PATH" HOME="$HOME" VIRTUAL_ENV="$VIRTUAL_ENV" python3 -m pip install --no-cache-dir pysocks

# 安装基础依赖
install_pkg "requests"
install_pkg "sqlalchemy"
install_pkg "paramiko"

# 安装PyQt6（UI核心）
echo "=== 安装PyQt6（可能需要较长时间） ==="
install_pkg "PyQt6"

# 安装其他依赖
install_pkg "scapy"
install_pkg "netifaces"
install_pkg "python-ssdp"
install_pkg "pycryptodome"

# 验证依赖是否安装成功
echo "=== 验证依赖安装 ==="
python3 -c "import PyQt6; print('PyQt6 版本:', PyQt6.__version__)" 2>/dev/null || echo "PyQt6 安装失败！"
python3 -c "import requests; print('requests 版本:', requests.__version__)" 2>/dev/null || echo "requests 安装失败！"
python3 -c "import sqlalchemy; print('SQLAlchemy 版本:', sqlalchemy.__version__)" 2>/dev/null || echo "SQLAlchemy 安装失败！"

# 运行应用程序
echo "=== 启动应用程序 ==="
echo "正在启动路由器刷机工具..."

# 使用PYTHONPATH确保能找到src模块
PYTHONPATH="." python3 src/ui/main_window.py
