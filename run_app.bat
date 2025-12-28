@echo off

:: 路由器刷机工具Windows启动脚本
echo === 路由器刷机工具 ===
echo 正在准备运行环境...

:: 检查是否已创建虚拟环境
if not exist "venv" (
    echo 正在创建虚拟环境...
    python -m venv venv
    echo 虚拟环境创建成功！
)

:: 激活虚拟环境
echo 正在激活虚拟环境...
call venv\Scripts\activate

:: 创建pip配置文件，使用国内镜像
echo 创建pip配置，使用国内镜像源...
mkdir %USERPROFILE%\pip 2>nul
echo [global]^

index-url = https://pypi.tuna.tsinghua.edu.cn/simple^

trusted-host = pypi.tuna.tsinghua.edu.cn > %USERPROFILE%\pip\pip.ini

:: 安装核心依赖
echo === 安装依赖包（使用国内镜像） ===

:: 先安装pysocks，解决SOCKS依赖问题
echo 先安装pysocks，解决SOCKS依赖问题...
pip install --no-cache-dir pysocks

:: 安装基础依赖
echo 正在安装requests...
pip install --no-cache-dir requests

echo 正在安装SQLAlchemy...
pip install --no-cache-dir SQLAlchemy

echo 正在安装paramiko...
pip install --no-cache-dir paramiko

:: 安装PyQt6（UI核心）
echo === 安装PyQt6（可能需要较长时间） ===
pip install --no-cache-dir PyQt6

:: 安装其他依赖
echo 正在安装scapy...
pip install --no-cache-dir scapy

echo 正在安装netifaces...
pip install --no-cache-dir netifaces

echo 正在安装python-ssdp...
pip install --no-cache-dir python-ssdp

echo 正在安装pycryptodome...
pip install --no-cache-dir pycryptodome

echo 正在安装zipfile...
pip install --no-cache-dir zipfile

:: 验证依赖是否安装成功
echo === 验证依赖安装 ===
python -c "import PyQt6; print('PyQt6 版本:', PyQt6.__version__)" 2>nul || echo PyQt6 安装失败！
python -c "import requests; print('requests 版本:', requests.__version__)" 2>nul || echo requests 安装失败！
python -c "import sqlalchemy; print('SQLAlchemy 版本:', sqlalchemy.__version__)" 2>nul || echo SQLAlchemy 安装失败！

:: 运行应用程序
echo === 启动应用程序 ===
echo 正在启动路由器刷机工具...
python src/ui/main_window.py

pause