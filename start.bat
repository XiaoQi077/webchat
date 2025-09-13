@echo off
chcp 65001 >nul
echo 正在启动Web聊天室服务...
cd /d %~dp0

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo 未检测到Python，请先安装Python 3.6或更高版本
    pause
    exit /b 1
)

REM 创建必要目录
if not exist "data" mkdir data
if not exist "data\files" mkdir data\files
if not exist "data\logs" mkdir data\logs
if not exist "data\certs" mkdir data\certs

REM 检查虚拟环境
if not exist "venv" (
    echo 创建虚拟环境...
    python -m venv venv
    call venv\Scripts\activate
    echo 安装依赖...
    pip install -r requirements.txt
) else (
    call venv\Scripts\activate
)

echo 启动服务...
echo 服务将在 https://%COMPUTERNAME%.local:5000 启动
echo 或使用本机IP地址访问，如: https://192.168.1.100:5000
echo.
echo 按 Ctrl+C 停止服务
python app.py

pause