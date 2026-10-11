@echo off
rem 占位启动器：首次运行 guard.py 时会按真实 python 路径重新生成本文件。
python -X utf8 "%~dp0guard.py" recycle --payload "%~1"
exit /b %errorlevel%
