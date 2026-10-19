@echo off
setlocal
cd /d "%~dp0"
py -3 -m venv .build-venv
if errorlevel 1 goto :error
call .build-venv\Scripts\activate.bat
python -m pip install -r requirements-desktop-build.txt
if errorlevel 1 goto :error
pyinstaller --noconfirm --clean --onedir --windowed --name TabbyDesktop --icon "assets\tabby-logo.ico" --add-data "assets;assets" --add-data "index.html;." --add-data "game_client;game_client" --paths game_client --collect-all keyring --collect-all eth_account --collect-all cryptography --collect-all PySide6.QtWebEngineCore --collect-all PySide6.QtWebEngineWidgets desktop.py
if errorlevel 1 goto :error
echo Build complete: dist\TabbyDesktop\TabbyDesktop.exe
exit /b 0
:error
echo Build failed.
exit /b 1
