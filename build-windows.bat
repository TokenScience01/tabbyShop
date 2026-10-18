@echo off
setlocal
cd /d "%~dp0"

py -3 -m venv .build-venv
if errorlevel 1 goto :error
call .build-venv\Scripts\activate.bat
python -m pip install --upgrade pip
if errorlevel 1 goto :error
python -m pip install -r requirements-build.txt
if errorlevel 1 goto :error

pyinstaller --noconfirm --clean --onefile --name TabbyShop --add-data "index.html;." --collect-all keyring --collect-all eth_account server.py
if errorlevel 1 goto :error

echo.
echo Build complete: dist\TabbyShop.exe
echo Copy TabbyShop.exe to a writable folder, then run it. The dashboard opens in your browser.
echo Keep config.local.json and monitor.local.json beside the exe to preserve settings.
pause
exit /b 0

:error
echo.
echo Build failed. Check the error above.
pause
exit /b 1
