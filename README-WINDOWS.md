# Tabby Shop Windows 版

## 直接运行源码

1. 安装 Python 3.11 或更新版本，并勾选 **Add Python to PATH**。
2. 在项目目录打开命令提示符，运行：

   ```bat
   py -3 -m venv .venv
   .venv\Scripts\activate
   python -m pip install -r requirements.txt
   python server.py
   ```
3. 浏览器会自动打开 `http://127.0.0.1:8766/`。保持命令行窗口运行即可；关闭窗口会停止本地服务。

## 打包为单文件 exe

在 Windows 电脑安装 Python 3.11+，把项目文件夹下载或克隆到本机，双击 `build-windows.bat`。构建完成后，文件位于 `dist\TabbyShop.exe`。把 exe 放到有写入权限的普通文件夹后运行，浏览器会打开本地控制台。关闭 exe 的命令行窗口会停止服务。

也可以在 GitHub 仓库的 **Actions → Build Windows exe → Run workflow** 手动构建，并从运行结果下载 `TabbyShop-windows-x64` artifact。

## 数据和安全

- 第一次使用需要在网页里填入商城 Bearer Token 并启动监控。
- `config.local.json` 和 `monitor.local.json` 会保存在源码目录或 exe 所在目录。备份这两个文件可以保留 Token 和筛选配置；不要分享或提交 `config.local.json`。
- 导入的私钥由 Windows 凭据管理器保存，不写入配置文件。请只使用专门的小额钱包。
- 关闭浏览器页面不会停止服务；要停止 exe，请关闭它的命令行窗口。
- exe 需要联网访问商城 API 和 BSC RPC。Windows Defender/防火墙首次询问时，只允许专用网络上的本地访问；服务仅绑定 `127.0.0.1`。
