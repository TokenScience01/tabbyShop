# Tabby 游戏与商城整合版

以此目录为整合项目，`desktop.py` 是统一入口。`game_client/` 包含游戏控制台、小地图、导航数据与项目素材；`server.py` / `index.html` 保留商城后端和网页。原 wssDemo 目录保留，但整合版后续修改应在这里进行。

## 启动

```sh
python -m pip install -r requirements-desktop.txt
python desktop.py
```

本机现有环境可用：

```sh
/opt/anaconda3/envs/CodexCtl/bin/python desktop.py
```

右上角“账号连接”可选择 Token 登录或 BSC 私钥签名登录。签名登录依次调用 `/membership/challenge`、`/membership/verify` 和 `/membership/enter`。Token 仅在内存中同步，游戏与商城共用；私钥只在本机签名，不会发送给服务器或保存到磁盘。可在账号弹窗连接或断开游戏，在顶部标签切换游戏与商城。商城在首次进入时启动内嵌网页及仅监听 127.0.0.1 的随机端口，不需要单独运行 server.py，也不会自动打开外部浏览器。

账号弹窗中的“记住钱包私钥”默认关闭；启用后仅使用系统钥匙串/凭据管理器保存，取消勾选会删除已保存项。开启“断线后自动重连”时，非手动断开会按退避间隔尝试重连，最多连续尝试 8 次；同时启用私钥记忆后，可在重连时自动签署新的登录挑战。应用不会在启动时自动登录。

整合版 Token 仅在内存中同步，不读取或写入原商城 config.local.json。商城的监控、购买参数仍使用原 monitor.local.json；每次启动整合版都会将监控、自动购买保持关闭，需用户在商城中手动启用。窗口关闭会停止后续监控；已经发出的网络请求或链上交易无法由关闭窗口撤回。

商城钱包功能仍使用原 eth-account 和系统 keyring；没有改动私钥存储位置。未加载本地私钥或 Token 到代码和测试资料中。

## Windows 打包

运行 `build-desktop-windows.bat`。产物为 `dist/TabbyDesktop/`，运行其中的 TabbyDesktop.exe；发布时需带上整个目录（含 Qt WebEngine 运行资源）。原 `build-windows.bat`、CI 和 server.py 的浏览器版入口仍保留。

## 验证

```sh
python -m unittest discover -s tests -v
```
