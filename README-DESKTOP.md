# Tabby 游戏与商城整合版

以此目录为整合项目，`desktop.py` 是统一入口。`game_client/` 包含游戏控制台、小地图、导航数据与项目素材；`server.py` / `index.html` 保留商城后端和网页。原 wssDemo 目录保留，但整合版后续修改应在这里进行。

桌面版品牌图标资源位于 `assets/tabby-logo.png`，Windows 可执行文件使用对应的多尺寸 `assets/tabby-logo.ico`。

## 启动

```sh
python -m pip install -r requirements-desktop.txt
python desktop.py
```

本机现有环境可用：

```sh
/opt/anaconda3/envs/CodexCtl/bin/python desktop.py
```

右上角“账号连接”默认选择 BSC 私钥签名，也可主动切换为 Token 登录。签名登录依次调用 `/membership/challenge`、`/membership/verify` 和 `/membership/enter`。Token 仅在内存中同步，游戏与商城共用；私钥只在本机签名，不会发送给服务器。可在账号弹窗连接或断开游戏，在顶部标签切换游戏与商城。商城在首次进入时启动内嵌网页及仅监听 127.0.0.1 的随机端口，不需要单独运行 server.py，也不会自动打开外部浏览器。

账号连接默认选择 BSC 私钥签名，Token 登录需主动切换；Token 框会拦截常见的 0x 私钥格式，并对 64 位十六进制内容要求确认，避免把私钥作为 Token 同步或发送。

桌面窗口右上角“检查更新”会查询 GitHub 最新 Release。Windows 已打包版本可直接下载并自动替换、重启；源码运行或其他平台会打开 Release 页面。私有仓库通过已登录的 GitHub CLI (`gh auth login`) 或 `GH_TOKEN` 环境变量授权；令牌只用于内存中的 HTTPS 请求，不会保存或写入日志。更新只接受 GitHub HTTPS Release 中的 `TabbyDesktop-windows-x64.zip` 资源。

“记住私钥”会要求设置至少 6 位的独立主密码。私钥使用 PBKDF2 派生密钥和 AES-GCM 加密，密文再用 XOR 随机分成三片存入用户数据目录；读取需要三片齐全和主密码。主密码不会保存，忘记主密码或丢失任一分片后只能重新输入私钥。分片仅降低单个文件泄漏的影响，不能防御已控制本机用户账户的恶意软件。取消勾选会删除本机分片并清理旧版钥匙串条目。开启“断线后自动重连”时，应用运行期间会暂时保留解锁主密码在内存中，以便自动重新签名；手动断开或退出时清除该引用。应用不会在启动时自动登录。

任务面板的“任务有限模式”只允许自动战斗攻击未完成的怪物任务目标；任务完成、没有可接任务或达到每日接取上限后会暂停战斗，不切换到自由刷怪。关闭此选项会恢复自由战斗行为。

整合版 Token 仅在内存中同步，不读取或写入原商城 config.local.json。商城的监控、购买参数仍使用原 monitor.local.json；每次启动整合版都会将监控、自动购买保持关闭，需用户在商城中手动启用。窗口关闭会停止后续监控；已经发出的网络请求或链上交易无法由关闭窗口撤回。

商城钱包功能仍使用原 eth-account 和系统 keyring；没有改动私钥存储位置。未加载本地私钥或 Token 到代码和测试资料中。

## Windows 打包

运行 `build-desktop-windows.bat`。产物为 `dist/TabbyDesktop/`，运行其中的 TabbyDesktop.exe；发布时需带上整个目录（含 Qt WebEngine 运行资源）。创建 GitHub Release 前，需把 `github_updater.py` 的 `APP_VERSION` 更新为对应标签版本。原 `build-windows.bat`、CI 和 server.py 的浏览器版入口仍保留。

## 验证

```sh
python -m unittest discover -s tests -v
```
