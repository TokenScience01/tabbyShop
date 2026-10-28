# Tabby 游戏与商城桌面工具

基于 Python 和 PySide6 的多账号桌面客户端，整合游戏控制台、小地图、任务编排和本地商城监控。游戏连接使用服务器下发的会话、位置修订和攻击票据，结果由游戏服务器校验。

## 当前功能

- 多账号后台连接、控制台切换和批量任务；未创建角色的账号单独标记，其他账号继续上线。
- 战士、守卫、弓手角色创建；按职业处理攻击距离、命中帧和装备限制。
- 怪物任务、追击、整图巡逻、小地图及地图间移动。
- 秘宝之地通行、到期回城、体力恢复药水、木钓竿传送和手动装备交付任务。
- 本地商城筛选、持续监控、账号配置与交易操作。
- 钱包主密码加密保存、GitHub Release 更新检查和 UI 卡顿诊断。

## 启动

建议使用 Python 3.11 或更新版本。Windows PowerShell：

```powershell
git clone https://github.com/TokenScience01/tabbyShop.git
cd tabbyShop
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-desktop.txt
.\.venv\Scripts\python.exe desktop.py
```

已有环境只需安装依赖后运行 `python desktop.py`。在账号管理页导入自己的钱包并解锁；账号不会在启动程序时自动上线。批量上线发现未创建角色的账号后，可点击该账号的“创建角色”选择职业和名称。

游戏控制台左侧的“秘宝与钓竿”提供道具操作。装备交付需要在任务页选择已接取的任务，再手动选满所需装备并确认消耗。地图切换与道具操作可能暂停当前自动任务，抵达后可手动重新启动方案。

独立运行商城浏览器版时，执行 `python server.py`，依赖和打包方式见 [Windows 使用说明](README-WINDOWS.md)。

## 本地数据

- 桌面钱包保存于操作系统用户数据目录的加密保险库，主密码仅保留在本次运行的内存中。
- 独立商城的 `config.local.json` 可能包含会话 Token；`monitor.local.json` 包含本机监控与购买配置。这些文件及其备份均不应上传。
- `.env`、钱包分片、保险库、日志、抓包文件、截图与 `exports/` 已加入忽略规则。
- 道具使用、装备交付或交易提交会影响线上账号，请在对应界面核对数量与选中项。离线测试不会使用真实钱包。

更多边界和审计结果见 [GitHub 公开前检查](PUBLICATION-AUDIT.md)。当前未添加统一 LICENSE；代码的发布许可及随仓库分发的游戏素材范围仍待仓库所有者明确，素材来源记录不等于许可声明。

## 运行检查

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe tools/benchmark_navigation_ui.py
```

测试覆盖账号登录与创建角色、战斗状态、道具确认、装备交付、商城监控、WebSocket 数据帧、更新器和地图碰撞。寻路负载脚本模拟 9 个账号同时请求路径，并检查 Qt 事件循环响应。

寻路由所有账号共用最多两个后台进程；网络发送与钱包加密也在后台执行。隐藏的游戏面板跳过快照重绘，降低多账号操作时的界面负担。

## 项目结构与文档

| 路径 | 内容 |
| --- | --- |
| `desktop.py` | 桌面入口、账号管理和任务编排 |
| `game_client/` | 游戏协议、导航、角色与界面 |
| `server.py`、`index.html` | 本地商城服务和网页 |
| `tests/` | 离线回归测试 |
| `tools/` | 数据同步、IDE 配置与性能检查工具 |
| [桌面详细说明](README-DESKTOP.md) | 登录、操作与 Windows 打包 |
| [2026-10-28 更新记录](UPDATE-20261028.md) | 新角色与新玩法的协议来源及支持范围 |
| [公开前审计](PUBLICATION-AUDIT.md) | 敏感信息、忽略规则与 Git 引用检查 |

官网公开发布包和恢复工程保留在本机 `exports/`，不随源码提交。需要重新适配公开版本时，可使用 `tools/export_live_site.py` 下载和校验资源；`tools/sync_public_release.py` 需要已经恢复的 Godot 工程，不能直接把 PCK 当作输入。
