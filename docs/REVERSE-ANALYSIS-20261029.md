# 2026-10-29 官网客户端逆向与兼容性分析

## 来源与恢复结果

- 公开来源：https://game.tabby.meme/ ，本次下载目录 `exports/game.tabby.meme-20261029-220623/`。
- HTTP Last-Modified：2026-10-29 13:28:20 UTC，即台北时间 21:28:20。
- 新 PCK：227,328,088 字节；SHA-256：`755a1d51dc8ab1567e054d0d75bb17c449162635decb518e9d711475d4170be1`。
- Godot 4.7.2；4694 个包内文件全部通过 MD5 校验。两次独立下载的 PCK SHA-256 一致。
- GDRE 恢复 162 个脚本，脚本失败 0；2095 个导入资源全部转换，22 个标记为有损转换，不应视为原工程逐字还原。
- 对比基准：`exports/game.tabby.meme-20261028-073822/godot-project/`。脚本新增 9、移除 8、修改 23；大量贴图改路径，因此包体缩小不代表玩法减少。
- 逐行差异：导出目录下 `script-changes.diff`；包内差异：`package-comparison.json`；原始校验数据：`archive-manifest.json`、`pck-index.json`。

本次仅下载公开客户端、静态分析和保存文档；没有登录钱包、发送游戏操作、兑换、付款或修改自动化代码。客户端恢复无法取得服务器实现；掉率、真实发奖及线上接口可用性仍需服务端证据。

## 玩法与协议变化

### 地图扩展

`scripts/main.gd` 增加三个场景与入口，邻接关系为：

| 地图 | 中文 | 从哪里进入 | 原地图入口矩形 x,y,w,h | 新地图返回矩形 |
| --- | --- | --- | --- | --- |
| 8 Blackstone Cavern | 黑石洞窟 | 6 南部森林 | 1312,1824,128,128 | 3168,6176,128,128 |
| 9 Lost Oasis | 失落绿洲 | 4 西部荒野 | 5024,-96,128,128 | 3168,6176,128,128 |
| 10 Frozen Cavern | 冰封洞穴 | 2 北部雪地 | 32,4640,128,128 | 3168,6176,128,128 |

地图 1 展示名称改成 Vylo Town / 维洛镇。ID 没变，名称变化不应触发路由或账号数据迁移。

必须读取新场景的地块、障碍和坐标变换后才能加入导航；只扩充地图枚举不足以保证可行走路径。

### 钓鱼已成为有消耗的完整流程

发送入口仍为 `useFishingRod`，携带背包真实 `playerItemId`。新版说明明确：消耗 1 根鱼竿，钓鱼 3 秒，战斗中不可使用。

`scripts/pvp_client.gd` 新增：

- `fishing_started`：使用 `durationMs`（默认 3000）；停止移动、关闭自动战斗，并刷新背包。
- `fishing_result`：读取 `outcome`，显示结果并刷新背包。枚举包括 `EXPERIENCE`、`FISHPOND`、`PURPLE`、`OTHER`、`STAMINA_POTION`、`BOSS_ENTRY_TICKET`、`TREASURE_STONE`、`TOWN_STONE`、`EMPTY`。
- 经验结果读取 `experience`；客户端默认展示值 2500，不能由此推断服务器固定奖励。
- `fishing_rod_failed`：结束进度；死亡、断线、战斗等条件需要服务器确认。

因此收到位置 `welcome` 只能确认位置，不能当作钓鱼结束；开始到结果期间应持续锁定重复使用和冲突动作。网络超时后先核对库存与状态，不能盲目重发消耗请求。

### Boss 地图通行

新增 `scripts/ui/boss_access_button.gd`，通过 `bossExpiresAt - serverTime` 计算剩余时间；有效时显示重新进入入口，发送 `enterBossMap`。地图仍为 5 废弃遗迹。

新版说明：一张 Boss 凭证开启 1 小时资格，有效期内重入不再消耗凭证。`travel_result` 若带 `serverTime` 也会刷新通行状态。通行时间和秘宝资格必须分别保存，不能复用同一到期变量。

### Boss 拍卖支付入口开启

`scripts/main.gd` 的 `BOSS_AUCTIONS_ENABLED` 从 false 改成 true。`scripts/ui/boss_auctions.gd`：

- 通过带 Bearer 的 `GET /boss-auctions` 拉取列表，支持 `before` 游标。
- 购买按钮要求 `eligible=true`、有 `productId`、`state=OPEN`，并且是 Web 构建。
- 通过钱包和商城桥 `VyloBossShop.buy(productId)` 完成订单支付流程，不是简单发送 WebSocket 拍卖动作。
- 界面说明付款占位 5 分钟，迟付需要审核；付款状态包含 `wallet_confirm`、`confirming`、`review`、`payment_uncertain`、`cancelled`。
- 原有展示规则仍为掉落 30 分钟后开始，10,000 TABBY 起价，每分钟降 500、最低 100；底价持续 2 分钟，项目费 10%，参与者按伤害分配其余 90%。这是客户端规则说明，不能替代服务端订单报价。

当前桌面若要支持，应先做只读列表、资格与报价展示；支付沿用经过验证的订单状态机和人工确认，不能将购买混入刷怪循环。

### 奖励通知与兑换

- 新 `boss_token_reward` 带 `rewardKey`、`monsterKey`、`amount`、`expiresAt`。官网按 rewardKey 去重，保留最多 256 条，并忽略过期通知；通知本身不证明链上到账。
- 新增 FishPond NFT 道具 `FISHPOND_NFT` 和兑换界面。
- `POST /equipment/fishpond/redeem`，JSON 为 `{playerItemId, confirmed:true}`，Bearer 认证。公开界面提示提交成功后道具消失、不可再出售，兑换至绑定钱包，预计 3 个工作日。该期限是界面文案，不是本次验证结果。
- 增加 MARS 等道具说明与图标；不能根据兑换宣传文案推定实际价格或保证收益。

### Boss 战斗与复活

- 新增逆蝶 butterfly、Marschain、巨魔 troll 的贴图或技能表现。巨魔根据 `fireballAt` 和专用动画恢复尾段对齐攻击，逆蝶使用辐射范围效果；范围仍取服务端 `fireballX/Y/Radius`。
- 单纯新增技能表现不能推出服务器伤害公式、冷却或掉率。自动战斗若要躲技能，必须明确处理预警时间和范围，不能只追着目标打。
- 复活函数从固定切到地图 1 改为接受 `respawn_map`，并由 `snapshot(action=respawn).position.map` 传入。客户端不得再假设复活必回城。
- 没发现本次改动增加可创建职业；当前职业分支仍为 WARRIOR / GUARD / ARCHER。主要新增的是地图、Boss 和玩法。

## 当前 Python 客户端的适配缺口

| 优先级 | 本地位置 | 已确认差异 | 建议 |
| --- | --- | --- | --- |
| 高 | `game_client/wss_tester.py` 的活动卡片 | 钓竿仍显示“不消耗钓竿” | 立即修正文案并明确消耗 |
| 高 | `accept_packet` / `accept_activity_packet` | 未处理 fishing_started / fishing_result；welcome 会清除钓竿待处理状态 | 分开位置确认和钓鱼生命周期；结果刷新库存；避免重复消耗 |
| 高 | MAP_NAMES / MAP_ROUTES / 导航数据 | 仅地图 1–7；缺少 8–10 及邻接边 | 一起补名称、入口、场景碰撞、任务/批量路线和小地图 |
| 高 | `accept_activity_resources` | 只跟踪秘宝有效期，未跟踪 bossExpiresAt | 分别维护 Boss 通行期限，重入先看服务器资格 |
| 中 | 怪物名称与战斗展示 | 新 Boss 命名和技能预警未适配 | 补目录映射与预警状态；先验证再扩展躲避策略 |
| 中 | 服务端事件处理 | 未见 boss_token_reward 专门分支 | 去重、到期处理和展示；不作为本地直接加余额依据 |
| 中 | 背包功能 | 没有 FishPond 兑换流程 | 独立手动入口，提交确认和请求幂等/超时核对 |
| 中 | 功能文档 | 旧文档称拍卖关闭、钓竿仅传送 | 按本次公开客户端更新，并区分官网支持与桌面已支持 |

本地复活已有读取权威位置的逻辑，不能直接断言存在固定回城错误；需要用地图 8–10 的 respawn 回包测试地图识别、复活后路线和旧计划清理。

## 性能与状态冲突注意点

官网 `minimap_navigation.gd` 把主城网格细分为 4 倍，节点上限随面积约增至 16 倍，并增加终点邻域搜索。不要把官网的同步建图循环直接搬到 PySide UI 线程。现有独立导航进程应继续承担新增地图解析后的路径计算，地图静态数据只加载和索引一次。

最需要回归的组合：钓鱼中启动批量方案；钓鱼中切图/掉线；旧 welcome 晚到；Boss 通行到期后自动回图；新地图死亡复活；任务换图与手动特殊道具同时触发。所有动作应共享明确的活动互斥状态和请求代次，按权威回包结束，避免多个定时器互相覆盖。

本报告标注的是静态分析发现与适配建议，没有对线上伤害、奖励或支付执行验证。
