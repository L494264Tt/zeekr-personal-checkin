# Zeekr personal check-in

个人使用的极氪 Z-Green 自动签到工具，Python 3.9+，仅使用标准库。支持 Linux systemd 和 Windows 任务计划器。

功能包括签到状态核验、随机步数上报、阅读任务、每周任务未完成时点赞，以及能量球、极值、碎片和七日奖励的领取与复查。每个自动任务均可在 `protocol.json` 的 `automation` 中配置。

## 私有配置

仓库不提供账号 Token、签名材料、设备标识、服务器连接信息或个人运行记录。`credentials.example.json` 只有占位符，无法直接连接账号。

将示例复制到仓库以外的私有位置，填写自己授权获取的字段：

```json
{
  "authorization": "Bearer YOUR_BUSINESS_JWT",
  "device_id": "YOUR_DEVICE_ID",
  "signing_secret": "YOUR_AUTHORIZED_CLIENT_SIGNING_SECRET"
}
```

签名材料也可以通过 `ZEEKR_SIGNING_SECRET` 环境变量提供；优先读取私有 JSON。缺少签名材料时，程序停止并报告 `SIGNING_SECRET_MISSING`。不要把凭证放入 Git 提交、命令行参数或日志。

`.gitignore` 用于防止常见私有文件误提交。发布前另外运行 `tools/check_publish.py` 检查跟踪文件；它只是辅助检查，不能替代内容审查。

## 手动运行

```bash
python3 -X utf8 zeekr_checkin.py --credentials /path/outside/repo/credentials.json --claim --save-report /path/outside/repo/latest.json
```

`--claim` 执行领取。不带该参数时，主奖励流程仅查询；如果启用了 `carbon_goal_enabled`，减碳流程仍会领取能量球。需要完全禁止领取时，也应关闭该开关。

自动任务配置：

- `enabled=false`：关闭附加任务，保留签到和主奖励流程。
- `steps=null, steps_min=10000, steps_max=20000`：每次运行在包含两端的区间内随机选择整数。若不需要上报，将这三个字段都设为 `null`。填入 `steps` 时优先使用该固定值。
- `read`、`like`：分别控制阅读和点赞。点赞仅在对应每周任务未完成时尝试一次，跳过已经点赞的帖子。
- `carbon_goal_enabled`：启用减碳进度检查和能量领取；默认等待约 60 秒，网络请求耗时另计。

随机步数是提交的模拟值，并非手机健康数据同步。碳减排值由服务端结算；步数接口成功不能保证当天产生 2000g 能量。没有足够可领能量时，结果是 `carbon=pending`，不能据此视为减碳任务已完成。

退出码：0 表示当前核验全部通过；1 表示未确认签到或配置/网络异常；2 表示签到已确认，但其他任务或奖励仍未全部确认。查看 JSON 报告中的 `error`、`automation_errors` 和 `remaining_rewards` 区分原因。

## Linux systemd

提供的服务和定时器每天北京时间 08:10、08:20 运行；第二次同样会执行启用的自动任务。`Persistent=true` 支持恢复后补跑。

先将程序和公开配置安装至 `/opt/zeekr-checkin`，将真实凭证单独存放在 `/etc/zeekr-checkin/credentials.json`：

```bash
id zeekr-checkin >/dev/null 2>&1 || sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin zeekr-checkin
sudo install -d -m 0755 /opt/zeekr-checkin
sudo install -m 0644 zeekr_checkin.py protocol.json /opt/zeekr-checkin/
sudo install -d -o root -g zeekr-checkin -m 0750 /etc/zeekr-checkin
sudo install -o root -g zeekr-checkin -m 0640 /path/to/private/credentials.json /etc/zeekr-checkin/credentials.json
sudo install -m 0644 zeekr-checkin.service zeekr-checkin.timer /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/zeekr-checkin.service /etc/systemd/system/zeekr-checkin.timer
sudo systemctl daemon-reload
sudo systemctl start zeekr-checkin.service
sudo cat /var/lib/zeekr-checkin/latest.json
sudo systemctl enable --now zeekr-checkin.timer
```

服务以专用低权限用户运行。`SuccessExitStatus=2` 允许部分完成的任务正常结束，但不代表所有任务都完成，应检查报告。

```bash
systemctl list-timers --all zeekr-checkin.timer
sudo journalctl -u zeekr-checkin.service -n 50 --no-pager
sudo systemctl disable --now zeekr-checkin.timer
```

## Windows

安装 Python 后，用 PowerShell 执行：

```powershell
.\install-windows-task.ps1 -CredentialsPath 'C:\private\credentials.json'
```

安装器要求北京时间时区；定时任务使用当前用户交互会话，需要电脑开机、已登录且联网。每天 08:10、08:20 和用户登录时运行。已有同名任务时停止安装。

## 离线验证

```bash
python3 -m unittest test_checkin.py -v
python3 tools/check_publish.py
```

离线测试使用虚构账号和测试签名材料，不调用真实账号接口。仓库未配置在线签到的 GitHub Actions，避免将账号凭证放入 CI。

## 实现参考与限制

协议和业务流程参考 `m20104600/zeekr-checkin`，固定提交 `2b6c9ce96486dc400b314d759f93489be76d9fff`。本仓库不附带其完整分发脚本，也不对第三方代码另行授予许可。

接口、任务名和签名规则可能变化。Token 需自行更新，不实现自动登录或续期；部分奖励尚未完成真实场景验证。请按自己的使用范围配置自动任务。
