# EUserv 自动续期

基于 Python + GitHub Actions 的 EUserv 合同检查与续期脚本。

当前策略以安全为优先：

- **FREE 产品**：满足条件时允许自动续期。
- **付费或无法确认类型的产品**：只发送提醒，**不会自动续费**。
- 可额外配置 **合同号白名单**，形成“FREE 产品识别 + 合同号白名单”双重保险。
- 续期成功必须经过 EUserv 后台状态复核，不以 GitHub Actions 绿色状态或接口返回文本作为唯一依据。

## 功能

- 自动登录 EUserv KundenCenter。
- 支持 EUserv Authenticator / TOTP 两步验证。
- 自动读取 Gmail、Google Workspace、Microsoft 365、Zoho 等邮箱中的续期 PIN。
- 自动识别合同、产品名称及续期状态。
- FREE 合同自动续期。
- 付费/未知合同只提醒，不自动提交续期。
- Telegram / Bark 通知。
- Telegram 通知包含合同号、产品名、续期结果、下一次可续期日期和 GitHub Actions 快捷按钮。
- 人工处理提醒自动去重，默认同一合同 **7 天最多提醒一次**。
- PIN、Session ID、Token 等敏感值不会打印到 Actions 日志。
- 多账号并发检查。
- GitHub Actions 定时执行与手动执行。

## 安全规则

自动续期必须先满足：

1. 产品名称能够明确识别为 **FREE**。
2. 如果配置了 `AUTO_RENEW_CONTRACTS`，合同号还必须存在于该白名单中。
3. EUserv 当前确实处于可续期状态。

任何不满足上述条件的合同都不会自动续期。

因此建议配置 `AUTO_RENEW_CONTRACTS`，例如：

```
123456,234567
```

请将合同号列表保存到 GitHub Actions **Secret**，不要写入公开仓库。

## GitHub Actions 部署

### 1. Fork 仓库

Fork 后进入自己的仓库。

### 2. 开启 Actions 写权限

进入：

`Settings → Actions → General → Workflow permissions`

选择：

`Read and write permissions`

保存。

### 3. 配置 Actions Secrets

进入：

`Settings → Secrets and variables → Actions → New repository secret`

推荐配置：

| Secret | 必须 | 说明 |
| --- | :---: | --- |
| `EUSERV_EMAIL` | 是 | EUserv 登录邮箱 |
| `EUSERV_PASSWORD` | 是 | EUserv 登录密码 |
| `EUSERV_TOTP_SECRET` | 视账号而定 | Authenticator 的 Base32 Setup Key，不是当前 6 位验证码 |
| `EMAIL_PASS` | 是 | 接收续期 PIN 邮箱的 IMAP/应用专用密码 |
| `EMAIL_PIN` | 否 | 接收 PIN 的邮箱地址；不填则使用 `EUSERV_EMAIL` |
| `AUTO_RENEW_CONTRACTS` | 推荐 | 允许自动续期的 FREE 合同号，多个用逗号分隔 |
| `TG_BOT_TOKEN` | 否 | Telegram Bot Token |
| `TG_CHAT_ID` | 否 | Telegram Chat ID |
| `BARK_URL` | 否 | Bark 推送地址 |

多账号可以继续使用：

`EUSERV_EMAIL2`、`EUSERV_PASSWORD2`、`EMAIL_PIN2`、`EMAIL_PASS2`

依此类推。

## Gmail 配置

如果 EUserv 续期 PIN 发送到 Gmail：

1. Google 账号开启两步验证。
2. 创建 **应用专用密码**。
3. 将 Gmail 地址配置为 `EUSERV_EMAIL` 或 `EMAIL_PIN`。
4. 将 16 位应用专用密码保存为 `EMAIL_PASS`。

不要把 Google 普通登录密码放到仓库或日志中。

脚本会自动使用：

`imap.gmail.com`

## Authenticator / TOTP

如果 EUserv 登录后提示：

`enter the PIN that is shown in your authenticator app`

需要配置 `EUSERV_TOTP_SECRET`。

这里必须填写绑定验证器时提供的 **Base32 Setup Key**，不能填写手机上不断变化的 6 位动态码。

## Telegram 通知

默认策略：

- FREE 合同续期成功：通知。
- FREE 合同续期失败：通知。
- 登录/合同读取异常：通知。
- 付费合同进入可处理状态：提醒，但不续费。
- FREE 合同未命中白名单：提醒，但不续期。
- 所有合同均无需处理：不发送 Telegram，避免刷屏。

人工处理提醒默认 **7 天最多一次**。可以通过仓库变量：

`PAID_REMINDER_INTERVAL_DAYS`

修改提醒间隔。

## GitHub Actions 运行时间

默认：

```yaml
cron: '0 12 * * *'
```

即每天 UTC 12:00 自动检查。

也可以在：

`Actions → EUserv Daily Renew → Run workflow`

随时手动执行。

## 如何判断续期真正成功

脚本不会仅根据以下情况判定成功：

- GitHub Actions 显示绿色。
- EUserv HTTP 请求返回 200。
- 页面包含类似 “success” 的文字。

续期提交后，脚本会重新读取 EUserv 后台。

只有出现以下可验证变化之一才算成功：

- 原来的手动续期 / 停用警告消失；
- 停用日期向后延长；
- 合同重新进入“暂不可续期”状态，并显示新的下一次可续期日期。

## 通知去重

付费或需要人工处理的合同进入提醒状态后，会写入：

`notification_state.json`

GitHub Actions 会保存该文件，因此同一个合同不会每天重复轰炸 Telegram。

默认间隔为 7 天。

## 日志安全

脚本不会在 Actions 日志中显示：

- 邮箱 PIN
- Authenticator TOTP
- EUserv Session ID
- 续期 Token
- GitHub Secrets

如果调试代码，请不要自行增加打印这些值的日志。

## 本地 / VPS 运行

安装依赖：

```bash
pip install -r requirements.txt
```

然后准备环境变量并运行：

```bash
python euser_renew.py
```

VPS 部署也可参考 [README_VPS.md](./README_VPS.md)。

## 维护建议

EUserv 控制面板 HTML 和安全验证流程可能调整。出现异常时应优先检查 GitHub Actions 日志中的：

- 登录验证阶段
- 合同页面解析
- PIN 获取
- Token 获取
- 最终后台状态复核

不要通过取消安全校验或“接口没报错就算成功”的方式绕过验证。
