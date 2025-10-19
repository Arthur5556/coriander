简体中文 | [English](README.md)

# CVE 监控器

一个近实时的 CVE 监控工具，基于 GitHub Actions 每 5 分钟运行一次。从 cve_targets.txt 读取关键词，与最新 CVE 进行匹配；如已配置 SMTP，则发送邮件告警；若未配置邮件，则将匹配结果写入仓库的 cve_reports/ 目录。

## 功能特性
- GitHub Actions 定时任务：每 5 分钟一次（cron: */5 * * * *）
- 使用 CIRCL CVE 源，结合 10 分钟滑动时间窗，保证新鲜度并容忍调度偏差
- 基于 cve_targets.txt 的关键词匹配（不区分大小写）
- 通过 SMTP 发送邮件提醒（需要配置 EMAIL_* Secrets）
- 文件输出兜底：当未配置或发送邮件失败时，将结果写入 cve_reports/（包含 latest.json、按时间戳命名的 *_matches.json 快照，以及 latest.md 摘要）

## 仓库结构
- scripts/cve_monitor.py — 核心监控脚本
- .github/workflows/cve-monitor.yml — GitHub Actions 工作流（每 5 分钟运行一次，同时支持手动触发）
- cve_targets.txt — 关键词列表（每行一个；以 # 开头的行为注释）
- cve_reports/ — 当采用文件输出时写入此目录（运行时自动创建）

## 配置步骤
1) 编辑 cve_targets.txt
- 每行一个关键词
- 以 # 开头的行会被忽略

2) 配置 GitHub Secrets（用于邮件告警；如果仅用文件输出可忽略）
- EMAIL_HOST：SMTP 服务器主机名
- EMAIL_PORT：SMTP 端口（例如 587 表示 STARTTLS，465 表示 SSL）
- EMAIL_USER：SMTP 用户名
- EMAIL_PASS：SMTP 密码或应用专用密码
- EMAIL_FROM：发件人地址（如 cve-bot@example.com）
- EMAIL_TO：收件人列表（用逗号或分号分隔）
- 可选：NVD_API_KEY（预留，当前脚本未使用）

## 本地运行
环境要求：建议 Python 3.11+（工作流使用 3.11），以及 requests 包。

示例步骤：

```
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install requests

# 可选（本地需要发邮件时）：
export EMAIL_HOST="smtp.example.com"
export EMAIL_PORT="587"
export EMAIL_USER="username"
export EMAIL_PASS="password_or_app_password"
export EMAIL_FROM="cve-bot@example.com"
export EMAIL_TO="alice@example.com,bob@example.com"

# 可选（预留，当前未使用）：
export NVD_API_KEY="..."

python scripts/cve_monitor.py
```

本地运行行为：
- 如果已完整配置邮件变量，则发送邮件汇总
- 否则将写入 cve_reports/：latest.json（原始匹配项）、按时间戳命名的 *_matches.json 快照，以及 latest.md（便于快速查看的文本摘要）

## GitHub Actions
- 调度：*/5 * * * *（每 5 分钟）
- 支持手动触发：workflow_dispatch
- 权限：contents: write（用于将文件输出提交到 cve_reports/）
- 如有变化，工作流会自动提交并推送 cve_reports/ 下的更新

## 配置细节
- 匹配规则：对每个关键词，在 CVE ID 与摘要/描述中进行不区分大小写的子串匹配
- 时间窗：使用 10 分钟（UTC）滑动窗口，以容忍调度偏差；由于任务每 5 分钟运行一次，跨运行可能出现重复；同一次运行内会按 CVE ID 去重
- 邮件发送：仅在所有 EMAIL_* 变量均设置时发送；收件人支持用逗号或分号分隔；未设置端口时默认 587
- 文件输出：
  - cve_reports/latest.json — 本次运行中符合时间窗且匹配关键词的 CIRCL 原始条目
  - cve_reports/YYYYMMDD_HHMM_matches.json — 本次运行匹配到的 CVE 摘要信息
  - cve_reports/latest.md — 人类可读的摘要文本

## 故障排查
- 速率限制或 API 异常：
  - 脚本会尝试不同抓取规模（200 → 100 → 50）提高成功率；若 CIRCL 不可用或限流，可能无结果并在日志中给出原因
- 没有结果：
  - 确认 cve_targets.txt 中已填写关键词且足够相关
  - 注意 10 分钟时间窗；超出窗口的 CVE 会被忽略
  - 查看 Actions 日志，确认抓取与匹配数量
- SMTP 问题：
  - 校验 EMAIL_* 设置是否正确；检查端口与 TLS/SSL（587 vs 465）
  - 留意类似 “Email not fully configured; missing: ...” 的日志或 SMTP 错误
  - 确保 EMAIL_TO 使用逗号或分号分隔，地址有效

## 许可证
暂定（TBD）。后续可能采用 MIT 许可。

切换到英文版本？请查看 README.md。
