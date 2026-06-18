# Hermes Doctor Prescription Library

Use exact matches first. If multiple prescriptions match, show the safest one first.

| ID | Symptoms | Plain diagnosis | Safe prescription | Risk |
|-|-|-|-|-|
| RX-HERMES-001 | `plugin.json`, `.hermes-skill`, `缺少 Hermes plugin`, `manifest missing` | Hermes 插件身份文件缺失，项目不能被 Hermes 正确识别。 | 补充 `.hermes-skill/plugin.json` 和基础字段；写入前展示文件内容。 | L1 |
| RX-HERMES-002 | `invalid json`, `JSONDecodeError`, `plugin.json 不是合法 JSON` | Hermes manifest 格式坏了，不是功能坏了。 | 用 JSON 解析定位错误行，最小修改修复格式。 | L1 |
| RX-HERMES-003 | `agents`, `缺少 agents`, `角色边界不清` | Hermes 诊断、修复、病历角色没有拆开，后续容易乱修。 | 补充 diagnosis/repair/case agent 文档。 | L1 |
| RX-HERMES-004 | `skills`, `缺少 skills`, `子 Skill`, `触发失败` | Hermes 子能力没有按命令拆分，Agent 不知道该用哪个能力。 | 补齐 `skills/<name>/SKILL.md` 并写清触发场景。 | L1 |
| RX-HERMES-005 | `scripts`, `CLI`, `本地执行入口`, `command not found` | 缺少可验证脚本或命令不可用，无法闭环测试。 | 补充本地 CLI；安装依赖前必须确认。 | L1/L2 |
| RX-HERMES-006 | `references`, `PRD`, `测试清单`, `安全策略` | 交付缺少 PRD、药方、安全策略或验收清单。 | 补齐 references，并让 README 写真实状态。 | L1 |
| RX-RUNTIME-001 | `fetch failed`, `Failed to fetch`, `访问不到`, `打开了但取不到`, `timeout`, `web data` | Hermes 网页数据获取链路失败，可能是网络、代理、平台限制或解析链路问题。 | 先区分访问不到和取不到；检查 timeout/代理/最小请求，不绕过登录、验证码、反爬或限流。 | L0/L2 |
| RX-RUNTIME-002 | `playwright`, `chromium`, `browser`, `screenshot`, `vision`, `截图失败` | 浏览器或视觉链路异常。 | 只读检查浏览器依赖和截图日志；安装浏览器依赖或重启前必须确认。 | L2 |
| RX-TOOL-001 | `unknown tool`, `tool not found`, `工具不存在`, `工具调用失败` | Hermes 调用了未注册、未暴露或名称不一致的工具。 | 对照工具注册表和调用名；修配置或代码前展示目标文件和最小 diff。 | L1/L2 |
| RX-DEP-001 | `ModuleNotFoundError`, `No module named`, `找不到模块` | Python 依赖缺失或解释器环境不对。 | 确认解释器和项目环境；安装前展示命令并确认。 | L2 |
| RX-FILE-001 | `No such file`, `ENOENT`, `path not found`, `找不到文件`, `找不到路径` | 命令找不到目标路径。 | 先确认当前目录和绝对路径；创建目录前必须确认。 | L0/L1 |
| RX-AUTH-001 | `401`, `unauthorized`, `invalid token`, `missing_scope` | 登录态、授权或 scope 不可用。 | 重新授权或补最小权限；不要打印 token。 | L2 |
| RX-SAFETY-001 | `cookie`, `token`, `password`, `private key`, `私钥`, `密码`, `client_secret`, `client-secret`, `bearer`, `Bearer`, `api_key`, `api-key`, `apikey`, `jwt`, `JWT`, `authorization`, `Authorization`, `secret`, `access_key`, `session_id`, `csrf_token`, `xsrf_token` | 输入或日志里可能包含敏感信息。 | 立即脱敏；不要写入病历或群聊回显。 | L3 |
| RX-SAFETY-002 | `login required`, `captcha`, `rate limit`, `too many requests`, `登录`, `验证码`, `请求太频繁` | 平台要求登录、验证码或触发限流，不能当作普通程序错误硬修。 | 停止自动重试；提示合规登录或降低频率，不收集 cookie/token，不绕过平台保护。 | L3 |
| RX-REPAIR-001 | `帮我修`, `自愈`, `怎么修`, `需要修复计划` | 用户需要安全修复步骤，而不是立即执行。 | 生成修复计划，包含影响范围、确认要求、验证和回滚。 | L0 |
| RX-REPAIR-002 | `删除`, `覆盖`, `reset --hard`, `rm -rf` | 请求包含破坏性动作。 | 升级 L3，只给人工计划，必须明确批准精确动作。 | L3 |
| RX-CASE-001 | `上次`, `病历`, `历史`, `怎么处理` | 用户在查历史处理记录。 | 调用 case search 返回最近匹配记录。 | L0 |
| RX-FEISHU-001 | `Hermes Doctor 体检`, `看看状态` | 飞书消息可路由到只读体检。 | 使用 route 判断意图，再调用 check。 | L0 |
| RX-FEISHU-002 | `Hermes Doctor 报错了`, `出错了` | 飞书消息可路由到药方匹配。 | 提取冒号后的错误正文，调用 match。 | L0 |
| RX-FEISHU-003 | `Hermes Doctor 帮我修一下`, `自愈` | 飞书消息涉及修复，不能直接执行。 | 调用 plan 生成计划，等待用户确认。 | L2 |
| RX-LOG-001 | `log 太大`, `log 文件`, `日志收集`, `日志量` | 日志文件过大或收集链路异常，可能影响体检与诊断。 | 检查日志大小、轮转策略和收集工具；清理前必须确认。 | L1 |

> **注**: 以下 6 条药方已定义但 v0.1.3 暂未在 CLI 挂载（架构评审 #4 待办），保留供 v0.2+ 启用：
> - `RX-AUTH-001`（登录/授权）— 待授权链路模块
> - `RX-CASE-001`（病历查询）— 与 `case-search` 命令功能重叠
> - `RX-FEISHU-001/002`（飞书路由触发）— 已由 `feishu-route` 子 skill 覆盖
> - `RX-REPAIR-001/002`（修复计划）— 风险等级与 `repair-plan` 一致，无需独立条目

