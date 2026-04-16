# 为 AgentShield 贡献

感谢你对 AgentShield 项目的关注。本文档提供贡献指南和说明。

## 行为准则

尊重他人，保持建设性，假设善意。我们在构建安全基础设施 —— 精确和清晰比速度更重要。

## 开始之前

### 前置条件

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)（Python 包管理器）
- Node.js 20+（用于控制台前端）
- Docker & Docker Compose（用于集成测试）

### 搭建开发环境

```bash
# 克隆仓库
git clone https://github.com/YOUR_ORG/agentshield.git
cd agentshield

# 启动依赖服务
make dev

# 安装核心引擎依赖
cd packages/core && uv sync --extra dev

# 安装 SDK 依赖
cd packages/sdk-python && uv sync --extra dev

# 安装前端依赖
cd packages/console/frontend && npm install
```

### 运行测试

```bash
# 运行主要测试套件（单元 + 安全）
make test

# 运行各类测试
make test-unit          # 218 个单元测试
make test-security      # 92 个安全测试
make test-integration   # 集成测试（需要 Docker 服务）
make test-perf          # 性能基准测试

# 带覆盖率运行
make test-coverage
```

## 如何贡献

### 报告问题

- **安全漏洞**：请私下报告安全问题。**不要**开公开 issue，请直接联系维护者。
- **Bug**：请提供最小复现案例、Python 版本和 `uv pip list` 输出。
- **功能请求**：描述使用场景，而不仅仅是解决方案。

### Pull Request

1. Fork 仓库并从 `main` 创建分支。
2. 如果添加了代码，请添加测试。安全相关的更改需要在 `packages/core/tests/security/` 中添加安全测试。
3. 确保所有测试通过：`make test`
4. 确保代码通过检查：`make lint`
5. 编写清晰的 PR 描述，解释**为什么**这样做，而不仅仅是**做了什么**。

### 提交信息

使用约定式提交：

```
feat(core): 为规则 DSL 添加基于时间的条件
fix(sdk-python): 处理 guard 装饰器中的连接超时
test(security): 添加 base64 载荷的编码绕过测试
docs: 更新信任模型文档
```

## 项目结构

| 包 | 说明 | 语言 |
|---|------|------|
| `packages/core` | 安全引擎 —— 核心大脑 | Python (FastAPI) |
| `packages/proxy` | 透明 sidecar 代理 | Python |
| `packages/console` | 管理后台 | React（前端）+ Python（后端） |
| `packages/sdk-python` | Python SDK | Python |
| `packages/sdk-typescript` | TypeScript SDK | TypeScript |
| `packages/sdk-go` | Go SDK | Go |

## 代码规范

- **Python**：由 [Ruff](https://docs.astral.sh/ruff/) 严格模式强制执行。提交前运行 `make format`。
- **TypeScript**：由 Prettier 和 TypeScript 严格模式强制执行。
- **Go**：标准 `gofmt`。

关键约定：
- 所有公开函数必须有类型注解（Python）
- 禁止无注释的 `# type: ignore`
- 安全敏感代码必须有明确的测试覆盖
- YAML DSL 自定义规则必须包含 `reason` 字段

## 编写安全测试

安全测试位于 `packages/core/tests/security/`。添加新的检测规则或修改安全管线时，必须添加对应的测试。

测试分类：
- `test_attack_samples.py` — 基于真实攻击载荷的测试（JSONL 格式）
- `test_bypass_attempts.py` — 已知绕过技术的测试
- `test_encoding_bypass.py` — Unicode、base64 等编码攻击
- `test_header_forgery.py` — 通过 Header 伪造信任等级
- `test_trust_escalation.py` — 权限提升尝试
- `test_combined_attacks.py` — 多向量组合攻击链
- `test_fuzz.py` — 随机输入模糊测试

攻击样本存储在 `tests/security/samples/` 中，为 JSONL 格式。每行包含：
```json
{"input": "攻击载荷", "expected": "BLOCK", "category": "direct_injection"}
```

## 添加内置规则

1. 在 `packages/core/src/agentshield_core/engine/intent/rule_engine.py` 中添加规则逻辑
2. 在 `configs/builtin_rules.yaml` 中注册
3. 在 `packages/core/tests/unit/test_rule_engine.py` 中添加单元测试
4. 添加安全测试和该规则应捕获的攻击样本
5. 如适用，更新文档中的规则数量

## 添加框架集成

1. 创建 `packages/sdk-python/src/agentshield/integrations/your_framework.py`
2. 在 `packages/sdk-python/src/agentshield/integrations/__init__.py` 中导出
3. 在 `packages/sdk-python/tests/test_integrations.py` 中添加测试
4. 在 `examples/` 中添加示例
5. 更新 SDK README

## 许可证

向 AgentShield 贡献代码即表示你同意你的贡献将以 Apache License 2.0 许可发布。
