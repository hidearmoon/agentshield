# AgentGuard への貢献

AgentGuard への貢献にご関心をお寄せいただきありがとうございます。本ドキュメントでは、貢献に関するガイドラインと手順を説明します。

## 行動規範

敬意を持って接してください。建設的であってください。善意を前提としてください。私たちはセキュリティインフラを構築しています — スピードよりも正確さと明確さが重要です。

## はじめに

### 前提条件

- Python 3.12 以上
- [uv](https://docs.astral.sh/uv/)（Python パッケージマネージャー）
- Node.js 20 以上（コンソールフロントエンド用）
- Docker および Docker Compose（統合テスト用）

### 開発環境のセットアップ

```bash
# リポジトリをクローン
git clone https://github.com/hidearmoon/agentguard.git
cd agentguard

# 依存サービスを起動
make dev

# コアエンジンの依存関係をインストール
cd packages/core && uv sync --extra dev

# SDK の依存関係をインストール
cd packages/sdk-python && uv sync --extra dev

# フロントエンドの依存関係をインストール
cd packages/console/frontend && npm install
```

### テストの実行

```bash
# 主要テストスイートを実行（ユニット + セキュリティ）
make test

# 個別のテストスイートを実行
make test-unit          # 218 ユニットテスト
make test-security      # 92 セキュリティテスト
make test-integration   # 統合テスト（Docker サービスが必要）
make test-perf          # パフォーマンスベンチマーク

# カバレッジ付きで実行
make test-coverage
```

## 貢献の方法

### 問題の報告

- **セキュリティ脆弱性**: セキュリティに関する問題は非公開で報告してください。公開 Issue を作成しないでください。メンテナーに直接メールしてください。
- **バグ**: 最小限の再現手順、Python のバージョン、および `uv pip list` の出力を添えて Issue を作成してください。
- **機能リクエスト**: 解決策だけでなく、ユースケースを説明する Issue を作成してください。

### プルリクエスト

1. リポジトリをフォークし、`main` ブランチからブランチを作成してください。
2. コードを追加した場合はテストも追加してください。セキュリティ関連の変更には `packages/core/tests/security/` にセキュリティテストが必要です。
3. すべてのテストが通ることを確認してください: `make test`
4. リンターチェックが通ることを確認してください: `make lint`
5. **何を** 変更したかだけでなく、**なぜ** 変更したかを明確に説明する PR の説明文を書いてください。

### コミットメッセージ

Conventional Commits を使用してください:

```
feat(core): ルール DSL に時間ベースの条件を追加
fix(sdk-python): guard デコレータでの接続タイムアウトを処理
test(security): base64 ペイロードのエンコーディングバイパステストを追加
docs: トラストモデルのドキュメントを更新
```

## プロジェクト構成

| パッケージ | 説明 | 言語 |
|---------|-------------|----------|
| `packages/core` | セキュリティエンジン — 頭脳 | Python (FastAPI) |
| `packages/proxy` | トランスペアレントサイドカープロキシ | Python |
| `packages/console` | 管理 UI | React（フロントエンド）+ Python（バックエンド） |
| `packages/sdk-python` | Python SDK | Python |
| `packages/sdk-typescript` | TypeScript SDK | TypeScript |
| `packages/sdk-go` | Go SDK | Go |

## コードスタイル

- **Python**: [Ruff](https://docs.astral.sh/ruff/) により厳格な設定で強制されます。コミット前に `make format` を実行してください。
- **TypeScript**: Prettier および TypeScript の strict モードで強制されます。
- **Go**: 標準の `gofmt` を使用します。

主要な規約:
- すべてのパブリック関数に型アノテーションを付ける（Python）
- 説明コメントなしに `# type: ignore` を使用しない
- セキュリティに関わるコードには明示的なテストカバレッジが必要
- YAML DSL のカスタムルールには `reason` フィールドを含める

## セキュリティテストの作成

セキュリティテストは `packages/core/tests/security/` にあります。新しい検出ルールの追加やセキュリティパイプラインの変更を行う場合は、対応するテストを追加する必要があります。

テストカテゴリ:
- `test_attack_samples.py` — 実際の攻撃ペイロードに対するテスト（JSONL 形式）
- `test_bypass_attempts.py` — 既知のバイパス手法に対するテスト
- `test_encoding_bypass.py` — Unicode、base64、およびその他のエンコーディング攻撃
- `test_header_forgery.py` — ヘッダーを介した信頼レベルの偽装
- `test_trust_escalation.py` — 権限昇格の試行
- `test_combined_attacks.py` — 複数ベクトルの攻撃チェーン
- `test_fuzz.py` — ランダム入力によるファジング

攻撃サンプルは `tests/security/samples/` に JSONL ファイルとして保存されます。各行には以下が含まれます:
```json
{"input": "攻撃ペイロード", "expected": "BLOCK", "category": "direct_injection"}
```

## 新しい組み込みルールの追加

1. `packages/core/src/agentguard_core/engine/intent/rule_engine.py` にルールロジックを追加する
2. `configs/builtin_rules.yaml` に登録する
3. `packages/core/tests/unit/test_rule_engine.py` にユニットテストを追加する
4. ルールで検出すべき攻撃サンプルを含むセキュリティテストを追加する
5. 該当する場合はドキュメント内のルール数を更新する

## フレームワーク統合の追加

1. `packages/sdk-python/src/agentguard/integrations/your_framework.py` を作成する
2. `packages/sdk-python/src/agentguard/integrations/__init__.py` からエクスポートする
3. `packages/sdk-python/tests/test_integrations.py` にテストを追加する
4. `examples/` にサンプルを追加する
5. SDK の README を更新する

## ライセンス

AgentGuard に貢献することにより、あなたの貢献物が Apache License 2.0 の下でライセンスされることに同意したものとみなされます。
