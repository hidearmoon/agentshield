# AgentGuard에 기여하기

AgentGuard에 관심을 가져주셔서 감사합니다. 이 문서는 기여를 위한 가이드라인과 지침을 제공합니다.

## 행동 강령 (Code of Conduct)

서로 존중해 주세요. 건설적인 태도를 취하세요. 좋은 의도를 가정하세요. 우리는 보안 인프라를 구축하고 있습니다 — 속도보다 정확성과 명확성이 더 중요합니다.

## 시작하기

### 사전 요구 사항

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (Python 패키지 매니저)
- Node.js 20+ (콘솔 프론트엔드용)
- Docker & Docker Compose (통합 테스트용)

### 개발 환경 설정

```bash
# 저장소 클론
git clone https://github.com/hidearmoon/agentguard.git
cd agentguard

# 종속성 시작
make dev

# 코어 엔진 종속성 설치
cd packages/core && uv sync --extra dev

# SDK 종속성 설치
cd packages/sdk-python && uv sync --extra dev

# 프론트엔드 종속성 설치
cd packages/console/frontend && npm install
```

### 테스트 실행

```bash
# 기본 테스트 스위트 실행 (단위 + 보안)
make test

# 개별 테스트 스위트 실행
make test-unit          # 218개 단위 테스트
make test-security      # 92개 보안 테스트
make test-integration   # 통합 테스트 (Docker 서비스 필요)
make test-perf          # 성능 벤치마크

# 커버리지와 함께 실행
make test-coverage
```

## 기여 방법

### 이슈 보고

- **보안 취약점**: 보안 이슈는 비공개로 보고해 주세요. 공개 이슈를 열지 마세요. 유지 관리자에게 직접 이메일을 보내주세요.
- **버그**: 최소한의 재현 케이스, Python 버전, 그리고 `uv pip list`의 출력을 포함하여 이슈를 열어주세요.
- **기능 요청**: 솔루션만 설명하지 말고 사용 사례(use case)를 설명하는 이슈를 열어주세요.

### 풀 리퀘스트 (Pull Requests)

1. 저장소를 포크(fork)하고 `main`에서 브랜치를 생성합니다.
2. 코드를 추가했다면 테스트도 추가하세요. 보안 관련 변경 사항은 `packages/core/tests/security/`에 보안 테스트가 필요합니다.
3. 모든 테스트가 통과하는지 확인합니다: `make test`
4. 코드가 린팅을 통과하는지 확인합니다: `make lint`
5. 단순한 **내용(what)**이 아니라 **이유(why)**를 설명하는 명확한 PR 설명을 작성하세요.

### 커밋 메시지

Conventional Commits 형식을 사용하세요:

```
feat(core): add time-based condition to rule DSL
fix(sdk-python): handle connection timeout in guard decorator
test(security): add encoding bypass test for base64 payloads
docs: update trust model documentation
```

## 프로젝트 구조

| 패키지 | 설명 | 언어 |
|---------|-------------|----------|
| `packages/core` | 보안 엔진 — 두뇌 역할 | Python (FastAPI) |
| `packages/proxy` | 투명한 사이드카(sidecar) 프록시 | Python |
| `packages/console` | 관리 UI | React (프론트엔드) + Python (백엔드) |
| `packages/sdk-python` | Python SDK | Python |
| `packages/sdk-typescript` | TypeScript SDK | TypeScript |
| `packages/sdk-go` | Go SDK | Go |

## 코드 스타일

- **Python**: 엄격한 설정으로 [Ruff](https://docs.astral.sh/ruff/)에 의해 강제됩니다. 커밋하기 전에 `make format`을 실행하세요.
- **TypeScript**: Prettier 및 TypeScript strict 모드에 의해 강제됩니다.
- **Go**: 표준 `gofmt`.

주요 규칙:
- 모든 공개 함수에 타입 어노테이션 작성 (Python)
- 설명 주석 없이 `# type: ignore` 사용 금지
- 보안에 민감한 코드는 명시적인 테스트 커버리지를 가져야 함
- YAML DSL의 사용자 정의 규칙에는 `reason` 필드가 포함되어야 함

## 보안 테스트 작성

보안 테스트는 `packages/core/tests/security/`에 있습니다. 새로운 탐지 규칙을 추가하거나 보안 파이프라인을 수정할 때는 해당하는 테스트를 반드시 추가해야 합니다.

테스트 카테고리:
- `test_attack_samples.py` — 실제 공격 페이로드에 대한 테스트 (JSONL 형식)
- `test_bypass_attempts.py` — 알려진 우회 기법에 대한 테스트
- `test_encoding_bypass.py` — 유니코드, base64 및 기타 인코딩 공격
- `test_header_forgery.py` — 헤더를 통한 신뢰 수준 스푸핑
- `test_trust_escalation.py` — 권한 상승 시도
- `test_combined_attacks.py` — 다중 벡터 공격 체인
- `test_fuzz.py` — 무작위 입력을 사용한 퍼징

공격 샘플은 JSONL 파일로 `tests/security/samples/`에 저장됩니다. 각 줄의 구성:
```json
{"input": "the attack payload", "expected": "BLOCK", "category": "direct_injection"}
```

## 새로운 내장 규칙 추가

1. `packages/core/src/agentguard_core/engine/intent/rule_engine.py`에 규칙 로직 추가
2. `configs/builtin_rules.yaml`에 등록
3. `packages/core/tests/unit/test_rule_engine.py`에 단위 테스트 추가
4. 규칙이 잡아내야 하는 공격 샘플을 사용하여 보안 테스트 추가
5. 해당하는 경우 문서의 규칙 개수 업데이트

## 프레임워크 통합 추가

1. `packages/sdk-python/src/agentguard/integrations/your_framework.py` 생성
2. `packages/sdk-python/src/agentguard/integrations/__init__.py`에서 내보내기(export)
3. `packages/sdk-python/tests/test_integrations.py`에 테스트 추가
4. `examples/`에 예제 추가
5. SDK README 업데이트

## 라이선스

AgentGuard에 기여함으로써, 귀하의 기여가 Apache License 2.0에 따라 라이선스됨에 동의하는 것으로 간주됩니다.
