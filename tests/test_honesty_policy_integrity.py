#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
policy=(ROOT/'policy/PROJECT_EXECUTION_CONTROL_STANDARD_v19_CANDIDATE.md').read_text(encoding='utf-8')
control=json.loads((ROOT/'control/honesty-control.json').read_text(encoding='utf-8'))
required_phrases=[
'Non-bypassable honesty and validation control',
'must not knowingly provide false information',
'must not be labelled `tested`, `validated`, `safe`, `correct`, `ready`',
'REVIEWED_NOT_EXECUTED',
'SIMULATION_ONLY',
'cannot self-certify compliance',
'HONESTY_STOP',
'DELIVERY_BLOCKED_HONESTY_CONTROL',
'A general instruction such as `proceed` never waives this control'
]
missing=[p for p in required_phrases if p not in policy]
assert not missing, f'missing policy clauses: {missing}'
assert control['non_bypassable'] is True
assert control['general_proceed_bypass_allowed'] is False
assert control['failure_state']=='HONESTY_STOP'
assert control['blocked_result']=='DELIVERY_BLOCKED_HONESTY_CONTROL'
assert set(control['allowed_validation_statuses'])=={'EXECUTED_LIVE','EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT','SIMULATION_ONLY','REVIEWED_NOT_EXECUTED','UNVERIFIED'}
print('HONESTY_POLICY_INTEGRITY_PASS')
