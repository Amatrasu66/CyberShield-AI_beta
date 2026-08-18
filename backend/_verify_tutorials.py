from app.services import sql_lab_service as lab
from app.services import sql_service as demo

r = lab.SQLLabService.run_scenario('login', "' OR '1'='1")
print('SCENARIO', r['scenario'], '| PAYLOAD', r['input'])
print('VULN_QUERY', r['vulnerable_query'])
print('VULN_ROWS', r['vulnerable_result']['rows'], r['vulnerable_result']['columns'])
print('VULN_DATA', r['vulnerable_result']['data'])
print('SAFE_ROWS', r['safe_result']['rows'], '| STATUS', r['safe_result']['execution_status'])
print('SANDBOX', r['sandbox'])
print('WHY_SAFE', r['explanation']['why_safe'][:80])

d = demo.SQLPlaygroundService.run_demo("' OR '1'='1")
print('DEMO_PATTERNS', d['detected_patterns'], '| VULNERABLE', d['vulnerable_pattern_detected'])
print('DEMO_UNSAFE', d['unsafe_query'])

c = lab.SQLLabService.run_scenario('union', "' UNION SELECT username, role FROM users --")
print('UNION_VULN_ROWS', c['vulnerable_result']['rows'], c['vulnerable_result']['data'])
print('UNION_SAFE_ROWS', c['safe_result']['rows'])

b = lab.SQLLabService.run_scenario('boolean', "' AND 1=1 --")
print('BOOL_VULN_ROWS', b['vulnerable_result']['rows'], '| SAFE', b['safe_result']['rows'])
print('BOOL_SAFE_DATA', b['safe_result']['data'])