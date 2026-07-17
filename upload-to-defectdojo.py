#!/usr/bin/env python3
import requests, os, sys
from datetime import date

DOJO_URL   = os.environ.get('DOJO_URL', 'http://<DOJO_PRIVATE_IP>:8080') #The IP address must be Dojo Private IP not Public IP
DOJO_TOKEN = os.environ['DOJO_TOKEN']
ENGAGEMENT = os.environ.get('ENGAGEMENT_ID', '1')

# Several scan reports are written inside Application-Code/ because their
# Jenkinsfile stages run in dir("${APP_DIR}"), not the workspace root.
APP_DIR = os.environ.get('APP_DIR', 'Application-Code')

headers = {'Authorization': f'Token {DOJO_TOKEN}'}

def upload(scan_type, file_path):
    if not os.path.exists(file_path):
        print(f'  SKIP {file_path} - not found')
        return
    print(f'  Uploading {scan_type}: {file_path}')
    with open(file_path, 'rb') as f:
        r = requests.post(
            f'{DOJO_URL}/api/v2/import-scan/',
            headers=headers,
            data={
                'scan_type': scan_type,
                'engagement': ENGAGEMENT,
                'scan_date': str(date.today()),
                'active': True,
                'verified': False,
            },
            files={'file': f}
        )
    status = 'OK' if r.status_code == 201 else f'FAIL ({r.status_code})'
    print(f'    {status}')
    if r.status_code != 201:
        print(f'    {r.text[:500]}')

print('Uploading scan results to DefectDojo...')
upload('Gitleaks Scan',             'gitleaks-report.json')
upload('SonarQube API Import',      'sonar-report.json')
upload('Semgrep JSON Report',       'semgrep-report.json')
upload('Trivy Scan',                os.path.join(APP_DIR, 'trivy-fs-report.json'))
upload('Trivy Scan',                'trivy-image-report.json')
upload('Dependency Check Scan',     os.path.join(APP_DIR, 'dependency-check-report', 'dependency-check-report.xml'))
upload('ZAP Scan',                  'zap-baseline-report.xml')
upload('CycloneDX Scan',            os.path.join(APP_DIR, 'sbom.cyclonedx.json'))
print(f'Done. View at: {DOJO_URL}/engagement/{ENGAGEMENT}/')
