"""
Extract nbgitpuller clicks from JupyterHub logs.

Parses JupyterHub logs from stdin to output jsonl
with nbgitpuller URLs. Those aren't parsed properly,
so user should do that.
"""
import hmac
import json
import sys
import secrets
from datetime import datetime
import re

HMAC_KEY = secrets.token_bytes(32)

for l in sys.stdin:
    if re.search(r'302 GET /hub/user-redirect/(git-sync|git-pull|interact)\?', l):
        if '/hub/login' not in l:
            parts = l.split(' ')
            timestamp = datetime.fromisoformat(f'{parts[1]}T{parts[2]}').isoformat()
            url = parts[7]
            user = parts[10][1:-1].split('@')[0]
            hashed_user = hmac.new(
                key=HMAC_KEY, msg=user.encode(), digestmod='sha256'
            ).hexdigest()

            print(json.dumps({
                'timestamp': timestamp,
                'url': url,
                'username': hashed_user
            }))
