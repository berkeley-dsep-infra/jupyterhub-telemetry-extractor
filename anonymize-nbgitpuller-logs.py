#!/usr/bin/env python3
import hashlib
import hmac
import json
from datetime import datetime
import re
import secrets
from urllib import parse

# Generate a HMAC key for salting the username
# This is only kept in memory, so we can not reverse this after this process dies
HMAC_KEY = secrets.token_bytes(32)

def parse_activity_line(line):
    """
    Parses nbgitpuller click actions from JupyterHub logs

    Returns a tuple of (timestamp, url, anonymized_username, hubname).
    """
    log_entry = json.loads(line)
    payload = log_entry['textPayload']
    parts = payload.split() # this is...  terrible and error prone.

    user = parts[10][1:-1].split('@')[0]
    userhash = hmac.new(
        HMAC_KEY, user.encode(), hashlib.sha512
    ).hexdigest()

    hub = log_entry['labels']['k8s-pod/release']
    ts = datetime.fromisoformat(f'{parts[1]}T{parts[2]}').isoformat()
    url = parse.unquote(parts[7])

    return (ts, url, userhash, hub)

def generate_session_data(infile_path, outfile_path):
    """
    Generate nbgitpuller click data from JupyterHub logs in infile_path
    """
    with open(infile_path) as infile, open(outfile_path, 'w') as outfile:
        for l in infile:
            if '/hub/login' not in l:
                timestamp, url, user, hub = parse_activity_line(l)
                outfile.write(
                    json.dumps(
                        {'timestamp': timestamp, 'url': url, 'username': user, 'hub': hub}
                    )
                    + '\n'
                )

# input file is created by running egrep on STDERR logs from datahub
# and then putting that all in one big file.
# pattern to match is:
# egrep -ihr '302 GET /hub/user-redirect/(git-sync|git-pull|interact)\?'
generate_session_data(
    '/e/datahub/stderr/nbgitpuller-clicks-spring-2023.json',
    '../data/processed/spring-2023/nbgitpuller-clicks-spring23.jsonl'
)
