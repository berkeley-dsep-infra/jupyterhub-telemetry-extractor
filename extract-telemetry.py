#!/usr/bin/env python3
import json
import dateutil.parser
import sys
import os
import pathlib
import logging
import secrets
import hmac
from jupyter_telemetry.eventlog import EventLog



def parse_activity_line(line):
    """
    Parses a user server start/stop line from JupyterHub logs

    Returns a tuple of (timestamp, anonymized_username, action).

    timestamp is rounded out to the nearest hour for anonymization purposes.
    """
    lineparts = line.split()
    try:
        # Round all timestamp info to the hour to make it more anonymous
        ts = dateutil.parser.parse('{} {}'.format(lineparts[1], lineparts[2])).replace(minute=0, second=0, microsecond=0)
        username = lineparts[6].strip()

        action = lineparts[-1].strip()
    except IndexError:
        # Poor person's debugger!
        print(lineparts)
        raise
    return (ts, username, action)


def main():
    eventlog = EventLog(
        allowed_schemas=[
            "hub.jupyter.org/server-action"
        ],
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    hmac_key = secrets.token_bytes(32)
    for dirname, _, files in os.walk(pathlib.Path(__file__).parent / "event-schemas"):
        for file in files:
            if not file.endswith('.yaml'):
                continue
            eventlog.register_schema_file(os.path.join(dirname, file))
    for l in sys.stdin:
        if 'seconds to' not in l:
            continue
        timestamp, user, action = parse_activity_line(l)
        eventlog.record_event(
            "hub.jupyter.org/server-action",
            1,
            {
                "action": action,
                "username": hmac.new(
                    key=hmac_key,
                    msg=user.encode(),
                    digestmod='sha256'
                ),
                "servername": ""
            },
            timestamp_override=timestamp

        )

if __name__ == '__main__':
    main()
