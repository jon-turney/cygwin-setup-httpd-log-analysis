#!/usr/bin/env python3

import re
import sys

class Agent():
    def __init__(self):
        self.ips = set()
        self.status = {}
        self.total = 0

data = {}

r = re.compile(r'(\S*) (\S*) (\S*) (\[.*\]) \"GET /mirrors.lst .*\" (\S*) (\S*) \"(.*)\" "(.*)"')
for l in sys.stdin:
    m = re.match(r, l)
    if m:
        ip = m.group(1)
        identity = m.group(2)
        username = m.group(3)
        timestamp = m.group(4)
        status = m.group(5)
        size = m.group(6)
        referer = m.group(7)
        agent = m.group(8)

        # ignore lines which have a referer: these are browsers following a link
        # to mirrors.lst
        if referer != "-":
            continue

        agent = re.sub(r' appid: [^)]*', '', agent)
        agent = re.sub(r'User-Agent: (.*)', r'\1', agent)
        agent = re.sub(r'.* \(compatible.*; (.*[Bb]ot/.*)\)', r'\1', agent)
        agent = re.sub(r'.* (Edge/\S*)', r'Edge/(various)', agent)
        agent = re.sub(r'.* (Safari/\S*).*', r'Safari/(various)', agent)
        agent = re.sub(r'.* (Firefox/\S*)', r'Firefox/(various)', agent)
        agent = re.sub(r'Python-urllib/\S*', r'Python-urllib/(various)', agent)
        agent = re.sub(r'.* WindowsPowerShell/(\S*)', r'WindowsPowerShell/\1', agent)

        if agent not in data:
            data[agent] = Agent()

        data[agent].status[status] = data[agent].status.get(status, 0) + 1
        data[agent].ips.add(ip)

grand_total = 0
grand_total_ips = 0
for agent in data:
    total = 0
    for s in data[agent].status:
        total += data[agent].status[s]
    data[agent].total = total
    grand_total += total
    grand_total_ips += len(data[agent].ips)

max_agent_width = 25
max_width = 79 + max_agent_width

print('%-*s | %-11s | %-45s | %s' % (max_agent_width, 'user-agent', 'unique IPs', 'response status count', 'total'))
print('-' * max_width)

for agent in sorted(data.keys(), key=lambda k: data[k].total, reverse=True):
    if len(data[agent].ips) <= 1 or data[agent].total <= 1:
        continue

    if len(agent) > max_agent_width:
        short_agent = agent[:max_agent_width]
    else:
        short_agent = agent

    print('%-*s | ' % (max_agent_width, short_agent), end='')
    ips = len(data[agent].ips)
    print('%5d (%2d%%) | ' % (ips, 100*ips/grand_total_ips), end='')
    for s in ['200', '206', '304', '403' ]:
        if s in data[agent].status:
            print('%s %5d | ' % (s, data[agent].status[s]), end='')
        else:
            print('          | ', end='')
    print('%6d (%2d%%) | ' % (data[agent].total, 100*data[agent].total/grand_total), end='')
    print()

print('-' * max_width)
print('hits to mirror.lst, excluding: non-empty referrer (browser hits), user-agents with only a single IP')
print('-' * max_width)
