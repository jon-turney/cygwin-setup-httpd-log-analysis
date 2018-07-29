#!/usr/bin/env python3

import re
import sys

class Agent(object):
    def __init__(self):
        self.ips = set()
        self.status = {}
        self.total = 0

class OS(object):
    def __init__(self):
        self.ips = set()
        self.total = 0

    @staticmethod
    def add(collection, key, ip):
        if key not in collection:
            collection[key] = OS()

        collection[key].total += 1
        collection[key].ips.add(ip)

def breakdown(collection, title):
    t = 0
    tips = 0
    max_width = len(title)

    for i in collection:
        t += collection[i].total
        tips += len(collection[i].ips)
        max_width = max(max_width, len(i))

    print('-' * (max_width +  32))
    print('|%-*s | unique IPs  | requests     |' % (max_width, title))
    print('-' * (max_width +  32))

    for i in sorted(collection.keys(), key=lambda k: collection[k].total, reverse=True):
        print('|%-*s | %5d (%2d%%) | %6d (%2d%%) | ' % (max_width, i, len(collection[i].ips), 100*len(collection[i].ips)/tips, collection[i].total, 100*collection[i].total/t))
    print('-' * (max_width +  32))
    print()

data = {}

setup_versions = {}
setup_oses = {}
setup_bitnesses = {}
setup_downloads = {}

r = re.compile(r'(\S*) (\S*) (\S*) (\[.*\]) \"GET /(\S*) .*\" (\S*) (\S*) \"(.*)\" "(.*)"')
rc = re.compile(r'Cygwin-Setup/(\S*)(?: \(Windows NT (\S*);(\S*)\)|$)')

for l in sys.stdin:
    m = re.match(r, l)
    if m:
        ip = m.group(1)
        identity = m.group(2)
        username = m.group(3)
        timestamp = m.group(4)
        path = m.group(5)
        status = m.group(6)
        size = m.group(7)
        referer = m.group(8)
        agent = m.group(9)

        if path == "mirrors.lst":
            # ignore lines which have a referer: these are browsers following a link
            # to mirrors.lst
            if referer != "-":
                continue

            original_agent = agent

            agent = re.sub(r' appid: [^)]*', '', agent)
            agent = re.sub(r'User-Agent: (.*)', r'\1', agent)
            agent = re.sub(r'.* \(compatible.*; (.*[Bb]ot/.*)\)', r'\1', agent)
            agent = re.sub(r'.* (Edge/\S*)', r'Edge/(various)', agent)
            agent = re.sub(r'.* (Safari/\S*).*', r'Safari/(various)', agent)
            agent = re.sub(r'.* (Firefox/\S*)', r'Firefox/(various)', agent)
            agent = re.sub(r'Python-urllib/\S*', r'Python-urllib/(various)', agent)
            agent = re.sub(r'.* WindowsPowerShell/(\S*)', r'WindowsPowerShell/\1', agent)
            agent = re.sub(r'Cygwin-Setup/(\S*) .*', r'Cygwin-Setup/\1', agent)

            if agent not in data:
                data[agent] = Agent()

            data[agent].status[status] = data[agent].status.get(status, 0) + 1
            data[agent].ips.add(ip)

            if original_agent.startswith('Cygwin'):
                mc = re.match(rc, original_agent)
                if mc:
                    ver = mc.group(1)
                    os = mc.group(2)
                    bitness = mc.group(3)

                    OS.add(setup_versions, ver, ip)
                    if os:
                        OS.add(setup_oses, os, ip)
                    if bitness:
                        OS.add(setup_bitnesses, bitness, ip)
                else:
                    ver = "Unknown (<=2.879)"
                    OS.add(setup_versions, ver, ip)
        elif (path == 'setup-x86_64.exe') and (status == '200'):
            OS.add(setup_downloads, 'x86_64', ip)
        elif (path == 'setup-x86.exe') and (status == '200') and (ip != '125.174.164.21'):
            OS.add(setup_downloads, 'x86', ip)

grand_total = 0
grand_total_ips = 0
other = 0
other_ips = 0

for agent in data:
    total = 0
    for s in data[agent].status:
        total += data[agent].status[s]
    data[agent].total = total
    grand_total += total
    grand_total_ips += len(data[agent].ips)

max_agent_width = 25
max_width = 80 + max_agent_width

print('hits to mirrors.lst, excluding non-empty referrer (browser hits)')
print('-' * max_width)
print('|%-*s | %-11s | %-45s | %-12s |' % (max_agent_width, 'user-agent', 'unique IPs', 'response status count', 'requests'))
print('-' * max_width)

for agent in sorted(data.keys(), key=lambda k: data[k].total, reverse=True):
    if len(data[agent].ips) <= 1 or data[agent].total <= 1:
        other += data[agent].total
        other_ips += len(data[agent].ips)
        continue

    if len(agent) > max_agent_width:
        short_agent = agent[:max_agent_width]
    else:
        short_agent = agent

    print('|%-*s | ' % (max_agent_width, short_agent), end='')
    ips = len(data[agent].ips)
    print('%5d (%2d%%) | ' % (ips, 100*ips/grand_total_ips), end='')
    for s in ['200', '206', '304', '403' ]:
        if s in data[agent].status:
            print('%s %5d | ' % (s, data[agent].status[s]), end='')
        else:
            print('          | ', end='')
    print('%6d (%2d%%) | ' % (data[agent].total, 100*data[agent].total/grand_total), end='')
    print()

print('|%-*s | %5d       | %-45s | %6d       |' % (max_agent_width, 'other (agents with 1 IP)', other_ips, '', other))
print('-' * max_width)
print('|%-*s | %5d       | %-45s | %6d       |' % (max_agent_width, 'totals', grand_total_ips, '', grand_total))
print('-' * max_width)
print()

breakdown(setup_versions, "setup version")
breakdown(setup_oses, "OS version")
breakdown(setup_bitnesses, "bitness")

print('hits to setup executables')
breakdown(setup_downloads, "downloads")
