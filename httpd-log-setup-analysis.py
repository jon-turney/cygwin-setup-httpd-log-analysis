#!/usr/bin/env python3

import re
import sys
from datetime import datetime
from locale import windows_locale

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

def breakdown(collection, title, by=None):
    t = 0
    tips = 0
    max_width = len(title)

    if by:
        kl = lambda k: getattr(collection[k], by)
    else:
        # by default 'natual sort' to order embedded numbers correctly
        kl = lambda s: [int(t) if t.isdigit() else t.lower() for t in re.split('(\d+)', s)]

    for i in collection:
        t += collection[i].total
        tips += len(collection[i].ips)
        max_width = max(max_width, len(i))

    print('-' * (max_width +  36))
    print('|%-*s | unique IPs    | requests       |' % (max_width, title))
    print('-' * (max_width +  36))

    for i in sorted(collection.keys(), key=kl, reverse=(by != None)):
        print('|%-*s | %5d (%4.1f%%) | %6d (%4.1f%%) | ' % (max_width, i, len(collection[i].ips), 100*len(collection[i].ips)/tips, collection[i].total, 100*collection[i].total/t))
    print('-' * (max_width +  36))
    print()

def compatible(ver):
    v = '0'
    m = re.match(r'([0-9.]+)', ver)
    if m:
      v = m.group(1)
    if float(v) >= 2.895:
      return 'compatible (>=2.895)'
    else:
      return 'incompatible (<2.895)'

def os_major(os):
    (major, minor) = os.rsplit('.', 1)
    if major == '10.0':
        for (m, v) in reversed([
            (0    , 'Technical Preview'),
            (10240, '1507 (Threshold 1)'),
            (10568, '1511 (Threshold 2)'),
            (14393, '1607 (Redstone 1)'),
            (15063, '1703 (Redstone 2)'),
            (16299, '1709 (Redstone 3)'),
            (17134, '1803 (Redstone 4)'),
            (17763, '1809 (Redstone 5)'),
            (18362, '1903 (19H1)'),
            (18363, '1909 (19H2)'),
            (19041, '2004 (20H1)'),
            (19042, '(20H2)'),
            (19043, '(21H1)'),
            (19044, 'TBA'),
        ]):
            if int(minor) >= m:
                major += (' ' + v)
                break
    else:
        for (m, v) in [
                ('6.0', 'Windows Vista'),
                ('6.1', 'Windows 7'),
                ('6.2', 'Windows 8'),
                ('6.3', 'Windows 8.1'),
        ]:
            if m == major:
                major += ('  ' + v)
                break

    return major


def print_agent_data(agent, data):
    if len(agent) > max_agent_width:
        short_agent = agent[:max_agent_width]
    else:
        short_agent = agent

    print('|%-*s | ' % (max_agent_width, short_agent), end='')
    ips = len(data.ips)
    print('%5d (%4.1f%%) | ' % (ips, 100*ips/grand_total_ips), end='')
    print('%6d (%4.1f%%) | ' % (data.total, 100*data.total/grand_total), end='')
    for s in sorted(statuses.keys()):
        if s in data.status:
            print('%s %6d | ' % (s, data.status[s]), end='')
        else:
            print('           | ', end='')
    print()


data = {}
statuses = {}
times = []

setup_versions = {}
setup_compat = {}
setup_oses = {}
setup_oses_major = {}
setup_bitnesses = {}
setup_langs = {}
setup_downloads = {}

r = re.compile(r'(\S*) (\S*) (\S*) \[(.*)\] \"GET /(\S*) .*\" (\S*) (\S*) \"(.*)\" "(.*)"')
rc = re.compile(r'Cygwin-Setup/(\S*)(?: \(Windows NT (\S*)\)|$)')
rfr = re.compile(r'Setup.exe/(\S*)')

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

        timestamp = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z')
        if timestamp.timestamp():
            times.append(timestamp)

        if path == "mirrors.lst":
            # ignore lines which have a referer: these are browsers following a link
            # to mirrors.lst
            if referer != "-":
                continue

            original_agent = agent

            # do some canonicalization of agent string
            agent = re.sub(r'User-Agent: (.*)', r'\1', agent)
            agent = re.sub(r'.* (Edge/\S*)', r'Edge/\1', agent)
            agent = re.sub(r'.* (Safari/\S*).*', r'Safari/\1', agent)
            agent = re.sub(r'.* (Firefox/\S*)', r'Firefox/\1', agent)
            agent = re.sub(r'.* WindowsPowerShell/(\S*)', r'WindowsPowerShell/\1', agent)
            agent = re.sub(r'Mozilla/\S* \(compatible; (.*)', r'\1', agent)
            agent = re.sub(r'Setup.exe/(\S*) .*', r'Cygwin-Setup/\1', agent)  # some FR patched versions of setup identify as 'Setup.exe'
            agent = re.sub(r'Cygwin-Setup/(\S*) .*', r'Cygwin-Setup/\1', agent)
            agent = re.sub(r'Cygwin Setup', r'Cygwin-Setup/unknown', agent)
            agent = re.sub(r'^(\S*?)/\S*', r'\1/*', agent)

            if agent not in data:
                data[agent] = Agent()

            statuses[status] = statuses.get(status, 0) + 1
            data[agent].status[status] = data[agent].status.get(status, 0) + 1
            data[agent].ips.add(ip)

            ver = None
            if original_agent.startswith('Setup.exe'):
                mc = re.match(rfr, original_agent)
                if mc:
                    ver = mc.group(1)
                    OS.add(setup_versions, ver, ip)

            if original_agent.startswith('Cygwin'):
                mc = re.match(rc, original_agent)
                if mc:
                    ver = mc.group(1)
                    OS.add(setup_versions, ver, ip)

                    if mc.group(2):
                        details = mc.group(2).split(';')
                        details.extend([''] * 3)
                        details = details[:3]

                        os = details[0]
                        bitness = details[1]
                        lang = details[2]

                        if os:
                            OS.add(setup_oses, os, ip)
                            OS.add(setup_oses_major, os_major(os), ip)
                        if bitness:
                            # compensate for a bug in 2.893
                            if bitness == 'WoW64-14c':
                                bitness = 'Win32'

                            # compensate for a bug in 2.908
                            if bitness == 'Win64-on-Win32':
                                bitness = 'Win64'

                            # canonicalize pre-2.908 reporting
                            if bitness == 'WoW64':
                                bitness = 'Win32-on-Win64'

                            if bitness == 'WoW64-ARM64':
                                bitness = 'Win32-on-ARM64'

                            OS.add(setup_bitnesses, bitness, ip)
                        if lang:
                            lang_name = windows_locale.get(int(lang, 16), None)
                            if lang_name:
                                lang = '%s (%s)' % (lang, lang_name)
                            OS.add(setup_langs, lang, ip)
                else:
                    ver = "Unknown (<=2.879)"
                    OS.add(setup_versions, ver, ip)

            if ver:
                OS.add(setup_compat, compatible(ver), ip)

        elif (path == 'setup-x86_64.exe') and (status == '200'):
            OS.add(setup_downloads, 'x86_64', ip)
        elif (path == 'setup-x86.exe') and (status == '200') and (ip != '125.174.164.21'):
            OS.add(setup_downloads, 'x86', ip)

grand_total = 0
grand_total_ips = 0
other = Agent()

for agent in data:
    total = 0
    for s in data[agent].status:
        total += data[agent].status[s]
    data[agent].total = total
    grand_total += total
    grand_total_ips += len(data[agent].ips)

max_agent_width = 25
max_status_width = (len(statuses) * 13) - 3
max_width = 39 + max_agent_width + max_status_width

print('cygwin setup report from %s to %s' % (min(times), max(times)))
print()
print('hits to mirrors.lst, excluding non-empty referrer (browser hits)')
print('-' * max_width)
print('|%-*s | %-13s | %-14s | %-*s |' % (max_agent_width, 'user-agent', 'unique IPs', 'requests', max_status_width, 'requests by response status'))
print('-' * max_width)

# aggregate data for agents with a single IP
for agent in list(data.keys()):
    if len(data[agent].ips) <= 1:
        other.total += data[agent].total
        other.ips.update(data[agent].ips)
        for s in data[agent].status:
            other.status[s] = other.status.get(s, 0) + data[agent].status[s]
        del data[agent]

for agent in sorted(data.keys(), key=lambda k: data[k].total, reverse=True):
    print_agent_data(agent, data[agent])
print_agent_data('other (agents with 1 IP)', other)

print('-' * max_width)
print('|%-*s | %5d         | %6d         | %-*s |' % (max_agent_width, 'totals', grand_total_ips, grand_total, max_status_width, ''))
print('-' * max_width)
print()

breakdown(setup_versions, "setup version")
breakdown(setup_compat, "setup compatibility")
breakdown(setup_oses, "OS version")
breakdown(setup_oses_major, "OS version (major)")
breakdown(setup_bitnesses, "bitness", 'total')
breakdown(setup_langs, "UI language", 'total')

print('hits to setup executables')
breakdown(setup_downloads, "downloads", 'total')
