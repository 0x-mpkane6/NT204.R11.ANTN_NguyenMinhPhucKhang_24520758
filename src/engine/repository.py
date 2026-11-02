import ipaddress
from collections import defaultdict
from copy import deepcopy

from .models import Rule


class RuleRepository:
    def __init__(self, rules=()):
        self._rules = []
        self._networks = []
        self._exact = defaultdict(lambda: defaultdict(set))
        self._ranges = defaultdict(list)
        self._any = defaultdict(set)
        self._sids = set()
        self.last_query = {'indexed_rules': 0, 'header_checks': 0, 'candidates': 0, 'reason': None}
        for rule in rules:
            self.add(rule)

    def __len__(self):
        return len(self._rules)

    def add(self, rule):
        if not isinstance(rule, Rule):
            raise TypeError('Repository accepts validated Rule objects')
        if rule.sid in self._sids:
            raise ValueError('Duplicate SID: ' + str(rule.sid))
        stored = deepcopy(rule)
        header = stored.header
        if header.action != 'alert' or header.protocol not in ('tcp', 'udp', 'ip', 'any') or header.direction not in ('->', '<>'):
            raise ValueError('Unsupported rule header')
        networks = tuple(None if address == 'any' else ipaddress.IPv4Network(address)
                         for address in (header.src_ip, header.dst_ip))
        for interval in (header.src_port, header.dst_port):
            if len(interval) != 2 or any(type(p) is not int for p in interval) or not 0 <= interval[0] <= interval[1] <= 65535:
                raise ValueError('Invalid port interval')
        index = len(self._rules)
        self._rules.append(stored)
        self._networks.append(networks)
        self._sids.add(stored.sid)
        self._index(header.protocol, header.dst_port, index)
        if header.direction == '<>':
            self._index(header.protocol, header.src_port, index)

    def _index(self, protocol, interval, index):
        low, high = interval
        if (low, high) == (0, 65535):
            self._any[protocol].add(index)
        elif low == high:
            self._exact[protocol][low].add(index)
        else:
            self._ranges[protocol].append((low, high, index))

    def candidates(self, context):
        self.last_query = {'indexed_rules': len(self), 'header_checks': 0, 'candidates': 0, 'reason': None}
        try:
            if context.get('context_status') == 'invalid':
                raise ValueError('invalid_context')
            protocol = context['protocol'].lower()
            if protocol not in ('tcp', 'udp'):
                raise ValueError('unsupported_protocol')
            source = ipaddress.IPv4Address(context['src_ip'])
            destination = ipaddress.IPv4Address(context['dst_ip'])
            sport, dport = context['src_port'], context['dst_port']
            if any(type(p) is not int or not 0 <= p <= 65535 for p in (sport, dport)):
                raise ValueError('invalid_port')
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            self.last_query['reason'] = str(exc)
            return []
        pool = set()
        for bucket in (protocol, 'ip', 'any'):
            pool.update(self._any.get(bucket, ()))
            pool.update(self._exact.get(bucket, {}).get(dport, ()))
            pool.update(index for low, high, index in self._ranges.get(bucket, ()) if low <= dport <= high)
        selected = []
        for index in sorted(pool):
            rule = self._rules[index]
            header = rule.header
            src_net, dst_net = self._networks[index]
            self.last_query['header_checks'] += 1

            def matches(src, dst, sp, dp):
                return ((src_net is None or src in src_net) and
                        (dst_net is None or dst in dst_net) and
                        header.src_port[0] <= sp <= header.src_port[1] and
                        header.dst_port[0] <= dp <= header.dst_port[1])

            if matches(source, destination, sport, dport) or (
                header.direction == '<>' and matches(destination, source, dport, sport)
            ):
                selected.append(deepcopy(rule))
        self.last_query['candidates'] = len(selected)
        return selected
