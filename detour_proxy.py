#! /usr/bin/env python3

# Copyright 2017 twisteroid ambassador

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import asyncio
import csv
import errno
import ipaddress
import logging
import os.path
import random
import signal
import socket
import sys
import time
import warnings
from collections import defaultdict, Counter, namedtuple
from contextlib import ExitStack, contextmanager
from enum import Enum
from functools import partial
from itertools import cycle, islice
from typing import Dict, Union, Tuple, List

import aiodns
import pycares

# ========== Configuration section ==========
DEFAULT_DNS_POISON_FILE = os.path.join(
    os.path.dirname(__file__), 'dns_poison_list.txt')

WINDOWS_USE_PROACTOR_EVENT_LOOP = False  # do not use, won't work with aiodns
# IPV6_ONLY = False
# IPV4_ONLY = False
# IPV6_FIRST = False
# ========== End of configuration section ==========

# assert not (IPV4_ONLY and IPV6_ONLY)

INADDR_ANY = ipaddress.IPv4Address(0)

IPAddressType = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def roundrobin(*iterables):
    "roundrobin('ABC', 'D', 'EF') --> A D E B F C"
    # Recipe credited to George Sakkis
    pending = len(iterables)
    nexts = cycle(iter(it).__next__ for it in iterables)
    while pending:
        try:
            for next in nexts:
                yield next()
        except StopIteration:
            pending -= 1
            nexts = cycle(islice(nexts, pending))


class SOCKS5AuthType(bytes, Enum):
    NO_AUTH = b'\x00'
    GSSAPI = b'\x01'
    USERNAME_PASSWORD = b'\x02'
    NO_OFFERS_ACCEPTABLE = b'\xff'


class SOCKS5Command(bytes, Enum):
    CONNECT = b'\x01'
    BIND = b'\x02'
    UDP_ASSOCIATE = b'\x03'


class SOCKS5AddressType(bytes, Enum):
    IPV4_ADDRESS = b'\x01'
    DOMAIN_NAME = b'\x03'
    IPV6_ADDRESS = b'\x04'


class SOCKS5Reply(bytes, Enum):
    SUCCESS = b'\x00'
    GENERAL_FAILURE = b'\x01'
    CONNECTION_NOT_ALLOWED_BY_RULESET = b'\x02'
    NETWORK_UNREACHABLE = b'\x03'
    HOST_UNREACHABLE = b'\x04'
    CONNECTION_REFUSED = b'\x05'
    TTL_EXPIRED = b'\x06'
    COMMAND_NOT_SUPPORTED = b'\x07'
    ADDRESS_TYPE_NOT_SUPPORTED = b'\x08'


@contextmanager
def finally_close(writer: asyncio.StreamWriter):
    """Closes writer on normal context exit and aborts on exception.

    This is Better^{TM} than contextlib.closing because of the additional
    abort thing."""
    try:
        yield
    except Exception:
        writer.transport.abort()
        raise
    finally:
        writer.close()


class WithSet(set):
    """A set with a with_this(item) context manager."""

    @contextmanager
    def with_this(self, item):
        """Add item to self on entry of context, and remove it on exit."""
        if item in self:
            raise KeyError('item {!r} already in set'.format(item))
        self.add(item)
        try:
            yield
        finally:
            self.remove(item)


def safe_write_eof(writer: asyncio.StreamWriter):
    """This is a workaround of a bug in asyncio, where calling write_eof()
    on a StreamWriter after the transport has been closed by the remote side
    will raise an AttributeError.
    """
    if not writer.transport.is_closing():
        writer.write_eof()


def get_enum(enum_type, value):
    try:
        return enum_type(value)
    except ValueError:
        return value


class DetourException(Exception):
    """Base exception for this script."""
    pass


class UpstreamRelayError(DetourException):
    """Signify a network error in the upstream connection while relaying."""
    pass


class RelayError(DetourException):
    """Signify a network error while relaying."""
    pass


class UpstreamConnectError(DetourException):
    """Signify an error while connecting to upstream.

    args should be (socks5_reply_reason, human_readable_reason).
    socks5_reply_reason should be a SOCKS5Reply instance.
    """
    pass


class ServerHandlerError(DetourException):
    """Signify an error with a downstream connection."""
    pass


class ConnectionType(Enum):
    DIRECT = 'direct'
    ALTDNS = 'altdns'
    DETOUR = 'detour'


class DetourTokenHostEntry:
    """Maintains information on a host name / IP address.

    This class is responsible for remembering what kind of censorship, if any,
    is in effect for a single host name or IP address, and determining what
    connection methods should be used for it.

    The general idea is: each host starts with [direct, altdns, detour]
    connection methods available, which will be tried in order. When connecting
    with a method not first in the list, a token for that method is acquired
    (get_*_token). When that connection completes successfully, the token is
    returned (put_*_token), and the token count for that method is increased,
    while the token count for other methods are decreased. If a method has
    enough tokens, methods before it in the list are removed, so the new method
    becomes the default.
    """
    __slots__ = ['_is_ip_address', 'try_direct', 'try_altdns',
                 'tested_dns_poison', 'stash_gai_result',
                 '_last_detour_token', '_pending_detour_tokens',
                 'detour_tokens',
                 '_last_dns_token', '_pending_dns_tokens',
                 'dns_tokens',
                 '_temp_detour_timestamp', '_temp_dns_timestamp',
                 '_next_request_activates_temp_detour',
                 '_next_request_activates_temp_dns',
                 ]

    # After a fresh token is issued and before TOKEN_SUSTAIN seconds has passed,
    # the same token will be returned for new requests.
    TOKEN_SUSTAIN = 1.0
    # If a connection method has >= DETOUR_TOKEN_COUNT tokens, it is considered
    # the appropriate method for this host, and methods before this will no
    # longer be attempted.
    DETOUR_TOKEN_COUNT = 3
    # If a temporary connection method has been activated, all new connections
    # within TEMP_SUSTAIN seconds will use the same temporary method.
    TEMP_SUSTAIN = 1.0
    # With each new connection, there is RELEARN_PROBABILITY chance that it
    # will be re-learned.
    RELEARN_PROBABILITY = 0.001

    def __init__(self, is_ip_address=False):
        # If self deals with an IP address instead of a host name, then:
        # AltDNS should not be tried;
        # DNS poisoning should not be tested for.
        self._is_ip_address = is_ip_address
        self.try_direct = True
        self.try_altdns = not is_ip_address
        self.tested_dns_poison = is_ip_address
        self.stash_gai_result = None
        timenow = time.monotonic()
        # Make sure these "last did something" timestamps are expired
        self._last_detour_token = timenow - 2 * self.TOKEN_SUSTAIN
        self._pending_detour_tokens = set()
        self.detour_tokens = 0
        self._last_dns_token = timenow - 2 * self.TOKEN_SUSTAIN
        self._pending_dns_tokens = set()
        self.dns_tokens = 0
        self._temp_detour_timestamp = timenow - 2 * self.TEMP_SUSTAIN
        self._temp_dns_timestamp = timenow - 2 * self.TEMP_SUSTAIN
        self._next_request_activates_temp_detour = False
        self._next_request_activates_temp_dns = False

    def _reset_test_dns_poison(self):
        assert not self._is_ip_address
        self.try_direct = True
        self.try_altdns = not self._is_ip_address
        self.tested_dns_poison = self._is_ip_address
        self.stash_gai_result = None

    def _relearn(self):
        if self.detour_tokens >= self.DETOUR_TOKEN_COUNT:
            self.detour_tokens = self.DETOUR_TOKEN_COUNT - 1
        if self.dns_tokens >= self.DETOUR_TOKEN_COUNT:
            self.dns_tokens = self.DETOUR_TOKEN_COUNT - 1
        if not self._is_ip_address:
            self._reset_test_dns_poison()

    def dump(self):
        return {
            'tested_dns_poison': self.tested_dns_poison,
            'try_direct': self.try_direct,
            'try_altdns': self.try_altdns,
            'detour_tokens': self.detour_tokens,
            'dns_tokens': self.dns_tokens,
        }

    def load(self, tested_dns_poison, try_direct, try_altdns, detour_tokens,
             dns_tokens):
        if self._is_ip_address:
            if not (tested_dns_poison
                    and try_direct
                    and not try_altdns):
                raise ValueError('illegal state for ip address')
        if not try_direct and not try_altdns:
            raise ValueError('illegal state combination')
        self.tested_dns_poison = tested_dns_poison
        self.try_direct = try_direct
        self.try_altdns = try_altdns
        self.detour_tokens = detour_tokens
        self.dns_tokens = dns_tokens

    def report_dns_poison_test(self, poisoned=None):
        """Tell me whether this host's DNS records are poisoned.

        poisoned = True: definitely poisoned.
        poisoned = False: definitely not poisoned.
        poisoned = None: can't tell for sure.
        """
        assert not self._is_ip_address
        if poisoned is True:
            self.try_direct = False
            self.try_altdns = True
        elif poisoned is False:
            self.try_direct = True
            self.try_altdns = False
        else:
            self.try_direct = True
            self.try_altdns = True
        self.tested_dns_poison = True

    def get_connections(self) -> List[Tuple[ConnectionType, bool]]:
        """Return a list of connection types to try for this host.

        Returns a list of (connection_type, needs_token) in reverse order,
        i.e. the last entry in the list should be attempted first. This is for
        convenience with list.pop().
        """
        if random.random() < self.RELEARN_PROBABILITY:
            self._relearn()
        if ((not self.try_direct and not self.try_altdns)
            or self.detour_tokens >= self.DETOUR_TOKEN_COUNT):
            return [(ConnectionType.DETOUR, False)]
        # at this point:
        # self.try_direct or self.try_altdns == True
        connections = [(ConnectionType.DETOUR, True)]
        timenow = time.monotonic()
        if self._next_request_activates_temp_detour:
            self._temp_detour_timestamp = timenow
            self._next_request_activates_temp_detour = False
            return connections
        if timenow - self._temp_detour_timestamp < self.TEMP_SUSTAIN:
            return connections
        if not self.try_direct or self.dns_tokens >= self.DETOUR_TOKEN_COUNT:
            connections.append((ConnectionType.ALTDNS, False))
            return connections
        # at this point:
        # self.try_direct == True,
        # so self.try_altdns is undetermined
        if self.try_altdns:
            assert not self._is_ip_address, 'try_altdns for ip address'
            connections.append((ConnectionType.ALTDNS, True))
        if self._next_request_activates_temp_dns:
            self._temp_dns_timestamp = timenow
            self._next_request_activates_temp_dns = False
            return connections
        if timenow - self._temp_dns_timestamp < self.TEMP_SUSTAIN:
            return connections
        connections.append((ConnectionType.DIRECT, False))
        return connections

    def report_relay_failure(self, conn_type):
        if conn_type is ConnectionType.DIRECT:
            if self.try_altdns:
                self._next_request_activates_temp_dns = True
            else:
                self._next_request_activates_temp_detour = True
        elif conn_type is ConnectionType.ALTDNS:
            self._next_request_activates_temp_detour = True

    def report_relay_success(self, conn_type, token):
        if conn_type is ConnectionType.DIRECT:
            assert token is None, 'direct connections should not have token'
            if not self._is_ip_address:
                self.reduce_dns_token()
            self.reduce_detour_token()
        elif conn_type is ConnectionType.ALTDNS:
            if token is not None:
                self.put_dns_token(token)
            self.reduce_detour_token()
        elif conn_type is ConnectionType.DETOUR:
            if token is not None:
                self.put_detour_token(token)
            if not self._is_ip_address:
                self.reduce_dns_token()

    def get_detour_token(self):
        timenow = time.monotonic()
        if timenow - self._last_detour_token < self.TOKEN_SUSTAIN:
            return self._last_detour_token
        self._pending_detour_tokens.add(timenow)
        return timenow

    def get_dns_token(self):
        assert not self._is_ip_address, 'get_dns_token for ip address'
        timenow = time.monotonic()
        if timenow - self._last_dns_token < self.TOKEN_SUSTAIN:
            return self._last_dns_token
        self._pending_dns_tokens.add(timenow)
        return timenow

    def put_detour_token(self, token):
        if token in self._pending_detour_tokens:
            self._pending_detour_tokens.remove(token)
            self.detour_tokens += 1
        return

    def put_dns_token(self, token):
        assert not self._is_ip_address, 'put_dns_token for ip address'
        if token in self._pending_dns_tokens:
            self._pending_dns_tokens.remove(token)
            self.dns_tokens += 1
        return

    def reduce_detour_token(self):
        if self.detour_tokens > 0:
            self.detour_tokens -= 1
            return
        if self._pending_detour_tokens:
            self._pending_detour_tokens.pop()

    def reduce_dns_token(self):
        assert not self._is_ip_address, 'reduce_dns_token for ip address'
        if self.dns_tokens > 0:
            self.dns_tokens -= 1
            return
        if self._pending_dns_tokens:
            self._pending_dns_tokens.pop()


class DetourTokenWhitelist:
    """Manages persistent and learned connection information for all hosts."""
    def __init__(self):
        self._hosts = defaultdict(DetourTokenHostEntry
                                  )  # type: Dict[str, DetourTokenHostEntry]
        self._ips = defaultdict(partial(
            DetourTokenHostEntry, is_ip_address=True)
        )  # type: Dict[IPAddressType, DetourTokenHostEntry]
        self._persistent = dict()
        self._persistent_ip = dict()
        self._logger = logging.getLogger('DetourTokenWhitelist')

    def match_host(self, host) \
            -> Tuple[List, Union[DetourTokenHostEntry, None]]:
        """Get info host name / IP address, matching parents when necessary.

        Returns (connections, host_entry). Note that the connections list is
        backwards, as returned by HostEntry.get_connections().
        """
        if isinstance(host, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            # This does a linear search through persistent IPs, which works
            # fine for a small data set. Perhaps some prefix search method
            # can be implemented if a large amount of persistent IPs are
            # expected.
            for ip_network, conn_type in self._persistent_ip.items():
                if host in ip_network:
                    self._logger.info('%r matched %r in persistent IP list, '
                                      'state %r', host, ip_network, conn_type)
                    return [(conn_type, False)], None
            host_entry = self._ips[host]
            connections = host_entry.get_connections()
            self._logger.debug('%s connections: %r', host, connections)
            return connections, host_entry
        else:
            hosts_to_match = []
            base_domain = host
            while base_domain:
                hosts_to_match.append(base_domain)
                base_domain = base_domain.partition('.')[2]
            for match_host in hosts_to_match:
                if match_host in self._persistent:
                    conn_type = self._persistent[match_host]
                    self._logger.info('%r matched %r in persistent list, '
                                      'state %r', host, match_host, conn_type)
                    return [(conn_type, False)], None
            host_entry = self._hosts[host]
            connections = host_entry.get_connections()
            self._logger.debug('%s connections: %r', host, connections)
            return connections, host_entry

    def load_persistent_list(self, persistent_file):
        for line in persistent_file:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            state, host = line.split(maxsplit=1)
            state = state.lower()
            try:
                connection = ConnectionType(state)
            except ValueError as e:
                self._logger.warning('%r for line: %s', e, line)
                continue
            try:
                ip = ipaddress.ip_network(host)
            except ValueError:
                self._persistent[host] = connection
            else:
                self._persistent_ip[ip] = connection

    def load_state_file(self, filepath):
        with open(filepath, 'rt', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for record in reader:
                try:
                    ip = ipaddress.ip_address(record['host'])
                except ValueError:
                    host_entry = self._hosts[record['host']]
                    try:
                        host_entry.load(record['tested_dns_poison'] == '1',
                                        record['try_direct'] == '1',
                                        record['try_altdns'] == '1',
                                        int(record['detour_tokens']),
                                        int(record['dns_tokens']),
                                        )
                    except ValueError as e:
                        self._logger.warning('Loading state for %s failed: %r',
                                             record['host'], e)
                else:
                    host_entry = self._ips[ip]
                    try:
                        host_entry.load(True,
                                        True,
                                        False,
                                        int(record['detour_tokens']),
                                        0)
                    except ValueError as e:
                        self._logger.warning('Loading state for %s failed: %r',
                                             record['host'], e)

    def dump_state_file(self, filepath):
        with open(filepath, 'wt', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, (
                'host', 'tested_dns_poison', 'try_direct', 'try_altdns',
                'detour_tokens', 'dns_tokens'))
            writer.writeheader()
            for host, host_entry in self._hosts.items():
                state = host_entry.dump()
                if state['detour_tokens'] or state['dns_tokens']:
                    state['tested_dns_poison'] = int(state['tested_dns_poison'])
                    state['try_direct'] = int(state['try_direct'])
                    state['try_altdns'] = int(state['try_altdns'])
                    state['host'] = host
                    writer.writerow(state)
            for ip, host_entry in self._ips.items():
                state = host_entry.dump()
                if state['detour_tokens']:
                    state['tested_dns_poison'] = 0
                    state['try_direct'] = 1
                    state['try_altdns'] = 0
                    state['host'] = ip.compressed
                    writer.writerow(state)


class AltDNSCachedResult:
    __slots__ = ['result', 'expiry', 'task']

    def __init__(self):
        self.result = None
        self.expiry = None
        self.task = None


AltDNSCacheEntry = namedtuple('AltDNECacheEntry', ['ipv4', 'ipv6'])


class AltDNSResolver:
    MAX_TTL = 3 * 60 * 60
    DEFAULT_TTL = 60

    def __init__(self, servers, loop=None,
                 use_tcp=False, udp_port=None, tcp_port=None):
        self._loop = loop or asyncio.get_event_loop()
        def new_cache_entry():
            return AltDNSCacheEntry(AltDNSCachedResult(),
                                    AltDNSCachedResult())
        self._cache = defaultdict(new_cache_entry)
        self._logger = logging.getLogger('AltDNSResolver')
        resolver_args = {}
        if use_tcp:
            resolver_args['flags'] = pycares.ARES_FLAG_USEVC
        if udp_port is not None:
            resolver_args['udp_port'] = udp_port
        if tcp_port is not None:
            resolver_args['tcp_port'] = tcp_port
        self._resolver = aiodns.DNSResolver(servers, self._loop,
                                            **resolver_args)

    async def getaddrinfo(self, host, port, *,
                          ipv4_only=False, ipv6_only=False, ipv6_first=False):
        try:
            if ipv4_only:
                return await self._getaddrinfo_ipv4(host, port)
            if ipv6_only:
                return await self._getaddrinfo_ipv6(host, port)
        except aiodns.error.DNSError as e:
            raise UpstreamConnectError(SOCKS5Reply.HOST_UNREACHABLE,
                                       'DNS resolution failed') from e
        ipv4_task = asyncio.ensure_future(
            self._getaddrinfo_ipv4(host, port), loop=self._loop)
        ipv6_task = asyncio.ensure_future(
            self._getaddrinfo_ipv6(host, port), loop=self._loop)
        try:
            await asyncio.wait((ipv4_task, ipv6_task), loop=self._loop)
        except asyncio.CancelledError:
            ipv4_task.cancel()
            ipv6_task.cancel()
            raise
        exceptions = {}
        try:
            ipv4_addrinfo = ipv4_task.result()
        except aiodns.error.DNSError as e:
            ipv4_addrinfo = []
            exceptions['IPv4'] = e
        try:
            ipv6_addrinfo = ipv6_task.result()
        except aiodns.error.DNSError as e:
            ipv6_addrinfo = []
            exceptions['IPv6'] = e
        if ipv6_first:
            addrinfo = list(roundrobin(ipv6_addrinfo, ipv4_addrinfo))
        else:
            addrinfo = list(roundrobin(ipv4_addrinfo, ipv6_addrinfo))
        if not addrinfo:
            raise UpstreamConnectError(SOCKS5Reply.HOST_UNREACHABLE,
                                       'DNS resolution failed: %r' % exceptions)
        return addrinfo

    async def _resolve_and_cache(self, host, query_type,
                                 cache: AltDNSCachedResult):
        self._logger.debug('Making DNS %s request for %s', query_type, host)
        res = await self._resolver.query(host, query_type)
        addresses = [r.host for r in res]
        if not addresses:
            timeout = self.DEFAULT_TTL + self._loop.time()
        else:
            timeout = min(res[0].ttl, self.MAX_TTL) + self._loop.time()
        self._logger.debug('DNS %s request for %s results: %r',
                           query_type, host, addresses)
        cache.result = addresses
        cache.expiry = timeout
        return addresses

    async def _get_addresses(self, host, query_type, cache: AltDNSCachedResult):
        if cache.result is not None:
            assert cache.expiry is not None
            if cache.expiry > self._loop.time():
                self._logger.debug('Retrieved %s records for %s from cache',
                                   query_type, host)
                return cache.result
            else:
                cache.result = None
                self._logger.debug('Removed expired %s records for %s '
                                   'from cache', query_type, host)
        if cache.task is not None and not cache.task.done():
            self._logger.debug('Awaiting ongoing %s resolution task for %s',
                               query_type, host)
            return await cache.task
        else:
            self._logger.debug('Creating %s resolution task for %s',
                               query_type, host)
            cache.task = self._loop.create_task(
                self._resolve_and_cache(host, query_type, cache))
            return await cache.task

    async def _getaddrinfo_ipv4(self, host, port):
        addresses = await self._get_addresses(host, 'A', self._cache[host].ipv4)
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (addr, port))
                for addr in addresses]

    async def _getaddrinfo_ipv6(self, host, port):
        addresses = await self._get_addresses(host, 'AAAA',
                                              self._cache[host].ipv6)
        return [(socket.AF_INET6, socket.SOCK_STREAM, 0, '', (addr, port))
                for addr in addresses]


class DetourProxy:
    RELAY_BUFFER_SIZE = 2 ** 13
    NEXT_METHOD_DELAY = 3
    NEXT_SOCKET_DELAY = 1

    def __init__(self, listen_host, listen_port, upstream_host, upstream_port,
                 resolver: AltDNSResolver,
                 detour_whitelist: DetourTokenWhitelist,
                 *, ipv4_only=False, ipv6_only=False, ipv6_first=False,
                 loop: asyncio.AbstractEventLoop=None):
        self._upstream_host = upstream_host
        self._upstream_port = upstream_port
        self._resolver = resolver
        self._whitelist = detour_whitelist
        assert not (ipv4_only and ipv6_only)
        self._ipv4_only = ipv4_only
        self._ipv6_only = ipv6_only
        self._ipv6_first = ipv6_first
        self._loop = loop or asyncio.get_event_loop()

        self._logger = logging.getLogger('DetourProxy')
        self._dns_poison_ip = set()
        self._connections = WithSet()
        self._server = None
        self._server_task = loop.create_task(asyncio.start_server(
            self._server_handler, listen_host, listen_port, loop=loop))
        self._server_task.add_done_callback(self._server_done_callback)

    def _server_done_callback(self, fut):
        try:
            self._server = fut.result()
        except asyncio.CancelledError:
            self._logger.debug('start_server() cancelled')
        except Exception as e:
            self._logger.error('Creating server failed with %r', e,
                               exc_info=True)
        else:
            self._logger.info('DetourProxy listening on %r',
                              [s.getsockname() for s in self._server.sockets])

    def load_dns_poison_ip(self, ips):
        self._dns_poison_ip.update(ipaddress.ip_address(a) for a in ips)

    async def _open_connections_parallel(self, addrinfo_list, delay=None):
        if delay is None:
            delay = self.NEXT_SOCKET_DELAY
        pending = set()
        connected_sock = None
        exceptions = []
        remaining_addrs = list(reversed(addrinfo_list))
        self._logger.debug('Attempting to connect to one of: %r',
                           remaining_addrs)
        try:
            while True:
                while remaining_addrs:
                    sock = None
                    family, type_, proto, cname, addr = remaining_addrs.pop()
                    self._logger.debug('Attempting to connect to %r', addr)
                    try:
                        sock = socket.socket(family, type_, proto)
                        sock.setblocking(False)
                    except OSError as e:
                        self._logger.debug('Creating socket to %r failed: %r',
                                           addr, e)
                        exceptions.append(e)
                        # sock will be closed during `finally`
                    else:
                        self._logger.debug('Successfully created socket %r',
                                           sock)

                        async def connect_sock(sock=sock, addr=addr):
                            try:
                                await self._loop.sock_connect(sock, addr)
                                return sock
                            except:
                                sock.close()
                                raise

                        pending.add(self._loop.create_task(connect_sock()))
                        sock = None  # don't close this one during `finally`
                        break
                    finally:
                        if sock is not None:
                            sock.close()
                if remaining_addrs:
                    timeout = delay
                else:
                    timeout = None
                if pending:
                    done, pending = await asyncio.wait(
                        pending, loop=self._loop, timeout=timeout,
                        return_when=asyncio.FIRST_COMPLETED)
                    for d in done:
                        try:
                            sock = d.result()
                        except OSError as e:
                            self._logger.debug('Connecting one socket failed: '
                                               '%r', e)
                            exceptions.append(e)
                        else:
                            if not connected_sock:
                                self._logger.debug('Socket %r successfully '
                                                   'connected', sock)
                                connected_sock = sock
                            else:
                                self._logger.debug(
                                    'More than one socket connected '
                                    'successfully; closing extra socket %r',
                                    sock)
                                sock.close()
                if connected_sock:
                    break
                if (not remaining_addrs) and (not pending):
                    assert exceptions, 'all connections failed but no exception'
                    self._logger.info('All connect attempts failed: <%s>',
                                      ', '.join(repr(e) for e in exceptions))
                    raise exceptions[-1]

            while pending:
                pending.pop().cancel()

            self._logger.debug('Creating transport using socket %r',
                               connected_sock)
            return await asyncio.open_connection(
                loop=self._loop, limit=self.RELAY_BUFFER_SIZE,
                sock=connected_sock)
        except:
            if connected_sock is not None:
                connected_sock.close()
            for p in pending:
                p.cancel()
            raise

    def _map_exception_to_socks5_reply(self, exc):
        if isinstance(exc, OSError):
            if exc.errno == errno.ENETUNREACH:
                return SOCKS5Reply.NETWORK_UNREACHABLE
            elif exc.errno == errno.EHOSTUNREACH:
                return SOCKS5Reply.HOST_UNREACHABLE
            elif exc.errno == errno.ECONNREFUSED:
                return SOCKS5Reply.CONNECTION_REFUSED
            elif exc.errno == errno.ETIMEDOUT:
                return SOCKS5Reply.TTL_EXPIRED
        self._logger.warning('Unexpected exception', exc_info=True)
        return SOCKS5Reply.GENERAL_FAILURE

    async def _make_alt_dns_connection(self, uhost, uport,
                                       host_entry: DetourTokenHostEntry,
                                       need_token):
        assert not isinstance(
            uhost, (ipaddress.IPv4Address, ipaddress.IPv6Address)
        ), 'alt dns connection should not have ip address target'
        token = None
        if need_token:
            assert host_entry is not None, 'need_token but host_entry is None'
            token = host_entry.get_dns_token()
        addrinfo_list = await self._resolver.getaddrinfo(
            uhost, uport,
            ipv4_only=self._ipv4_only, ipv6_only=self._ipv6_only,
            ipv6_first=self._ipv6_first)
        if not addrinfo_list:
            raise UpstreamConnectError(SOCKS5Reply.HOST_UNREACHABLE,
                                       'DNS resolution result empty')
        if (host_entry is not None
            and not host_entry.tested_dns_poison
            and host_entry.stash_gai_result is not None):
            if any(ipaddress.ip_address(a[4][0]) in host_entry.stash_gai_result
                   for a in addrinfo_list):
                host_entry.report_dns_poison_test(False)
                raise UpstreamConnectError(
                    SOCKS5Reply.GENERAL_FAILURE,
                    'Alternative DNS resolution result overlaps with '
                    'native getaddrinfo() result')
            else:
                host_entry.report_dns_poison_test(None)
            host_entry.stash_gai_result = None
        try:
            r, w = await self._open_connections_parallel(addrinfo_list)
        except OSError as e:
            reply = self._map_exception_to_socks5_reply(e)
            raise UpstreamConnectError(reply) from e
        else:
            return r, w, token

    async def _make_direct_connection(self, uhost, uport,
                                      host_entry: DetourTokenHostEntry,
                                      need_token):
        assert not need_token, 'direct connection should not need_token'
        if isinstance(uhost, ipaddress.IPv4Address):
            if self._ipv6_only:
                raise UpstreamConnectError(
                    SOCKS5Reply.HOST_UNREACHABLE,
                    'Cannot connect to IPv4 address when ipv6_only is set')
            addrinfo_list = [(socket.AF_INET, socket.SOCK_STREAM, 0, '',
                              (uhost.compressed, uport))]
        elif isinstance(uhost, ipaddress.IPv6Address):
            if self._ipv4_only:
                raise UpstreamConnectError(
                    SOCKS5Reply.HOST_UNREACHABLE,
                    'Cannot connect to IPv6 address when ipv4_only is set')
            addrinfo_list = [(socket.AF_INET6, socket.SOCK_STREAM, 0, '',
                              (uhost.compressed, uport))]
        else:
            if self._ipv4_only:
                family = socket.AF_INET
            elif self._ipv6_only:
                family = socket.AF_INET6
            else:
                family = socket.AF_UNSPEC
            try:
                addrinfo_list = await self._loop.getaddrinfo(
                    uhost, uport, family=family, type=socket.SOCK_STREAM)
            except socket.gaierror as e:
                raise UpstreamConnectError(
                    SOCKS5Reply.HOST_UNREACHABLE, 'getaddrinfo failed') from e
            gai_ips = set(ipaddress.ip_address(a[4][0]) for a in addrinfo_list)
            if host_entry is not None:
                if not gai_ips.isdisjoint(self._dns_poison_ip):
                    host_entry.report_dns_poison_test(True)
                    raise UpstreamConnectError(SOCKS5Reply.HOST_UNREACHABLE,
                                               'DNS poisoning detected')
                else:
                    if not host_entry.tested_dns_poison:
                        host_entry.stash_gai_result = gai_ips
        try:
            r, w = await self._open_connections_parallel(addrinfo_list)
        except OSError as e:
            reply = self._map_exception_to_socks5_reply(e)
            raise UpstreamConnectError(reply) from e
        else:
            return r, w, None

    async def _make_detoured_connection(self, uhost, uport,
                                        host_entry: DetourTokenHostEntry,
                                        need_token):
        token = None
        if need_token:
            assert host_entry is not None, 'need_token but host_entry is None'
            token = host_entry.get_detour_token()
        try:
            r, w = await asyncio.open_connection(
                self._upstream_host, self._upstream_port,
                loop=self._loop, limit=self.RELAY_BUFFER_SIZE)
            try:
                await self._client_negotiate_socks5(uhost, uport, r, w)
            except:
                w.transport.abort()
                raise
        except (OSError, asyncio.IncompleteReadError) as e:
            self._logger.warning('Connecting to upstream proxy failed: %r', e)
            raise UpstreamConnectError(SOCKS5Reply.GENERAL_FAILURE) from e
        return r, w, token

    async def _client_negotiate_socks5(self, uhost, uport,
                                       ureader: asyncio.StreamReader,
                                       uwriter: asyncio.StreamWriter):
        self._logger.debug('Making upstream SOCKS5 connection to (%r, %r)',
                           uhost, uport)
        uwriter.write(b'\x05\x01' + SOCKS5AuthType.NO_AUTH)
        buf = await ureader.readexactly(2)
        if buf[0:1] != b'\x05':
            raise UpstreamConnectError(SOCKS5Reply.GENERAL_FAILURE,
                                       'Invalid upstream SOCKS5 auth reply')
        if buf[1:2] != SOCKS5AuthType.NO_AUTH:
            raise UpstreamConnectError(
                SOCKS5Reply.GENERAL_FAILURE,
                'Invalid upstream SOCKS5 auth type %r'
                % get_enum(SOCKS5AuthType, buf[1:2]))
        if isinstance(uhost, ipaddress.IPv4Address):
            addr = SOCKS5AddressType.IPV4_ADDRESS + uhost.packed
        elif isinstance(uhost, ipaddress.IPv6Address):
            addr = SOCKS5AddressType.IPV6_ADDRESS + uhost.packed
        else:
            addr = uhost.encode('idna')
            addr = (SOCKS5AddressType.DOMAIN_NAME
                    + len(addr).to_bytes(1, 'big') + addr)
        uwriter.write(b'\x05' + SOCKS5Command.CONNECT + b'\x00'
                      + addr + uport.to_bytes(2, 'big'))
        buf = await ureader.readexactly(4)
        if buf[0:1] != b'\x05' or buf[2:3] != b'\x00':
            raise UpstreamConnectError(
                SOCKS5Reply.GENERAL_FAILURE,
                'Invalid upstream SOCKS5 command response %r' % buf)
        try:
            reply = SOCKS5Reply(buf[1:2])
        except ValueError:
            raise UpstreamConnectError(
                SOCKS5Reply.GENERAL_FAILURE,
                'Invalid upstream SOCKS5 connect reply %r' % buf[1:2])
        if reply is not SOCKS5Reply.SUCCESS:
            raise UpstreamConnectError(
                reply, 'Upstream SOCKS5 server returned error %r' % reply)
        try:
            addr_type = SOCKS5AddressType(buf[3:4])
        except ValueError:
            raise UpstreamConnectError(
                SOCKS5Reply.GENERAL_FAILURE,
                'Invalid upstream SOCKS5 address type')
        if addr_type is SOCKS5AddressType.IPV4_ADDRESS:
            await ureader.readexactly(4 + 2)
        elif addr_type is SOCKS5AddressType.IPV6_ADDRESS:
            await ureader.readexactly(16 + 2)
        elif addr_type is SOCKS5AddressType.DOMAIN_NAME:
            buf = await ureader.readexactly(1)
            await ureader.readexactly(buf[0] + 2)
        self._logger.debug('Upstream SOCKS5 connection to (%r, %r) successful',
                           uhost, uport)

    async def _server_negotiate_socks5(self, initial_byte,
                                       dreader: asyncio.StreamReader,
                                       dwriter: asyncio.StreamWriter):
        assert initial_byte == b'\x05'
        log_name = '{!r} <=> ()'.format(
            dwriter.transport.get_extra_info('peername'))
        try:
            buf = await dreader.readexactly(1)  # number of auth methods
            buf = await dreader.readexactly(buf[0])  # offered auth methods
            if SOCKS5AuthType.NO_AUTH not in buf:
                self._logger.info('%s did not offer "no auth", offers: %r',
                                  log_name, buf)
                dwriter.write(b'\x05' + SOCKS5AuthType.NO_OFFERS_ACCEPTABLE)
                safe_write_eof(dwriter)
                await dwriter.drain()
                return None, None
            dwriter.write(b'\x05' + SOCKS5AuthType.NO_AUTH)

            # client command
            buf = await dreader.readexactly(4)  # ver, cmd, rsv, addr_type
            if buf[0] != 5 or buf[2] != 0:
                raise ServerHandlerError('%s malformed SOCKS5 command'
                                         % log_name)
            cmd = buf[1:2]
            addr_type = buf[3:4]
            if addr_type == SOCKS5AddressType.IPV4_ADDRESS:
                uhost = ipaddress.IPv4Address(
                    await dreader.readexactly(4))
            elif addr_type == SOCKS5AddressType.IPV6_ADDRESS:
                uhost = ipaddress.IPv6Address(
                    await dreader.readexactly(16))
            elif addr_type == SOCKS5AddressType.DOMAIN_NAME:
                buf = await dreader.readexactly(1)  # address len
                uhost = (await dreader.readexactly(buf[0])).decode('utf-8')
            else:
                raise ServerHandlerError('%s illegal address type' % log_name)
            try:
                uhost = ipaddress.ip_address(uhost)
            except ValueError:
                pass
            uport = int.from_bytes(await dreader.readexactly(2), 'big')
            log_name = '{!r} <=> ({!r}, {!r})'.format(
                dwriter.transport.get_extra_info('peername'),
                uhost, uport)
            self._logger.debug('%s parsed target address', log_name)
            if cmd != SOCKS5Command.CONNECT:
                self._logger.info('%s command %r not supported',
                                  log_name, cmd)
                await self._server_reply_socks5(
                    dwriter, SOCKS5Reply.COMMAND_NOT_SUPPORTED, INADDR_ANY, 0)
                return None, None
            self._logger.info('%s received CONNECT command', log_name)
            if self._ipv6_only:
                if addr_type == SOCKS5AddressType.IPV4_ADDRESS:
                    self._logger.info('%s cannot connect to IPv4 address '
                                      'while IPV6_ONLY set', log_name)
                    await self._server_reply_socks5(
                        dwriter, SOCKS5Reply.ADDRESS_TYPE_NOT_SUPPORTED,
                        INADDR_ANY, 0)
                    return None, None
            elif self._ipv4_only:
                if addr_type == SOCKS5AddressType.IPV6_ADDRESS:
                    self._logger.info('%s cannot connect to IPv6 address '
                                      'while IPV4_ONLY set', log_name)
                    await self._server_reply_socks5(
                        dwriter, SOCKS5Reply.ADDRESS_TYPE_NOT_SUPPORTED,
                        INADDR_ANY, 0)
                    return None, None
            return uhost, uport
        except (OSError, asyncio.IncompleteReadError) as e:
            raise ServerHandlerError from e

    async def _server_reply_socks5(self, dwriter: asyncio.StreamWriter,
                                   reply=None, host=None, port=None):
        if reply is None:
            reply = SOCKS5Reply.SUCCESS
        assert len(reply) == 1, 'invalid reply length'
        if host is None:
            host = INADDR_ANY
        if port is None:
            port = 0
        if isinstance(host, ipaddress.IPv4Address):
            b_addr = SOCKS5AddressType.IPV4_ADDRESS + host.packed
        elif isinstance(host, ipaddress.IPv6Address):
            b_addr = SOCKS5AddressType.IPV6_ADDRESS + host.packed
        else:
            b_addr = host.encode('idna')
            b_addr = (SOCKS5AddressType.DOMAIN_NAME
                      + len(b_addr).to_bytes(1, 'big') + b_addr)
        try:
            dwriter.write(b'\x05' + reply + b'\x00' +
                          b_addr + port.to_bytes(2, 'big'))
            if reply is not SOCKS5Reply.SUCCESS:
                safe_write_eof(dwriter)
            await dwriter.drain()
        except OSError as e:
            raise ServerHandlerError from e

    async def _server_reply_http_stub(self, initial_byte,
                                      dreader: asyncio.StreamReader,
                                      dwriter: asyncio.StreamWriter):
        log_name = '{!r} <=> ()'.format(
            dwriter.transport.get_extra_info('peername'))
        self._logger.info('%s Received HTTP request, replying with stub',
                          log_name)
        body = b'''<!doctype html>
<html lang=en>
<head>
<meta charset=utf8>
<title>DetourProxy is not an HTTP proxy</title>
</head>
<body>
<h1>403 Forbidden</h1>
<p>DetourProxy is not an HTTP proxy. Please configure your browser to use
DetourProxy as a SOCKS5 proxy instead.
'''
        response = b'\r\n'.join([
            b'HTTP/1.1 403 Forbidden',
            b'Content-Type: text/html;charset=utf-8',
            b'Content-Length: ' + str(len(body)).encode('utf-8'),
            b'Connection: close',
            b'',
            body
        ])
        try:
            dwriter.write(response)
            safe_write_eof(dwriter)
            await dwriter.drain()
            return None, None
        except OSError as e:
            raise ServerHandlerError from e

    async def _server_handler(self, dreader: asyncio.StreamReader,
                              dwriter: asyncio.StreamWriter):
        log_name = '{!r} <=> ()'.format(
            dwriter.transport.get_extra_info('peername'))

        try:  # catch, log and suppress all exceptions in outermost layer
            with ExitStack() as stack:
                stack.enter_context(self._connections.with_this(
                    asyncio.Task.current_task()))
                stack.enter_context(finally_close(dwriter))
                self._logger.debug('%s accepted downstream connection',
                                   log_name)
                try:
                    initial_byte = await dreader.readexactly(1)
                except (OSError, asyncio.IncompleteReadError) as e:
                    raise ServerHandlerError from e
                if initial_byte == b'\x05':
                    uhost, uport = await self._server_negotiate_socks5(
                        initial_byte, dreader, dwriter)
                elif b'A' <= initial_byte <= b'Z':
                    uhost, uport = await self._server_reply_http_stub(
                        initial_byte, dreader, dwriter)
                else:
                    raise ServerHandlerError('%s unknown protocol' % log_name)

                if uhost is None or uport is None:
                    return
                log_name = '{!r} <=> ({!r}, {!r})'.format(
                    dwriter.transport.get_extra_info('peername'),
                    uhost, uport)

                connections, host_entry = self._whitelist.match_host(uhost)
                self._logger.debug('%s connections: %r', log_name, connections)
                pending = set()
                task_to_conn_type = dict()
                fail_reasons = []
                ureader = uwriter = None
                connected_type = connected_token = None

                try:
                    while not uwriter and connections:
                        delay_fut = None
                        timed_out = False

                        conn_type, need_token = connections.pop()
                        if conn_type is ConnectionType.DIRECT:
                            connector = self._make_direct_connection
                        elif conn_type is ConnectionType.ALTDNS:
                            connector = self._make_alt_dns_connection
                        elif conn_type is ConnectionType.DETOUR:
                            connector = self._make_detoured_connection
                        else:
                            assert False, 'Illegal connection type'

                        if connections:
                            delay_fut = asyncio.ensure_future(asyncio.sleep(
                                self.NEXT_METHOD_DELAY, loop=self._loop),
                                loop=self._loop)
                            pending.add(delay_fut)

                        connect_fut = asyncio.ensure_future(connector(
                            uhost, uport, host_entry, need_token))
                        pending.add(connect_fut)
                        task_to_conn_type[connect_fut] = conn_type
                        self._logger.info('%s try %s', log_name, conn_type)
                        while uwriter is None and not timed_out and pending:
                            # if only the timeout task remains, break
                            if len(pending) == 1 and delay_fut in pending:
                                pending.discard(delay_fut)
                                delay_fut.cancel()
                                break
                            done, pending = await asyncio.wait(
                                pending, loop=self._loop,
                                return_when=asyncio.FIRST_COMPLETED)
                            for d in done:
                                if d is delay_fut:
                                    timed_out = True
                                    continue
                                this_conn_type = task_to_conn_type[d]
                                try:
                                    res = d.result()
                                except UpstreamConnectError as e:
                                    self._logger.info(
                                        '%s %s error during connect: '
                                        '<%r> caused by <%r>',
                                        log_name, this_conn_type,
                                        e, e.__cause__)
                                    # connect_exceptions.append(e)
                                    fail_reasons.append(e.args[0])
                                    continue
                                if uwriter is None:
                                    self._logger.info(
                                        '%s connection %s successful',
                                        log_name, this_conn_type)
                                    ureader, uwriter, connected_token = res
                                    stack.enter_context(
                                        finally_close(uwriter))
                                    connected_type = this_conn_type
                                else:
                                    self._logger.info(
                                        '%s connection %r also successful, '
                                        'closing', log_name, this_conn_type)
                                    res[1].close()
                finally:
                    for p in pending:
                        p.cancel()
                if uwriter is None:
                    assert fail_reasons
                    concrete_counter = Counter(
                        r for r in fail_reasons
                        if r is not SOCKS5Reply.GENERAL_FAILURE)
                    if concrete_counter:
                        reply = concrete_counter.most_common(1)[0][0]
                    else:
                        reply = SOCKS5Reply.GENERAL_FAILURE
                    await self._server_reply_socks5(dwriter, reply,
                                                    INADDR_ANY, 0)
                    return

                bind_host, bind_port = uwriter.transport.get_extra_info(
                    'sockname')[:2]
                try:
                    bind_host = ipaddress.ip_address(bind_host)
                except ValueError:
                    pass
                await self._server_reply_socks5(dwriter, SOCKS5Reply.SUCCESS,
                                                bind_host, bind_port)

                log_name = '{!r} <=> ({!r}, {!r}) [{}]'.format(
                    dwriter.transport.get_extra_info('peername'),
                    uhost, uport, connected_type)
                try:
                    await self._relay_data(dreader, dwriter,
                                           ureader, uwriter,
                                           (uhost, uport))
                except UpstreamRelayError as e:
                    self._logger.info(
                        '%s upstream relay error: <%r> caused by <%r>',
                        log_name, e, e.__cause__)
                    if host_entry is not None:
                        host_entry.report_relay_failure(connected_type)
                    return
                self._logger.info('%s completed normally',
                                  log_name)
                if host_entry is not None:
                    host_entry.report_relay_success(connected_type,
                                                    connected_token)
                return
        except asyncio.CancelledError:
            self._logger.debug('%s cancelled', log_name)
            raise
        except (UpstreamRelayError,
                RelayError,
                UpstreamConnectError,
                ServerHandlerError,
                ) as e:
            # not logging stack trace for normal errors
            self._logger.info('%s Exception: <%r> caused by <%r> ',
                              log_name, e, e.__cause__)
        except Exception as e:
            self._logger.error('%s %r', log_name, e, exc_info=True)
        finally:
            self._logger.debug('%s connection done', log_name)

    async def _relay_data_side(self, reader, writer,
                               log_name, write_is_upstream):
        bytes_relayed = 0
        try:
            while True:
                try:
                    buf = await reader.read(self.RELAY_BUFFER_SIZE)
                except OSError as e:
                    if not write_is_upstream:
                        raise UpstreamRelayError from e
                    else:
                        raise
                if not buf:
                    break
                self._logger.debug('%s received data', log_name)
                try:
                    writer.write(buf)
                    await writer.drain()
                except OSError as e:
                    if write_is_upstream:
                        raise UpstreamRelayError from e
                    else:
                        raise
                self._logger.debug('%s sent data', log_name)
                bytes_relayed += len(buf)
            self._logger.debug('%s received EOF', log_name)
            try:
                safe_write_eof(writer)
                await writer.drain()
            except OSError as e:
                if write_is_upstream:
                    raise UpstreamRelayError from e
                else:
                    raise
            self._logger.debug('%s wrote EOF', log_name)
            return bytes_relayed
        except asyncio.CancelledError:
            self._logger.debug('%s cancelled', log_name)
            raise
        except OSError as e:
            self._logger.debug('%s got OSError: %r', log_name, e)
            raise RelayError from e
            # except Exception as e:
            #     self._logger.info('%s got exception: %r', log_name, e)
            #     raise

    async def _relay_data(self,
                          dreader: asyncio.StreamReader,
                          dwriter: asyncio.StreamWriter,
                          ureader: asyncio.StreamReader,
                          uwriter: asyncio.StreamWriter,
                          uname):
        dname = dwriter.transport.get_extra_info('peername')
        utask = self._loop.create_task(self._relay_data_side(
            dreader, uwriter, '{!r} --> {!r}'.format(dname, uname), True))
        dtask = self._loop.create_task(self._relay_data_side(
            ureader, dwriter, '{!r} <-- {!r}'.format(dname, uname), False))
        try:
            u_bytes_relayed, d_bytes_relayed = await asyncio.gather(
                utask, dtask, loop=self._loop)
            if u_bytes_relayed and not d_bytes_relayed:
                raise UpstreamRelayError('Upstream server did not send data')
        except:
            dwriter.transport.abort()
            uwriter.transport.abort()
            dtask.cancel()
            utask.cancel()
            raise

    async def close(self):
        """Terminate the server and all active connections."""
        self._logger.info('DetourProxy closing')
        wait_list = []
        self._server_task.cancel()
        wait_list.append(self._server_task)
        if self._server is not None:
            self._server.close()
            wait_list.append(self._server.wait_closed())
        for conn in self._connections:
            conn.cancel()
            wait_list.append(conn)
        # wait_list.extend(self._connections)
        await asyncio.gather(*wait_list, return_exceptions=True)


def windows_async_signal_helper(loop, interval=0.2):
    """Schedule a do-nothing regular callback on Windows only.

    This is a workaround for Python Issue 23057 in Windows
    ( https://bugs.python.org/issue23057 ), where signals like
    KeyboardInterrupt will not be delivered in an event loop if nothing
    is happening. A regular callback allows such signals to be
    delivered.
    """
    if sys.platform == 'win32':
        noop_callback(loop, interval)


def noop_callback(loop, delay):
    """Do nothing and schedule to do nothing later."""
    loop.call_later(delay, noop_callback, loop, delay)


def sigterm_handler(sig, frame):
    logging.warning('Received signal %r', sig)
    sys.exit(0)


def relay():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='Automatically divert connections to censored sites '
                    'through a proxy.')
    parser.add_argument(
        'proxy',
        help='Host name / IP address of the upstream proxy server.')
    parser.add_argument(
        'proxy_port', nargs='?', type=int, default=1080,
        help='Port number of the upstream proxy server.')
    parser.add_argument(
        '--bind', '-b', default='127.0.0.1',
        help='Host name / IP address to bind to.')
    parser.add_argument(
        '--bind-port', '-p', type=int, default=1080,
        help='Port number to bind to.')
    parser.add_argument(
        '--dns', '-D', default='8.8.8.8',
        help='IP address of the safe DNS server. A server unaffected by '
             'censorship and/or poisoning should be used.')
    parser.add_argument(
        '--dns-port', '-P', type=int, default=53,
        help='Port number of the safe DNS server.')
    parser.add_argument(
        '--dns-tcp', '-T', action='store_true',
        help='Use TCP instead of UDP for safe DNS. ')
    parser.add_argument(
        '--state', '-s', default='state.csv',
        help='Path to the "state file" which stores information learned about '
             'censored sites. Relative paths are relative to the working '
             'directory.')
    parser.add_argument(
        '--persistent', '-e',
        help='Path to the "persistent rules file", which describes sites that '
             'should always use a particular connection method. If '
             'unspecified, will try to load "persistent.txt" from the working '
             'directory.')
    parser.add_argument(
        '--dns-poison-ip',
        help='Path to "poisoned IP list" file, which stores a list of IP '
             'addresses known to be returned by the poisoned DNS responses. If '
             'unspecified, will try to load "dns_poison_list.txt" from the '
             'same directory as the script.')
    ip_version_group = parser.add_mutually_exclusive_group()
    ip_version_group.add_argument(
        '--ipv4-only', '-4', action='store_true',
        help='Restrict most network actions to IPv4 only.')
    ip_version_group.add_argument(
        '--ipv6-only', '-6', action='store_true',
        help='Restrict most network actions to IPv6 only.')
    parser.add_argument(
        '--ipv6-first', action='store_true',
        help='Prioritize IPv6 in most network actions.')
    parser.add_argument(
        '--verbose', '-v', action='count',
        help='Increase output verbosity. Specify once for INFO, twice for '
             'DEBUG.')
    parser.add_argument(
        '--log',
        help='Path to log file.')

    args = parser.parse_args()

    rootlogger = logging.getLogger()
    if not args.verbose:
        log_level = logging.WARNING
    elif args.verbose == 1:
        log_level = logging.INFO
    else:
        log_level = logging.DEBUG
    rootlogger.setLevel(log_level)
    stream_formatter = logging.Formatter('%(levelname)-8s %(name)s %(message)s')
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(stream_formatter)
    rootlogger.addHandler(stream_handler)

    if args.log:
        file_formatter = logging.Formatter(
            '%(asctime)s %(levelname)-8s %(name)s %(funcName)s %(message)s')
        file_handler = logging.FileHandler(args.debug_log)
        file_handler.setFormatter(file_formatter)
        rootlogger.addHandler(file_handler)

    # logging.getLogger('asyncio').setLevel(logging.INFO)
    # logging.getLogger('DetourProxy').setLevel(logging.DEBUG)
    logging.captureWarnings(True)
    warnings.filterwarnings('always')

    if WINDOWS_USE_PROACTOR_EVENT_LOOP and sys.platform == 'win32':
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)
    else:
        loop = asyncio.get_event_loop()
    # loop.set_debug(True)

    whitelist = DetourTokenWhitelist()
    persistent_path = args.persistent or 'persistent.txt'
    try:
        with open(persistent_path, 'rt') as f:
            whitelist.load_persistent_list(f)
    except OSError as e:
        logging.warning('loading persistent file failed: %r', e)
        if args.persistent:
            raise
    else:
        logging.info('persistent file loaded')
    try:
        whitelist.load_state_file(args.state)
    except OSError as e:
        logging.warning('loading state file failed: %r', e)
    else:
        logging.info('state file loaded')

    resolver = AltDNSResolver([args.dns], loop,
                              use_tcp=args.dns_tcp,
                              udp_port=args.dns_port,
                              tcp_port=args.dns_port)

    proxy = DetourProxy(args.bind, args.bind_port, args.proxy, args.proxy_port,
                        resolver, whitelist,
                        ipv4_only=args.ipv4_only, ipv6_only=args.ipv6_only,
                        ipv6_first=args.ipv6_first, loop=loop)
    dns_poison_path = args.dns_poison_ip or DEFAULT_DNS_POISON_FILE
    try:
        with open(dns_poison_path, 'rt') as dpf:
            proxy.load_dns_poison_ip(l.strip() for l in dpf)
    except OSError as e:
        logging.warning('loading DNS poison IP list failed: %r', e)
        if args.dns_poison_ip:
            raise
    else:
        logging.info('DNS poison IP list loaded')

    windows_async_signal_helper(loop)
    try:
        loop.add_signal_handler(signal.SIGINT, sigterm_handler)
        loop.add_signal_handler(signal.SIGTERM, sigterm_handler)
    except NotImplementedError:
        pass
    try:
        loop.run_forever()
    except (SystemExit, KeyboardInterrupt) as e:
        logging.warning('Received %r', e)
        loop.run_until_complete(proxy.close())
    finally:
        whitelist.dump_state_file(args.state)
        loop.close()


if __name__ == '__main__':
    relay()
