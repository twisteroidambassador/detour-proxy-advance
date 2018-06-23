#! /usr/bin/env python3

# Copyright 2017, 2018 twisteroid ambassador

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
import enum
import errno
import ipaddress
import itertools
import logging
import os.path
import random
import signal
import socket
import sys
import time
import warnings
from collections import defaultdict, Counter, namedtuple, OrderedDict
from contextlib import ExitStack, contextmanager, suppress
from functools import partial
from typing import Dict, Union, Tuple, List, Iterable, Callable, Any, \
    Optional, Awaitable

import dns
import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype

# ========== Configuration section ==========
DEFAULT_DNS_POISON_FILE = os.path.join(
    os.path.dirname(__file__), 'dns_poison_list.txt')

# Use ProactorEventLoop instead of SelectorEventLoop if (1) we're running on
# Windows, and (2) not using UDP for DNS. ProactorEventLoop is supposed to have
# better performance, but it seems to be more buggy as well.
WINDOWS_USE_PROACTOR_EVENT_LOOP = True

# When negotiating SOCKS5 with the downstream client, return a fake IPv4
# address / port instead of the actual bound address / port. This may help
# when the bound address is an IPv6 address and the downstream client does
# not support parsing anything but an IPv4 address: certain versions of
# Privoxy and Polipo are known to have this problem.
SOCKS5_RETURN_FAKE_BIND_ADDR = False

# When negotiating SOCKS5 with the upstream proxy, do not wait for the server
# to confirm our choice of "no authentication" and send our CONNECT command
# preemptively. This violates RFC 1928 and may potentially make proxy servers
# freak out, but saves one RTT during connection creation.
SOCKS5_PREEMPTIVE_COMMAND = True

# Maximum amount of time (in seconds) a DNS resolution result will be cached.
# Set None for no maximum.
RESOLVER_CACHE_MAX_TTL = 60 * 60
# ========== End of configuration section ==========

INADDR_ANY = ipaddress.IPv4Address(0)
SOCKS4A_INVALID_IP = ipaddress.IPv4Network('0.0.0.0/24')

IPAddressType = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
HostType = Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]

WINDOWS = sys.platform == 'win32'


def monkey_patch_write_eof():
    """Work around https://bugs.python.org/issue31647

    The proper fix should be in place for Python 3.7.0 and 3.6.6.
    """
    if sys.version_info < (3, 6, 6):
        import asyncio.selector_events
        SST = asyncio.selector_events._SelectorSocketTransport
        original_write_eof = SST.write_eof

        def write_eof(self):
            if self._closing:
                return
            original_write_eof(self)

        SST.write_eof = write_eof


monkey_patch_write_eof()


def roundrobin(*iterables, _sentinel=object()):
    """roundrobin('ABC', 'D', 'EF') --> A D E B F C"""
    return (e for e in itertools.chain.from_iterable(itertools.zip_longest(
        *iterables, fillvalue=_sentinel)) if e is not _sentinel)


# See implementation of current_task() in async-timeout; this does not
# include a tokio-specific hack
if sys.version_info >= (3, 7):
    # Python 3.7 deprecates asyncio.Task.current_task()
    current_task = asyncio.current_task
else:
    current_task = asyncio.Task.current_task


# The following adapted from async-timeout by Andrew Svetlov, licensed Apache2
class Timeout:
    """timeout context manager.

    Useful in cases when you want to apply timeout logic around block
    of code or in cases when asyncio.wait_for is not suitable.

    timeout - value in seconds or None to disable timeout logic
    raise_timeouterror - whether to raise TimeoutError when timed out
    loop - asyncio compatible event loop
    """

    def __init__(self, timeout, raise_timeouterror=True, *, loop=None):
        self._timeout = timeout
        self._raise = raise_timeouterror
        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
        self._task = None
        self._cancelled = False
        self._cancel_handler = None
        self._cancel_at = None

    def cancel_timeout(self):
        if self._timeout is not None and self._cancel_handler is not None:
            self._cancel_handler.cancel()
            self._cancel_handler = None

    def _cancel_task(self):
        self._task.cancel()
        self._cancelled = True

    async def __aenter__(self):
        # Support Tornado 5- without timeout
        # Details: https://github.com/python/asyncio/issues/392
        if self._timeout is None:
            return self

        self._task = current_task(loop=self._loop)
        if self._task is None:
            raise RuntimeError('Timeout context manager should be used '
                               'inside a task')

        if self._timeout <= 0:
            self._loop.call_soon(self._cancel_task)
            return self

        self._cancel_at = self._loop.time() + self._timeout
        self._cancel_handler = self._loop.call_at(
            self._cancel_at, self._cancel_task)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is asyncio.CancelledError and self._cancelled:
            self._cancel_handler = None
            self._task = None
            if self._raise:
                raise asyncio.TimeoutError
            return True  # suppress exception
        self.cancel_timeout()
        self._task = None


class BytesEnum(bytes, enum.Enum):
    pass


class SOCKS5AuthType(BytesEnum):
    NO_AUTH = b'\x00'
    GSSAPI = b'\x01'
    USERNAME_PASSWORD = b'\x02'
    NO_OFFERS_ACCEPTABLE = b'\xff'


class SOCKS5Command(BytesEnum):
    CONNECT = b'\x01'
    BIND = b'\x02'
    UDP_ASSOCIATE = b'\x03'


class SOCKS5AddressType(BytesEnum):
    IPV4_ADDRESS = b'\x01'
    DOMAIN_NAME = b'\x03'
    IPV6_ADDRESS = b'\x04'


class SOCKS5Reply(BytesEnum):
    SUCCESS = b'\x00'
    GENERAL_FAILURE = b'\x01'
    CONNECTION_NOT_ALLOWED_BY_RULESET = b'\x02'
    NETWORK_UNREACHABLE = b'\x03'
    HOST_UNREACHABLE = b'\x04'
    CONNECTION_REFUSED = b'\x05'
    TTL_EXPIRED = b'\x06'
    COMMAND_NOT_SUPPORTED = b'\x07'
    ADDRESS_TYPE_NOT_SUPPORTED = b'\x08'


class SOCKS4Command(BytesEnum):
    CONNECT = b'\x01'
    BIND = b'\x02'


class SOCKS4Reply(BytesEnum):
    GRANTED = b'\x5A'
    REJECTED_FAILED = b'\x5B'
    NO_IDENTD = b'\x5C'
    IDENTD_MISMATCH = b'\x5D'


@contextmanager
def finally_close(writer: asyncio.StreamWriter):
    """Closes writer on normal context exit and aborts on exception.

    This is Better^{TM} than contextlib.closing because of the additional
    abort thing.
    """
    try:
        yield
    except Exception:
        writer.transport.abort()
        raise
    finally:
        writer.close()


# https://github.com/twisteroidambassador/async_stagger
async def staggered_race(
        coro_fns: Iterable[Callable[[], Awaitable]],
        delay: Optional[float],
        *,
        loop: asyncio.AbstractEventLoop = None,
) -> Tuple[
    Any,
    Optional[int],
    List[Optional[Exception]]
]:
    """Run coroutines with staggered start times and take the first to finish.

    This method takes an iterable of coroutine functions. The first one is
    started immediately. From then on, whenever the immediately preceding one
    fails (raises an exception), or when *delay* seconds has passed, the next
    coroutine is started. This continues until one of the coroutines complete
    successfully, in which case all others are cancelled, or until all
    coroutines fail.

    Args:
        coro_fns: an iterable of coroutine functions, i.e. callables that
            return a coroutine object when called. Use ``functools.partial`` or
            lambdas to pass arguments.

        delay: amount of time, in seconds, between starting coroutines. If
            ``None``, the coroutines will run sequentially.

        loop: the event loop to use.

    Returns:
        tuple *(winner_result, winner_index, exceptions)* where

        - *winner_result*: the result of the winning coroutine, or ``None``
          if no coroutines won.

        - *winner_index*: the index of the winning coroutine in
          ``coro_fns``, or ``None`` if no coroutines won. If the winning
          coroutine may return None on success, *winner_index* can be used
          to definitively determine whether any coroutine won.

        - *exceptions*: list of exceptions returned by the coroutines.
          ``len(exceptions)`` is equal to the number of coroutines actually
          started, and the order is the same as in ``coro_fns``. The winning
          coroutine's entry is ``None``.

    """
    loop = loop or asyncio.get_event_loop()
    enum_coro_fns = enumerate(coro_fns)
    winner_result = None
    winner_index = None
    exceptions = []
    tasks = []

    async def run_one_coro(previous_failed: Optional[asyncio.Event]) -> None:
        # Wait for the previous task to finish, or for delay seconds
        if previous_failed is not None:
            with suppress(asyncio.TimeoutError):
                # Use asyncio.wait_for() instead of asyncio.wait() here, so
                # that if we get cancelled at this point, Event.wait() is also
                # cancelled, otherwise there will be a "Task destroyed but it is
                # pending" later.
                await asyncio.wait_for(previous_failed.wait(), delay)
        # Get the next coroutine to run
        try:
            this_index, coro_fn = next(enum_coro_fns)
        except StopIteration:
            return
        # Start task that will run the next coroutine
        this_failed = asyncio.Event()
        next_task = loop.create_task(run_one_coro(this_failed))
        tasks.append(next_task)
        assert len(tasks) == this_index + 2
        # Prepare place to put this coroutine's exceptions if not won
        exceptions.append(None)
        assert len(exceptions) == this_index + 1

        try:
            result = await coro_fn()
        except Exception as e:
            exceptions[this_index] = e
            this_failed.set()  # Kickstart the next coroutine
        else:
            # Store winner's results
            nonlocal winner_index, winner_result
            assert winner_index is None
            winner_index = this_index
            winner_result = result
            # Cancel all other tasks. We take care to not cancel the current
            # task as well. If we do so, then since there is no `await` after
            # here and CancelledError are usually thrown at one, we will
            # encounter a curious corner case where the current task will end
            # up as done() == True, cancelled() == False, exception() ==
            # asyncio.CancelledError.
            # https://bugs.python.org/issue30048
            for i, t in enumerate(tasks):
                if i != this_index:
                    t.cancel()

    first_task = loop.create_task(run_one_coro(None))
    tasks.append(first_task)
    try:
        # Wait for a growing list of tasks to all finish: poor man's version of
        # curio's TaskGroup or trio's nursery
        done_count = 0
        while done_count != len(tasks):
            done, _ = await asyncio.wait(tasks)
            done_count = len(done)
            # If run_one_coro raises an unhandled exception, it's probably a
            # programming error, and I want to see it.
            if __debug__:
                for d in done:
                    if d.done() and not d.cancelled() and d.exception():
                        raise d.exception()
        return winner_result, winner_index, exceptions
    finally:
        # Make sure no tasks are left running if we leave this function
        for t in tasks:
            t.cancel()


class ExceptionCausePrinter:
    """Makes printing the cause(s) of an exception easier."""

    def __init__(self, exc: Exception):
        self.exc = exc

    def __str__(self):
        exc = self.exc
        out = [str(exc)]
        while exc.__cause__:
            exc = exc.__cause__
            out.append('caused by')
            out.append(str(exc))
        return ' '.join(out)

    def __repr__(self):
        exc = self.exc
        out = ['<', repr(exc), '>']
        while exc.__cause__:
            exc = exc.__cause__
            out.append(' caused by <')
            out.append(repr(exc))
            out.append('>')
        return ''.join(out)


class DetourException(Exception):
    """Base exception for this script."""
    pass


class UpstreamConnectionError(DetourException):
    """Error while connecting to the destination."""
    pass


class DownstreamNegotiationError(DetourException):
    """Error while negotiating with downstream clients."""
    pass


class RelayError(DetourException):
    """Network error while relaying."""
    pass


class UpstreamRelayError(RelayError):
    """Network error in the upstream connection while relaying."""
    pass


class SOCKS5Error(DetourException):
    """SOCKS5 proxy server returned an error.

    args should be (socks5_reply_reason, human_readable_reason).
    socks5_reply_reason should be a SOCKS5Reply instance.
    """
    pass


class ConnectionType(enum.Enum):
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
    __slots__ = [
        '_is_ip_address', 'try_direct', 'try_altdns',
        'tested_dns_poison', 'stash_gai_result',
        '_last_detour_token', '_pending_detour_tokens', 'detour_tokens',
        '_last_dns_token', '_pending_dns_tokens', 'dns_tokens',
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
        timenow = self._time_now()
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

    def _time_now(self):
        return time.monotonic()

    def _reset_test_dns_poison(self):
        assert not self._is_ip_address
        self.try_direct = True
        self.try_altdns = not self._is_ip_address
        self.tested_dns_poison = self._is_ip_address
        self.stash_gai_result = None

    def _relearn(self):
        # give each connection type one chance
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
        poisoned = None: inconclusive.
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
        """Generate a list of connection types to try for this host.

        Returns a list of (connection_type, needs_token) .
        """
        if random.random() < self.RELEARN_PROBABILITY:
            self._relearn()
        if ((not self.try_direct and not self.try_altdns)
                or self.detour_tokens >= self.DETOUR_TOKEN_COUNT):
            return [(ConnectionType.DETOUR, False)]
        # at this point:
        # self.try_direct or self.try_altdns == True
        connections = [(ConnectionType.DETOUR, True)]
        timenow = self._time_now()
        if self._next_request_activates_temp_detour:
            self._temp_detour_timestamp = timenow
            self._next_request_activates_temp_detour = False
            return connections
        if timenow - self._temp_detour_timestamp < self.TEMP_SUSTAIN:
            return connections
        if not self.try_direct or self.dns_tokens >= self.DETOUR_TOKEN_COUNT:
            connections.insert(0, (ConnectionType.ALTDNS, False))
            return connections
        # at this point:
        # self.try_direct == True,
        # so self.try_altdns is undetermined
        if self.try_altdns:
            assert not self._is_ip_address
            connections.insert(0, (ConnectionType.ALTDNS, True))
        if self._next_request_activates_temp_dns:
            self._temp_dns_timestamp = timenow
            self._next_request_activates_temp_dns = False
            return connections
        if timenow - self._temp_dns_timestamp < self.TEMP_SUSTAIN:
            return connections
        connections.insert(0, (ConnectionType.DIRECT, False))
        return connections

    def report_relay_failure(self, conn_type):
        """Report that relaying encountered an upstream error.

        This means that the connection was established successfully, but then
        an error in the upstream direction closed the connection abnormally. In
        this case, the same connection method will be skipped temporarily.
        """
        if conn_type is ConnectionType.DIRECT:
            if self.try_altdns:
                self._next_request_activates_temp_dns = True
            else:
                self._next_request_activates_temp_detour = True
        elif conn_type is ConnectionType.ALTDNS:
            self._next_request_activates_temp_detour = True

    def report_relay_success(self, conn_type, token):
        """Report that relaying was successful.

        This means that the connection closed gracefully after data was
        transmitted.
        """
        if conn_type is ConnectionType.DIRECT:
            assert token is None
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
        timenow = self._time_now()
        if timenow - self._last_detour_token < self.TOKEN_SUSTAIN:
            return self._last_detour_token
        self._pending_detour_tokens.add(timenow)
        return timenow

    def get_dns_token(self):
        assert not self._is_ip_address
        timenow = self._time_now()
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
        assert not self._is_ip_address
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
        assert not self._is_ip_address
        if self.dns_tokens > 0:
            self.dns_tokens -= 1
            return
        if self._pending_dns_tokens:
            self._pending_dns_tokens.pop()


class DetourTokenWhitelist:
    """Manages persistent and learned connection information for all hosts."""

    def __init__(self):
        self._hosts = defaultdict(
            DetourTokenHostEntry
        )  # type: Dict[dns.name.Name, DetourTokenHostEntry]
        self._ips = defaultdict(
            partial(DetourTokenHostEntry, is_ip_address=True)
        )  # type: Dict[IPAddressType, DetourTokenHostEntry]
        self._persistent = dict()
        self._persistent_ip = dict()
        self._logger = logging.getLogger('detour.whitelist')

    def match_host(self, host) \
            -> Tuple[List, Union[DetourTokenHostEntry, None]]:
        """Get info host name / IP address, matching parents when necessary.

        Returns (connections, host_entry).
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
        else:
            try:
                host = dns.name.from_text(host)
            except dns.exception.DNSException as e:
                raise ValueError('Invalid host name') from e
            match_host = host
            while True:
                if match_host in self._persistent:
                    conn_type = self._persistent[match_host]
                    self._logger.info('%r matched %r in persistent list, '
                                      'state %r', host, match_host, conn_type)
                    return [(conn_type, False)], None
                else:
                    try:
                        match_host = match_host.parent()
                    except dns.name.NoParent:
                        break
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
                self._logger.warning(
                    'Invalid connection type in persistent file line "%s": %r',
                    line, e)
                continue
            try:
                ip = ipaddress.ip_network(host)
            except ValueError:
                try:
                    hostname = dns.name.from_text(host)
                except dns.exception.DNSException as e:
                    self._logger.warning(
                        'Invalid host name in persistent file line "%s": %r',
                        line, e)
                    continue
                self._persistent[hostname] = connection
            else:
                self._persistent_ip[ip] = connection

    def load_state_file(self, filepath):
        with open(filepath, 'rt', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for record in reader:
                try:
                    ip = ipaddress.ip_address(record['host'])
                except ValueError:
                    try:
                        host = dns.name.from_text(record['host'])
                    except dns.exception.DNSException as e:
                        self._logger.warning(
                            'Invalid host name in state file record %r: %r',
                            record, e)
                        continue
                    host_entry = self._hosts[host]
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
                    state['host'] = host.to_unicode(omit_final_dot=True)
                    writer.writerow(state)
            for ip, host_entry in self._ips.items():
                state = host_entry.dump()
                if state['detour_tokens']:
                    state['tested_dns_poison'] = 0
                    state['try_direct'] = 1
                    state['try_altdns'] = 0
                    state['host'] = ip.compressed
                    writer.writerow(state)


CacheEntry = namedtuple('CacheEntry', ['answer', 'expiry'])


class ResolverCache:
    """Cache DNS resolution results, and combine concurrent queries.

    Resolution results are cached according to their ttl. When multiple queries
    for the same host are requested, only one query will be sent, and the result
    is duplicated for all requests.
    """

    def __init__(self, *, max_ttl=None, prune_interval=60, loop=None):
        self._loop = loop or asyncio.get_event_loop()
        self._max_ttl = max_ttl
        self._prune_interval = prune_interval

        self._logger = logging.getLogger('detour.dns.cache')
        self._cache = dict()
        self._last_pruned = self._loop.time()

    def _prune(self):
        self._logger.debug('Pruning cache')
        for host in list(self._cache.keys()):
            entry = self._cache[host]
            if isinstance(entry, CacheEntry):
                if entry.expiry < self._loop.time():
                    del self._cache[host]
        self._last_pruned = self._loop.time()

    def _maybe_prune(self):
        if self._last_pruned + self._prune_interval < self._loop.time():
            self._prune()

    async def get_cache_or_query(self, key, query_coro, *args):
        """Retrieve answer for key if cached, else retrieve using query_coro.

        If the answer for key is already cached, return it.
        If key is being queried right now, wait until the query is done
        and return the answer.
        Else, call query_coro(*args) to get the answer and potentially cache it.

        query_coro should return (answer, ttl).
        """
        self._maybe_prune()
        if key in self._cache:
            cache_entry = self._cache[key]
            if not isinstance(cache_entry, CacheEntry):
                # cache_entry is a future
                self._logger.debug('query for %r ongoing, awaiting result', key)
                return await cache_entry
            if cache_entry.expiry > self._loop.time():
                self._logger.debug('cached answer for %r valid', key)
                return cache_entry.answer
            del self._cache[key]
            self._logger.debug('cached answer for %r stale, deleting', key)

        self._logger.debug('no cached answer for %r, querying', key)
        answer_fut = asyncio.Future()
        self._cache[key] = answer_fut
        try:
            answer, ttl = await query_coro(*args)
            self._logger.debug('Got answer %r with ttl %r', answer, ttl)
            answer_fut.set_result(answer)
            if self._max_ttl is not None:
                ttl = min(ttl, self._max_ttl)
            if ttl > 0:
                self._logger.debug('answer for %r saved in cache', key)
                self._cache[key] = CacheEntry(answer, self._loop.time() + ttl)
            return answer
        except Exception as e:
            answer_fut.set_exception(e)
            raise
        finally:
            if self._cache[key] is answer_fut:
                del self._cache[key]


class Resolver:
    """Provide DNS resolution, request consolidation and caching.

    Combines queriers and ResolverCaches.
    """

    def __init__(self, querier,
                 ipv4_only=False, ipv6_only=False, ipv6_first=False,
                 max_ttl=RESOLVER_CACHE_MAX_TTL, loop=None):
        self._querier = querier
        self._ipv4_only = ipv4_only
        self._ipv6_only = ipv6_only
        self._ipv6_first = ipv6_first
        self._loop = loop or asyncio.get_event_loop()

        self._logger = logging.getLogger('detour.dns.resolver')
        self._cache_ipv4 = ResolverCache(max_ttl=max_ttl, loop=self._loop)
        self._cache_ipv6 = ResolverCache(max_ttl=max_ttl, loop=self._loop)

    async def _query_and_cache(self, key, ip_version=4):
        if ip_version == 4:
            cache = self._cache_ipv4
        elif ip_version == 6:
            cache = self._cache_ipv6
        else:
            raise ValueError('ip_version must be 4 or 6')
        try:
            return await asyncio.shield(cache.get_cache_or_query(
                key, self._querier.query, key, ip_version), loop=self._loop)
        except socket.gaierror:
            raise
        except (OSError, EOFError) as e:
            # turn internal exceptions into gaierror
            raise socket.gaierror from e

    async def getaddrinfo(self, host, port):
        """Resolve host IP addresses, and return in the getaddrinfo format.

        Note that other arguments available for socket.getaddrinfo() like type,
        family, proto, etc are not supported, and the returned sockaddr tuples
        are always (address, port) even for IPv6. (This is fine since
        BaseSelectorEventLoop.sock_connect() in fact discards anything
        other than (address, port) in its _ipaddr_info() method.)
        """
        key = dns.name.from_text(host)
        if self._ipv4_only:
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (addr, port))
                    for addr in (await self._query_and_cache(key, 4))]
        elif self._ipv6_only:
            return [(socket.AF_INET6, socket.SOCK_STREAM, 0, '', (addr, port))
                    for addr in (await self._query_and_cache(key, 6))]
        else:
            ipv4_task = self._loop.create_task(self._query_and_cache(key, 4))
            ipv6_task = self._loop.create_task(self._query_and_cache(key, 6))
            ipv4_result, ipv6_result = await asyncio.gather(
                ipv4_task, ipv6_task, loop=self._loop)
            exception_count = 0
            e = ipv4_task.exception()
            if e:
                self._logger.warning('IPv4 resolution failed: %r',
                                     ExceptionCausePrinter(e))
                exception_count += 1
                ipv4_addrinfo = []
            else:
                ipv4_addrinfo = [
                    (socket.AF_INET, socket.SOCK_STREAM, 0, '', (addr, port))
                    for addr in ipv4_result]
            e = ipv6_task.exception()
            if e:
                self._logger.warning('IPv6 resolution failed: %r',
                                     ExceptionCausePrinter(e))
                exception_count += 1
                ipv6_addrinfo = []
            else:
                ipv6_addrinfo = [
                    (socket.AF_INET6, socket.SOCK_STREAM, 0, '', (addr, port))
                    for addr in ipv6_result]
            if exception_count >= 2:
                raise socket.gaierror('Both IPv4 and IPv6 resolution failed')
            if self._ipv6_first:
                return list(roundrobin(ipv6_addrinfo, ipv4_addrinfo))
            else:
                return list(roundrobin(ipv4_addrinfo, ipv6_addrinfo))


class BaseQuerier:
    """Base class for DNS queriers.

    Queriers are responsible for sending DNS queries and receiving responses
    over the wire.
    """
    # subclasses MUST assign self._logger in __init__
    _logger = None

    async def query(self, qname=None, ip_version=4,
                    request: dns.message.Message = None):
        """Query for the IP addresses of hostname.

        Arguments:
        qname: the hostname to query.
        ip_version: either 4 or 6.
        request: the request DNS message to send.

        Either (qname, ip_version) or request must be specified.

        Returns (ip_addresses, ttl).

        Subclasses are encouraged to use _make_query() and _parse_response().
        """
        raise NotImplementedError

    @staticmethod
    def _make_query(qname, ip_version=4) -> dns.message.Message:
        """Construct query message."""
        if ip_version not in {4, 6}:
            raise ValueError('ip_version must be 4 or 6')
        if isinstance(qname, str):
            qname = dns.name.from_text(qname)
        if ip_version == 4:
            rdtype = dns.rdatatype.A
        else:
            rdtype = dns.rdatatype.AAAA
        return dns.message.make_query(qname, rdtype)

    def _parse_response(self, response: dns.message.Message):
        """Parse the response and return (addresses, ttl)."""
        min_ttl = float('inf')
        qname = response.question[0].name
        if response.rcode() == dns.rcode.NOERROR:
            # Follow CNAME chain, collect addresses and ttl
            current_name = qname
            rdtype = response.question[0].rdtype
            checked_names = set()

            while True:
                if current_name in checked_names:
                    self._logger.info('CNAME loop in response')
                    break
                checked_names.add(current_name)
                try:
                    rrset = response.find_rrset(
                        response.answer, current_name,
                        dns.rdataclass.IN, rdtype)
                except KeyError:
                    try:
                        rrset = response.find_rrset(
                            response.answer, current_name,
                            dns.rdataclass.IN, dns.rdatatype.CNAME)
                    except KeyError:  # NODATA
                        break
                    else:
                        min_ttl = min(min_ttl, rrset.ttl)
                        current_name = rrset[0].target
                else:
                    min_ttl = min(min_ttl, rrset.ttl)
                    addresses = [rr.address for rr in rrset]
                    assert min_ttl != float('inf')
                    return addresses, min_ttl
        elif response.rcode() != dns.rcode.NXDOMAIN:
            raise socket.gaierror('DNS response has RCODE {}'.format(
                dns.rcode.to_text(response.rcode())))
        # either NXDOMAIN or NODATA: check SOA record for ttl
        current_name = qname
        while True:
            try:
                rrset = response.find_rrset(
                    response.authority, current_name,
                    dns.rdataclass.IN, dns.rdatatype.SOA)
            except KeyError:
                try:
                    current_name = current_name.parent()
                except dns.name.NoParent:
                    break
            else:
                min_ttl = min(min_ttl, rrset.ttl, rrset[0].minimum)
                break
        if min_ttl == float('inf'):
            min_ttl = 0
        return [], min_ttl


class DNSUDPReceiverProtocol(asyncio.DatagramProtocol):
    """Protocol class for receiving DNS responses over UDP."""

    def __init__(self, request: dns.message.Message,
                 response_fut: asyncio.Future):
        self._request = request
        self._response_fut = response_fut

        self._logger = logging.getLogger('detour.dns.udp.receiver')
        self._transport = None

    def connection_made(self, transport):
        self._transport = transport
        self._logger.debug('Datagram endpoint created')

    def connection_lost(self, exc):
        if exc is None:
            self._logger.debug('Datagram endpoint closed')
            if not self._response_fut.done():
                self._response_fut.set_exception(ConnectionError(
                    'Endpoint closed before receiving response'))
        else:
            self._logger.error('Datagram endpoint closed with exception',
                               exc_info=exc)
            if not self._response_fut.done():
                self._response_fut.set_exception(exc)

    def datagram_received(self, data, addr):
        self._logger.debug('Datagram received from %r', addr)
        if self._response_fut.done():
            self._logger.debug('Datagram received after future done')
            return
        try:
            response = dns.message.from_wire(data)
        except dns.exception.DNSException as e:
            self._logger.warning('Error parsing datagram as DNS message: %r', e)
            return
        self._logger.debug('Received DNS message:\n%s', response)
        if self._request.is_response(response):
            self._response_fut.set_result(response)
        else:
            self._logger.warning('Received spurious DNS message')

    def error_received(self, exc):
        self._logger.error('Datagram endpoint error_received', exc_info=exc)


class UDPQuerier(BaseQuerier):
    """DNS querier over UDP.

    Sends regular old UDP DNS queries. Uses default EDNS(0) options as defined
    by dnspython.
    """
    query_sends = 3
    query_send_interval = 2
    query_send_backoff = 2

    def __init__(self, server, port=53, loop=None):
        self._server = server
        self._port = port
        self._loop = loop or asyncio.get_event_loop()

        self._logger = logging.getLogger('detour.dns.udp')
        self._fallback_querier = TCPQuerier(
            self._server, self._port, loop=self._loop)

    async def query(self, qname=None, ip_version=4,
                    request: dns.message.Message = None):
        if request is None:
            request = self._make_query(qname, ip_version)
        request.use_edns(0)

        response_fut = asyncio.Future(loop=self._loop)
        transport, protocol = await self._loop.create_datagram_endpoint(
            partial(DNSUDPReceiverProtocol, request, response_fut),
            remote_addr=(self._server, self._port))
        try:
            timeout = self.query_send_interval
            request_wire = request.to_wire()
            for _ in range(self.query_sends):
                self._logger.debug('Sending request for %s', qname)
                transport.sendto(request_wire)
                done, pending = await asyncio.wait(
                    (response_fut,), loop=self._loop, timeout=timeout)
                if done:
                    response = response_fut.result()
                    self._logger.debug('Response for %s received', qname)
                    break
                timeout *= self.query_send_backoff
            else:  # all resends exhausted
                raise TimeoutError('No response received after all retries')
            if response.flags & dns.flags.TC:
                self._logger.debug('UDP response has TC flag set, falling back '
                                   'to TCP')
                return await self._fallback_querier.query(request=request)
            return self._parse_response(response)
        finally:
            response_fut.cancel()
            transport.close()


class TCPQuerier(BaseQuerier):
    """DNS querier over TCP.

    Sends each request in its own TCP connection.
    """
    query_retries = 3
    query_retry_interval = 1

    def __init__(self, server, port=53, connect_coro=asyncio.open_connection,
                 loop=None):
        self._server = server
        self._port = port
        self.connector = connect_coro
        self._loop = loop or asyncio.get_event_loop()

        self._logger = logging.getLogger('detour.dns.tcp')

    async def query(self, qname=None, ip_version=4,
                    request: dns.message.Message = None):
        if request is None:
            request = self._make_query(qname, ip_version)
        request_wire = request.to_wire()
        to_send = len(request_wire).to_bytes(2, 'big') + request_wire
        for retry in range(self.query_retries):
            if retry:
                await asyncio.sleep(self.query_retry_interval, loop=self._loop)
            writer = None
            try:
                reader, writer = await self.connector(
                    self._server, self._port, loop=self._loop)
                writer.write(to_send)
                await writer.drain()
                # writer.write_eof()
                response_len = int.from_bytes(
                    (await reader.readexactly(2)), 'big')
                response_wire = await reader.readexactly(response_len)
                response = dns.message.from_wire(response_wire)
                return self._parse_response(response)
            except (OSError, EOFError) as e:
                self._logger.error('Error sending DNS query: %r',
                                   ExceptionCausePrinter(e))
                continue
            finally:
                if writer is not None:
                    writer.close()
        else:
            raise socket.gaierror('DNS resolution all retries failed')


class TCPPipeliningQuerier(BaseQuerier):
    """DNS querier over TCP, using pipelining.

    Multiple requests are sent over the same TCP connection. Uses the
    edns-tcp-keepalive option.
    """
    receive_timeout = 30
    query_retries = 3
    query_retry_interval = 0

    def __init__(self, server, port=53, connect_coro=asyncio.open_connection,
                 idle_timeout=5, loop=None):
        self._server = server
        self._port = port
        self.connector = connect_coro
        self.idle_timeout = idle_timeout
        self._loop = loop or asyncio.get_event_loop()

        self._logger = logging.getLogger('detour.dns.tcp-pl')
        self._reader = None  # type: asyncio.StreamReader
        self._writer = None  # type: asyncio.StreamWriter
        self._connect_event = asyncio.Event(loop=self._loop)
        self._connect_event.set()
        self._receive_task = None
        self._idle_timeout_ctx = None  # type: Timeout
        self._pending_requests = [
        ]  # type: List[Tuple[dns.message.Message, asyncio.Future]]

    async def _ensure_connected(self):
        if self._writer is not None:
            return
        if not self._connect_event.is_set():
            await self._connect_event.wait()
            if self._writer is None:
                raise ConnectionError('TCP connection was not established')
            return
        self._connect_event.clear()
        try:
            self._reader, self._writer = await self.connector(
                self._server, self._port, loop=self._loop)
        except (OSError, EOFError) as e:
            self._logger.warning('TCP connection failed: %r',
                                 ExceptionCausePrinter(e))
            # self._reader = self._writer = None
            raise
        finally:
            self._connect_event.set()

        self._receive_task = self._loop.create_task(
            self._receive(self._reader, self._writer))

    def _cancel_idle_timeout(self):
        if self._idle_timeout_ctx is not None:
            self._idle_timeout_ctx.cancel_timeout()
            self._idle_timeout_ctx = None
            self._logger.debug('Idle timeout cancelled')

    async def _receive(self, reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter):
        this_conn_idle_timeout = self.idle_timeout
        try:
            while True:
                assert this_conn_idle_timeout != 0
                if self._pending_requests:
                    idle_timeout = None
                else:
                    idle_timeout = this_conn_idle_timeout
                async with Timeout(self.receive_timeout, loop=self._loop), \
                           Timeout(idle_timeout, loop=self._loop) \
                        as self._idle_timeout_ctx:
                    try:
                        response_len = int.from_bytes(
                            await reader.readexactly(2), 'big')
                    except EOFError:
                        self._logger.debug('DNS server closed connection')
                        break
                    response_wire = await reader.readexactly(response_len)
                    try:
                        response = dns.message.from_wire(response_wire)
                    except dns.exception.DNSException as e:
                        self._logger.error('Error parsing DNS response: %r', e)
                        continue
                    self._logger.debug('Received DNS message:\n%s', response)
                    if response.edns == 0:
                        for option in response.options:
                            if option.otype == 11:
                                # TIMEOUT is in units of 100 milliseconds
                                this_conn_idle_timeout = int.from_bytes(
                                    option.data, 'big') / 10
                                self._logger.debug('Found tcp_edns_keepalive '
                                                   'option, timeout: %f',
                                                   this_conn_idle_timeout)
                                break
                    responded = []
                    for request, fut in self._pending_requests:
                        if request.is_response(response):
                            try:
                                fut.set_result(response)
                            except asyncio.InvalidStateError:
                                self._logger.error(
                                    'Future invalid state: done=%r, '
                                    'cancelled=%r, exception=%r',
                                    fut.done(), fut.cancelled(),
                                    fut.exception())
                            responded.append(request)
                    if responded:
                        self._pending_requests = [
                            t for t in self._pending_requests
                            if t[0] not in responded]
                    else:
                        self._logger.warning('Received unsolicited DNS message')
                if not self._pending_requests:
                    if this_conn_idle_timeout == 0:
                        self._logger.debug('Connection idle and idle timeout is'
                                           ' 0, disconnecting')
                        break
        except asyncio.TimeoutError:
            self._logger.debug('Connection timed out')
        except asyncio.CancelledError:
            self._logger.debug('Receive task cancelled')
        except Exception:
            self._logger.warning('Receive task caught exception', exc_info=True)
        finally:
            self._reader = self._writer = None
            writer.close()
            for request, fut in self._pending_requests:
                fut.set_exception(ConnectionError(
                    'TCP connection closed but no response received'))
            self._pending_requests.clear()
            self._receive_task = None
            self._cancel_idle_timeout()

    async def _send_query(self, query_msg: dns.message.Message
                          ) -> dns.message.Message:
        await self._ensure_connected()
        self._cancel_idle_timeout()
        query_wire = query_msg.to_wire()
        to_send = len(query_wire).to_bytes(2, 'big') + query_wire
        result_fut = asyncio.Future()
        self._pending_requests.append((query_msg, result_fut))
        self._writer.write(to_send)
        await self._writer.drain()
        return await result_fut

    async def query(self, qname=None, ip_version=4,
                    request: dns.message.Message = None):
        """Query for the IP addresses of hostname.

        Arguments:
        qname: the hostname to query.
        ip_version: either 4 or 6.
        request: the request DNS message to send.

        Either (qname, ip_version) or request must be specified.

        Returns (ip_addresses, ttl).
        """
        if request is None:
            request = self._make_query(qname, ip_version)
        # RFC 7828: edns-tcp-keepalive
        edns_tcp_keepalive = dns.edns.GenericOption(11, b'')
        request.use_edns(0, options=[edns_tcp_keepalive])

        last_exception = None
        for retry in range(self.query_retries):
            if retry:
                await asyncio.sleep(self.query_retry_interval, loop=self._loop)
            try:
                response = await self._send_query(request)
                break
            except OSError as e:
                self._logger.error('DNS query failed: %r', e)
                last_exception = e
                continue
        else:
            raise socket.gaierror('All retries failed') from last_exception

        return self._parse_response(response)


SuccessfulConnection = namedtuple(
    'SuccessfulConnection',
    ['reader', 'writer', 'host_entry', 'conn_type', 'token', 'bindaddr'])


class DetourProxy:
    """Route blocked connections through proxy automatically"""
    RELAY_BUFFER_SIZE = 2 ** 13
    NEXT_METHOD_DELAY = 3
    NEXT_SOCKET_DELAY = 0.3

    def __init__(self, listen_host, listen_port, upstream_host, upstream_port,
                 resolver: Resolver, detour_whitelist: DetourTokenWhitelist,
                 *, ipv4_only=False, ipv6_only=False, ipv6_first=False,
                 loop: asyncio.AbstractEventLoop = None):
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._upstream_host = upstream_host
        self._upstream_port = upstream_port
        self._resolver = resolver
        self._whitelist = detour_whitelist
        assert not (ipv4_only and ipv6_only)
        self._ipv4_only = ipv4_only
        self._ipv6_only = ipv6_only
        self._ipv6_first = ipv6_first
        self._loop = loop or asyncio.get_event_loop()

        self._logger = logging.getLogger('detour.proxy')
        self._dns_poison_ip = set()
        self._connections = set()
        self._server = None

        self._connector_table = {
            ConnectionType.DIRECT: self._make_direct_connection,
            ConnectionType.ALTDNS: self._make_alt_dns_connection,
            ConnectionType.DETOUR: self._make_detoured_connection,
        }

    async def start(self):
        self._server = await asyncio.start_server(
            self._server_handler, self._listen_host, self._listen_port,
            loop=self._loop)
        self._logger.info('DetourProxy listening on %r',
                          [s.getsockname() for s in self._server.sockets])

    async def stop(self):
        """Terminate the server and all active connections."""
        if self._server is None:
            raise RuntimeError('DetourProxy is not running')
        self._logger.info('DetourProxy closing')
        self._server.close()
        await self._server.wait_closed()
        self._logger.info('Listening socket closed')
        if self._connections:
            for conn in self._connections:
                conn.cancel()
            done, _ = await asyncio.wait(self._connections, loop=self._loop)
            for d in done:
                if not d.cancelled() and d.exception():
                    self._logger.error('Exception in closed connection',
                                       exc_info=d.exception())

    def load_dns_poison_ip(self, ips):
        self._dns_poison_ip.update(ipaddress.ip_address(a) for a in ips)

    async def _connect_sock(self, addrinfo):
        family, type_, proto, cname, addr = addrinfo
        self._logger.debug('Attempting to connect to %r', addr)
        try:
            sock = socket.socket(family, type_, proto)
            try:
                sock.setblocking(False)
                await self._loop.sock_connect(sock, addr)
                self._logger.debug('Connecting to %r successful: %r',
                                   addr, sock)
                return sock
            except:
                sock.close()
                raise
        except OSError as e:
            self._logger.debug('Connecting to %r failed: %r', addr, e)
            raise

    async def _getaddrinfo_native(self, host, port, family=socket.AF_UNSPEC):
        """Happy Eyeballs-appropriate getaddrinfo(). Reorders addresses."""
        addrinfos = await self._loop.getaddrinfo(
            host, port, family=family, type=socket.SOCK_STREAM)
        if family == socket.AF_UNSPEC:
            addrinfos_by_family = OrderedDict()
            for addr in addrinfos:
                family = addr[0]
                if family not in addrinfos_by_family:
                    addrinfos_by_family[family] = []
                addrinfos_by_family[family].append(addr)
            addrinfos_lists = list(addrinfos_by_family.values())
            addrinfos = list(roundrobin(*addrinfos_lists))
        return addrinfos

    async def _open_connections_parallel(self, addrinfo_list, delay=None):
        if delay is None:
            delay = self.NEXT_SOCKET_DELAY
        self._logger.debug('Attempting to connect to one of: %r', addrinfo_list)
        coro_fns = [partial(self._connect_sock, a) for a in addrinfo_list]
        connected_sock, _, exceptions = await staggered_race(
            coro_fns, delay, loop=self._loop)
        if connected_sock:
            try:
                return await asyncio.open_connection(
                    loop=self._loop, limit=self.RELAY_BUFFER_SIZE,
                    sock=connected_sock)
            except:
                connected_sock.close()
                raise
        assert exceptions
        self._logger.info('All connect attempts failed: <%s>',
                          ', '.join(repr(e) for e in exceptions))
        raise exceptions[-1]

    async def _make_direct_connection(self, uhost, uport,
                                      host_entry: DetourTokenHostEntry,
                                      need_token):
        assert not need_token
        if isinstance(uhost, ipaddress.IPv4Address):
            if self._ipv6_only:
                raise ConnectionError(
                    errno.EHOSTUNREACH,
                    'Cannot connect to IPv4 address when ipv6_only is set')
            addrinfo_list = [(socket.AF_INET, socket.SOCK_STREAM, 0, '',
                              (uhost.compressed, uport))]
        elif isinstance(uhost, ipaddress.IPv6Address):
            if self._ipv4_only:
                raise ConnectionError(
                    errno.EHOSTUNREACH,
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
            addrinfo_list = await self._getaddrinfo_native(uhost, uport, family)
            gai_ips = set(ipaddress.ip_address(a[4][0]) for a in addrinfo_list)
            if host_entry is not None:
                if not gai_ips.isdisjoint(self._dns_poison_ip):
                    host_entry.report_dns_poison_test(True)
                    raise ConnectionError('DNS poisoning detected')
                else:
                    if not host_entry.tested_dns_poison:
                        host_entry.stash_gai_result = gai_ips
        r, w = await self._open_connections_parallel(addrinfo_list)
        sockname = w.get_extra_info('sockname')
        return r, w, None, sockname

    async def _make_alt_dns_connection(self, uhost, uport,
                                       host_entry: DetourTokenHostEntry,
                                       need_token):
        assert not isinstance(
            uhost, (ipaddress.IPv4Address, ipaddress.IPv6Address))
        token = None
        if need_token:
            assert host_entry is not None
            token = host_entry.get_dns_token()
        addrinfo_list = await self._resolver.getaddrinfo(uhost, uport)
        if not addrinfo_list:
            raise ConnectionError(
                errno.EHOSTUNREACH, 'DNS resolution result empty')
        gai_ips = set(ipaddress.ip_address(a[4][0]) for a in addrinfo_list)
        if not gai_ips.isdisjoint(self._dns_poison_ip):
            self._logger.warning(
                'DNS resolution result for %s contains known poisoned IP '
                'address(es): DNS server is potentially poisoned!', uhost)
        if (host_entry is not None
                and not host_entry.tested_dns_poison
                and host_entry.stash_gai_result is not None):
            if not gai_ips.isdisjoint(host_entry.stash_gai_result):
                # When AltDNS resolves to an IP address also present in native
                # getaddrinfo(), assume hostname is not poisoned, and cancel
                # this AltDNS connection
                host_entry.report_dns_poison_test(False)
                raise ConnectionError(
                    'AltDNS result overlaps with getaddrinfo() result')
            else:
                host_entry.report_dns_poison_test(None)
            host_entry.stash_gai_result = None
        r, w = await self._open_connections_parallel(addrinfo_list)
        sockname = w.get_extra_info('sockname')
        return r, w, token, sockname

    def _socks5_send_connect_command(self, uhost, uport, uwriter):
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

    async def _socks5_upstream_negotiate(self, uhost, uport,
                                         ureader: asyncio.StreamReader,
                                         uwriter: asyncio.StreamWriter):
        self._logger.debug('Making upstream SOCKS5 connection to (%r, %r)',
                           uhost, uport)
        try:
            uwriter.write(b'\x05\x01' + SOCKS5AuthType.NO_AUTH)
            if SOCKS5_PREEMPTIVE_COMMAND:
                self._socks5_send_connect_command(uhost, uport, uwriter)
            buf = await ureader.readexactly(2)
            if buf[0:1] != b'\x05':
                raise ValueError('Invalid upstream SOCKS5 auth reply')
            if SOCKS5AuthType(buf[1:2]) is not SOCKS5AuthType.NO_AUTH:
                raise ValueError('Unsupported upstream SOCKS5 auth type')
            if not SOCKS5_PREEMPTIVE_COMMAND:
                self._socks5_send_connect_command(uhost, uport, uwriter)
            buf = await ureader.readexactly(4)
            if buf[0:1] != b'\x05' or buf[2:3] != b'\x00':
                raise ConnectionError(
                    'Invalid upstream SOCKS5 command response %r' % buf)
            reply = SOCKS5Reply(buf[1:2])
            if reply is not SOCKS5Reply.SUCCESS:
                raise SOCKS5Error(
                    reply, 'Upstream SOCKS5 server returned error %r' % reply)
            addr_type = SOCKS5AddressType(buf[3:4])
            if addr_type is SOCKS5AddressType.IPV4_ADDRESS:
                bind_host = ipaddress.IPv4Address(await ureader.readexactly(4))
            elif addr_type is SOCKS5AddressType.IPV6_ADDRESS:
                bind_host = ipaddress.IPv6Address(await ureader.readexactly(16))
            elif addr_type is SOCKS5AddressType.DOMAIN_NAME:
                buf = await ureader.readexactly(1)
                bind_host = (await ureader.readexactly(buf[0])).decode('utf-8')
            else:
                raise ValueError('Invalid address type')
            bind_port = int.from_bytes(await ureader.readexactly(2), 'big')
            self._logger.debug(
                'Upstream SOCKS5 connection to (%r, %r) successful, '
                'bind address: (%r, %r)', uhost, uport, bind_host, bind_port)
            return bind_host, bind_port
        except (ValueError, OSError, EOFError) as e:
            raise ConnectionError('Upstream SOCKS5 connection error') from e

    async def _open_connection_detour(self, host, port, **kwargs):
        r, w = await asyncio.open_connection(
            self._upstream_host, self._upstream_port, **kwargs)
        try:
            bindaddr = await self._socks5_upstream_negotiate(host, port, r, w)
        except:
            w.transport.abort()
            raise
        return r, w, bindaddr

    async def open_connection_detour(self, host, port, **kwargs):
        """Open a connection to (host, port) through the upstream proxy.

        Returns (reader, writer).

        **kwargs are passed to asyncio.open_connection().
        """
        try:
            r, w, bindaddr = await self._open_connection_detour(
                host, port, **kwargs)
            return r, w
        except SOCKS5Error as e:
            raise ConnectionError('Upstream SOCKS5 proxy returned error') from e

    async def _make_detoured_connection(self, uhost, uport,
                                        host_entry: DetourTokenHostEntry,
                                        need_token):
        token = None
        if need_token:
            assert host_entry is not None
            token = host_entry.get_detour_token()
        try:
            r, w, bindaddr = await self._open_connection_detour(
                uhost, uport, loop=self._loop, limit=self.RELAY_BUFFER_SIZE)
        except OSError as e:
            self._logger.warning('Connecting to upstream proxy failed: %r',
                                 ExceptionCausePrinter(e))
            raise
        return r, w, token, bindaddr

    async def _make_connection(self, connection, host_entry,
                               host, port, log_name):
        conn_type, need_token = connection
        self._logger.info('%s try %s', log_name, conn_type)
        connector = self._connector_table[conn_type]
        try:
            result = await connector(host, port, host_entry, need_token)
        except (OSError, EOFError, SOCKS5Error) as e:
            self._logger.info('%s %s error during connect: %r', log_name,
                              conn_type, ExceptionCausePrinter(e))
            raise
        self._logger.info('%s connection %s successful', log_name, conn_type)
        return result

    async def _make_best_connection(self, host, port, log_name) -> \
            Tuple[Union[None, SuccessfulConnection],
                  Dict[ConnectionType, Exception]]:
        connections, host_entry = self._whitelist.match_host(host)
        self._logger.debug('%s connections: %r', log_name, connections)
        coro_fns = [partial(self._make_connection, conn, host_entry, host, port,
                            log_name) for conn in connections]
        success_result, success_idx, exceptions = await staggered_race(
            coro_fns, self.NEXT_METHOD_DELAY, loop=self._loop)
        fail_reasons = {conn[0]: exc for conn, exc
                        in zip(connections, exceptions) if exc is not None}
        success_connection = None
        if success_result is not None:
            reader, writer, this_conn_token, bindaddr = success_result
            bind_host = bindaddr[0]
            with suppress(ValueError):
                bind_host = ipaddress.ip_address(bind_host)
            bind_port = bindaddr[1]
            success_connection = SuccessfulConnection(
                reader, writer, host_entry, connections[success_idx][0],
                this_conn_token, (bind_host, bind_port))
        return success_connection, fail_reasons

    async def _socks5_downstream_negotiate(
            self, dreader: asyncio.StreamReader, dwriter: asyncio.StreamWriter
    ) -> Tuple[HostType, int]:
        log_name = '{!r} <=> ()'.format(
            dwriter.transport.get_extra_info('peername'))
        try:
            buf = await dreader.readexactly(1)  # number of auth methods
            buf = await dreader.readexactly(buf[0])  # offered auth methods
            if SOCKS5AuthType.NO_AUTH not in buf:
                dwriter.write(b'\x05' + SOCKS5AuthType.NO_OFFERS_ACCEPTABLE)
                dwriter.write_eof()
                await dwriter.drain()
                raise DownstreamNegotiationError(
                    'Client did not offer "no auth", offers: %r' % buf)
            dwriter.write(b'\x05' + SOCKS5AuthType.NO_AUTH)

            # client command
            buf = await dreader.readexactly(4)  # ver, cmd, rsv, addr_type
            if buf[0] != 5 or buf[2] != 0:
                raise DownstreamNegotiationError('%s malformed SOCKS5 command'
                                                 % log_name)
            cmd = SOCKS5Command(buf[1:2])
            addr_type = SOCKS5AddressType(buf[3:4])
            if addr_type is SOCKS5AddressType.IPV4_ADDRESS:
                uhost = ipaddress.IPv4Address(await dreader.readexactly(4))
            elif addr_type is SOCKS5AddressType.IPV6_ADDRESS:
                uhost = ipaddress.IPv6Address(await dreader.readexactly(16))
            elif addr_type is SOCKS5AddressType.DOMAIN_NAME:
                buf = await dreader.readexactly(1)  # address len
                uhost = (await dreader.readexactly(buf[0])).decode('utf-8')
                try:
                    uhost = ipaddress.ip_address(uhost)
                except ValueError:
                    pass
                else:
                    self._logger.info(
                        '%s client sending IP address literal as host name: %r',
                        log_name, uhost)
            else:
                raise ValueError('%s unsupported address type %r'
                                 % (log_name, addr_type))
            uport = int.from_bytes(await dreader.readexactly(2), 'big')
            log_name = '{!r} <=> ({!r}, {!r})'.format(
                dwriter.transport.get_extra_info('peername'),
                uhost, uport)
            self._logger.debug('%s parsed target address', log_name)
            if cmd is not SOCKS5Command.CONNECT:
                await self._socks5_downstream_reply(
                    dwriter, SOCKS5Reply.COMMAND_NOT_SUPPORTED, INADDR_ANY, 0)
                raise DownstreamNegotiationError(
                    'Client command %r not supported' % cmd)
            self._logger.info('%s received CONNECT command', log_name)
            if self._ipv6_only:
                if addr_type is SOCKS5AddressType.IPV4_ADDRESS:
                    await self._socks5_downstream_reply(
                        dwriter, SOCKS5Reply.ADDRESS_TYPE_NOT_SUPPORTED,
                        INADDR_ANY, 0)
                    raise DownstreamNegotiationError(
                        'Client request connection to IPv4 address '
                        'while IPV6_ONLY set')
            elif self._ipv4_only:
                if addr_type is SOCKS5AddressType.IPV6_ADDRESS:
                    await self._socks5_downstream_reply(
                        dwriter, SOCKS5Reply.ADDRESS_TYPE_NOT_SUPPORTED,
                        INADDR_ANY, 0)
                    raise DownstreamNegotiationError(
                        'Client request connection to IPv6 address '
                        'while IPV4_ONLY set')
            return uhost, uport
        except (OSError, EOFError, ValueError) as e:
            raise DownstreamNegotiationError(
                'Error while negotiating with SOCKS5 client') from e

    async def _socks5_downstream_reply(self, dwriter: asyncio.StreamWriter,
                                       reply, host, port):
        assert len(reply) == 1
        if isinstance(host, ipaddress.IPv4Address):
            b_addr = SOCKS5AddressType.IPV4_ADDRESS + host.packed
        elif isinstance(host, ipaddress.IPv6Address):
            b_addr = SOCKS5AddressType.IPV6_ADDRESS + host.packed
        else:
            b_addr = host.encode('idna')
            b_addr = (SOCKS5AddressType.DOMAIN_NAME
                      + len(b_addr).to_bytes(1, 'big') + b_addr)
        try:
            dwriter.write(b'\x05' + reply + b'\x00'
                          + b_addr + port.to_bytes(2, 'big'))
            if reply is not SOCKS5Reply.SUCCESS:
                dwriter.write_eof()
            await dwriter.drain()
        except OSError as e:
            raise DownstreamNegotiationError(
                'Error while replying to SOCKS5 client') from e

    def _map_exception_to_socks5_reply(self, exc):
        if isinstance(exc, SOCKS5Error):
            return exc.args[0]
        if isinstance(exc, socket.gaierror):
            return SOCKS5Reply.HOST_UNREACHABLE
        if isinstance(exc, TimeoutError):
            return SOCKS5Reply.TTL_EXPIRED
        if isinstance(exc, ConnectionRefusedError):
            return SOCKS5Reply.CONNECTION_REFUSED
        if isinstance(exc, OSError):
            if exc.errno == errno.ENETUNREACH:
                return SOCKS5Reply.NETWORK_UNREACHABLE
            elif exc.errno == errno.EHOSTUNREACH:
                return SOCKS5Reply.HOST_UNREACHABLE
            elif exc.errno == errno.ECONNREFUSED:
                return SOCKS5Reply.CONNECTION_REFUSED
            elif exc.errno == errno.ETIMEDOUT:
                return SOCKS5Reply.TTL_EXPIRED
            elif WINDOWS and exc.winerror == 121:
                # OSError: [WinError 121] The semaphore timeout period has
                # expired
                # Looks like this exception instead of TimeoutError is raised
                # by ProactorEventLoop
                return SOCKS5Reply.TTL_EXPIRED
        if isinstance(exc, ConnectionError):
            return SOCKS5Reply.GENERAL_FAILURE
        self._logger.warning('Unexpected exception', exc_info=exc)
        return SOCKS5Reply.GENERAL_FAILURE

    async def _server_handle_socks5(
            self, initial_byte: bytes, stack: ExitStack,
            dreader: asyncio.StreamReader, dwriter: asyncio.StreamWriter,
    ) -> Tuple[SuccessfulConnection, HostType, int]:
        assert initial_byte == b'\x05'
        uhost, uport = await self._socks5_downstream_negotiate(dreader, dwriter)
        log_name = '{!r} <=> ({!r}, {!r})'.format(
            dwriter.transport.get_extra_info('peername'),
            uhost, uport)
        conn, fail_reasons = await self._make_best_connection(
            uhost, uport, log_name)
        if conn is None:
            socks5_reply_counter = Counter(
                self._map_exception_to_socks5_reply(e)
                for e in fail_reasons.values())
            socks5_reply_counter.pop(SOCKS5Reply.GENERAL_FAILURE, None)
            if socks5_reply_counter:
                reply = socks5_reply_counter.most_common(1)[0][0]
            else:
                reply = SOCKS5Reply.GENERAL_FAILURE
            await self._socks5_downstream_reply(dwriter, reply,
                                                INADDR_ANY, 0)
            raise UpstreamConnectionError(
                'All connection attempts to ({!r}, {!r}) failed'.format(
                    uhost, uport))
        uwriter = conn.writer
        stack.enter_context(finally_close(uwriter))
        if not SOCKS5_RETURN_FAKE_BIND_ADDR:
            bind_host, bind_port = conn.bindaddr
        else:
            bind_host = INADDR_ANY
            bind_port = 0
        await self._socks5_downstream_reply(dwriter, SOCKS5Reply.SUCCESS,
                                            bind_host, bind_port)
        return conn, uhost, uport

    async def _socks4_downstream_negotiate(
            self, dreader: asyncio.StreamReader, dwriter: asyncio.StreamWriter
    ) -> Tuple[HostType, int]:
        log_name = '{!r} <=> ()'.format(
            dwriter.transport.get_extra_info('peername'))
        try:
            command = SOCKS4Command(await dreader.readexactly(1))
            if command is not SOCKS4Command.CONNECT:
                await self._socks4_downstream_reply(dwriter, False)
                raise DownstreamNegotiationError(
                    'Client command %r not supported' % command)
            self._logger.debug('%s received SOCKS4 CONNECT command', log_name)
            uport = int.from_bytes(await dreader.readexactly(2), 'big')
            uip = ipaddress.IPv4Address(await dreader.readexactly(4))
            userid = await dreader.readuntil(b'\0')
            if uip in SOCKS4A_INVALID_IP:
                self._logger.debug('%s request is SOCKS4A')
                uhost = await dreader.readuntil(b'\0')[:-1]
                try:
                    uhost = ipaddress.ip_address(uhost)
                except ValueError:
                    pass
                else:
                    self._logger.info(
                        '%s client sending IP address literal as host name: %r',
                        log_name, uhost)
            else:
                uhost = uip
            log_name = '{!r} <=> ({!r}, {!r})'.format(
                dwriter.transport.get_extra_info('peername'),
                uhost, uport)
            self._logger.debug('%s parsed target address', log_name)
            return uhost, uport
        except (OSError, EOFError, ValueError, asyncio.LimitOverrunError) as e:
            raise DownstreamNegotiationError(
                'Error while negotiating with SOCKS4 client') from e

    async def _socks4_downstream_reply(self, dwriter: asyncio.StreamWriter,
                                       success: bool):
        try:
            if success:
                dwriter.write(b'\0' + SOCKS4Reply.GRANTED + b'\0\0\0\0\0\0')
            else:
                dwriter.write(b'\0' + SOCKS4Reply.REJECTED_FAILED
                              + b'\0\0\0\0\0\0')
                dwriter.write_eof()
            await dwriter.drain()
        except (OSError, EOFError) as e:
            raise DownstreamNegotiationError(
                'Error while replying to SOCKS4 client') from e

    async def _server_handle_socks4(
            self, initial_byte: bytes, stack: ExitStack,
            dreader: asyncio.StreamReader, dwriter: asyncio.StreamWriter,
    ) -> Tuple[SuccessfulConnection, HostType, int]:
        assert initial_byte == b'\x04'
        uhost, uport = await self._socks4_downstream_negotiate(dreader, dwriter)
        log_name = '{!r} <=> ({!r}, {!r})'.format(
            dwriter.transport.get_extra_info('peername'),
            uhost, uport)
        conn, fail_reasons = await self._make_best_connection(
            uhost, uport, log_name)
        if conn is None:
            await self._socks4_downstream_reply(dwriter, False)
            raise UpstreamConnectionError(
                'All connection attempts to ({!r}, {!r}) failed'.format(
                    uhost, uport))
        stack.enter_context(finally_close(conn.writer))
        await self._socks4_downstream_reply(dwriter, True)
        return conn, uhost, uport

    async def _server_handle_http(self, initial_byte, stack,
                                  dreader: asyncio.StreamReader,
                                  dwriter: asyncio.StreamWriter):
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
            dwriter.write_eof()
            await dwriter.drain()
            raise DownstreamNegotiationError('Client sent HTTP request')
        except OSError as e:
            raise DownstreamNegotiationError(
                'Error while replying to HTTP client') from e

    async def _relay_data_side(self, reader, writer,
                               log_name, write_is_upstream):
        bytes_relayed = 0
        try:
            while True:
                try:
                    buf = await reader.read(self.RELAY_BUFFER_SIZE)
                except OSError as e:
                    if not write_is_upstream:
                        raise UpstreamRelayError(
                            'Error receiving from upstream') from e
                    else:
                        raise
                if not buf:  # EOF
                    break
                self._logger.debug('%s received data', log_name)
                try:
                    writer.write(buf)
                    await writer.drain()
                except OSError as e:
                    if write_is_upstream:
                        raise UpstreamRelayError(
                            'Error sending to upstream') from e
                    else:
                        raise
                self._logger.debug('%s sent data', log_name)
                bytes_relayed += len(buf)
            self._logger.debug('%s received EOF', log_name)
            try:
                writer.write_eof()
                await writer.drain()
            except OSError as e:
                if write_is_upstream:
                    raise UpstreamRelayError(
                        'Error writing EOF to upstream') from e
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

    async def _relay_data(self,
                          dreader: asyncio.StreamReader,
                          dwriter: asyncio.StreamWriter,
                          ureader: asyncio.StreamReader,
                          uwriter: asyncio.StreamWriter,
                          uname):
        # TODO: add content monitoring here to catch more censorship methods
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

    @staticmethod
    def _report_relay_result(conn: SuccessfulConnection, successful: bool):
        if conn.host_entry is not None:
            if successful:
                conn.host_entry.report_relay_success(conn.conn_type, conn.token)
            else:
                conn.host_entry.report_relay_failure(conn.conn_type)

    async def _server_handler(self, dreader: asyncio.StreamReader,
                              dwriter: asyncio.StreamWriter):
        log_name = '{!r} <=> ()'.format(
            dwriter.transport.get_extra_info('peername'))

        try:  # catch, log and suppress all exceptions in outermost layer
            with ExitStack() as stack:
                this_task = current_task()
                self._connections.add(this_task)
                stack.callback(self._connections.remove, this_task)
                stack.enter_context(finally_close(dwriter))
                self._logger.debug('%s accepted downstream connection',
                                   log_name)
                try:
                    initial_byte = await dreader.readexactly(1)
                except (OSError, EOFError) as e:
                    raise DownstreamNegotiationError(
                        'Error reading from client') from e
                if initial_byte == b'\x05':
                    conn, uhost, uport = await self._server_handle_socks5(
                        initial_byte, stack, dreader, dwriter)
                elif initial_byte == b'\x04':
                    conn, uhost, uport = await self._server_handle_socks4(
                        initial_byte, stack, dreader, dwriter)
                elif b'A' <= initial_byte <= b'Z':
                    conn, uhost, uport = await self._server_handle_http(
                        initial_byte, stack, dreader, dwriter)
                else:
                    raise DownstreamNegotiationError(
                        '%s unknown protocol' % log_name)

                ureader = conn.reader
                uwriter = conn.writer

                log_name = '{!r} <=> ({!r}, {!r}) [{}]'.format(
                    dwriter.transport.get_extra_info('peername'),
                    uhost, uport, conn.conn_type)

                try:
                    await self._relay_data(dreader, dwriter,
                                           ureader, uwriter,
                                           (uhost, uport))
                except UpstreamRelayError:
                    self._report_relay_result(conn, False)
                    raise
                self._logger.info('%s completed normally',
                                  log_name)
                self._report_relay_result(conn, True)
                return
        except asyncio.CancelledError:
            self._logger.debug('%s cancelled', log_name)
            raise
        except (UpstreamConnectionError,
                DownstreamNegotiationError,
                RelayError,
                ) as e:
            # not logging stack trace for expected errors
            self._logger.info('%s Exception: %r',
                              log_name, ExceptionCausePrinter(e))
        except Exception as e:
            self._logger.error('%s %r', log_name, e, exc_info=True)
        finally:
            self._logger.debug('%s connection done', log_name)


def windows_async_signal_helper(loop, interval=0.2):
    """Schedule a do-nothing regular callback on Windows only.

    This is a workaround for Python Issue 23057 in Windows
    ( https://bugs.python.org/issue23057 ), where signals like
    KeyboardInterrupt will not be delivered in an event loop if nothing
    is happening. A regular callback allows such signals to be
    delivered.
    """
    if WINDOWS:
        noop_callback(loop, interval)


def noop_callback(loop, delay):
    """Do nothing and schedule to do nothing later."""
    loop.call_later(delay, noop_callback, loop, delay)


def sigterm_handler():
    logging.warning('Received SIGTERM, exiting')
    sys.exit(0)


def relay():
    parser = argparse.ArgumentParser(
        description='''Automatically divert connections to censored sites 
        through a proxy.''')
    parser.add_argument(
        'proxy',
        help='''Host name / IP address of the upstream proxy server.''')
    parser.add_argument(
        'proxy_port', nargs='?', type=int, default=1080,
        help='''Port number of the upstream proxy server. (Default: 1080)''')
    parser.add_argument(
        '--bind', '-b', default='127.0.0.1',
        help='''Host name / IP address to bind to. (Default: 127.0.0.1)''')
    parser.add_argument(
        '--bind-port', '-p', type=int, default=1080,
        help='''Port number to bind to. (Default: 1080)''')
    parser.add_argument(
        '--dns', '-D', help='''IP address of a safe DNS server which returns 
        non-poisoned results. If none of the --dns[-*] arguments are 
        specified, it is equivalent to specifying "--dns 1.1.1.1 --dns-tcp 
        --dns-detour", i.e. making TCP requests to Cloudflare's public DNS 
        server through the upstream proxy.''')
    parser.add_argument(
        '--dns-port', '-P', type=int,
        help='''Port number of the safe DNS server.''')
    tcp_group = parser.add_mutually_exclusive_group()
    tcp_group.add_argument(
        '--dns-tcp', '-T', action='store_true', help='''Use TCP instead of 
        UDP to make DNS queries. Query pipelining and connection keepalive 
        are used to minimize connection overhead. The connection can be 
        routed through the upstream proxy if --dns-detour is set.''')
    tcp_group.add_argument(
        '--dns-tcp-lame', action='store_true', help='''Use TCP instead of UDP 
        to make DNS queries. Each query opens a new connection, so there's 
        quite a bit of overhead. Use --dns-tcp instead of this if at all 
        possible. Can be used with --dns-detour as well.''')
    parser.add_argument(
        '--dns-detour', '-R', action='store_true', help='''Make DNS queries 
        through the upstream proxy. Only works if --dns-tcp or --dns-tcp-lame 
        is set.''')
    parser.add_argument(
        '--state', '-s', default='state.csv', help='''Path to the "state 
        file" which stores information learned about censored sites. 
        (Default: state.csv)''')
    parser.add_argument(
        '--persistent', '-e', help='''Path to the "persistent rules file", 
        which describes sites that should always use a particular connection 
        method. (Default: persistent.txt)''')
    parser.add_argument(
        '--poison-ip', help='''Path to "poisoned IP list" file, which stores 
        a list of IP addresses known to be returned by the poisoned DNS 
        responses. (Default: "dns_poison_list.txt" in the *same directory as 
        the script*.)''')
    ip_version_group = parser.add_mutually_exclusive_group()
    ip_version_group.add_argument(
        '--ipv4-only', '-4', action='store_true',
        help='''Restrict most network actions to IPv4 only.''')
    ip_version_group.add_argument(
        '--ipv6-only', '-6', action='store_true',
        help='''Restrict most network actions to IPv6 only.''')
    parser.add_argument(
        '--ipv6-first', action='store_true',
        help='''Prioritize IPv6 in most network actions.''')
    parser.add_argument(
        '--verbose', '-v', action='count',
        help='''Increase output verbosity. Specify once for INFO, twice for 
        DEBUG.''')
    parser.add_argument(
        '--log', help='''Path to log file.''')

    args = parser.parse_args()

    # Argument sanity checking and defaults
    if args.dns is None:
        if (args.dns_port is not None or args.dns_tcp or args.dns_tcp_lame
                or args.dns_detour):
            sys.exit('Arguments error: --dns is not set. To use built-in '
                     'settings, do not set ANY of the --dns[-*] options.')
        # Use a domain name here for the DNS server, so the upstream proxy is
        # free to decide whether to use IPv4 or IPv6.
        args.dns = '1dot1dot1dot1.cloudflare-dns.com'
        args.dns_tcp = True
        args.dns_detour = True

    if args.dns_port is None:
        args.dns_port = 53

    if args.dns_detour and not (args.dns_tcp or args.dns_tcp_lame):
        sys.exit('Arguments error: --dns-detour must be specified with '
                 'either --dns-tcp or --dns-tcp-lame.')

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
        file_handler = logging.FileHandler(args.log)
        file_handler.setFormatter(file_formatter)
        rootlogger.addHandler(file_handler)
    # logging.getLogger('asyncio').setLevel(logging.INFO)
    # logging.getLogger('detour.dns').setLevel(logging.DEBUG)
    logging.captureWarnings(True)
    warnings.filterwarnings('always')

    if (WINDOWS_USE_PROACTOR_EVENT_LOOP
            and WINDOWS
            and (args.dns_tcp or args.dns_tcp_lame)):
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

    assert args.dns
    if args.dns_tcp:
        querier_class = TCPPipeliningQuerier
    elif args.dns_tcp_lame:
        querier_class = TCPQuerier
    else:
        querier_class = UDPQuerier
    querier = querier_class(args.dns, args.dns_port, loop=loop)
    resolver = Resolver(
        querier, ipv4_only=args.ipv4_only, ipv6_only=args.ipv6_only,
        ipv6_first=args.ipv6_first, loop=loop)

    proxy = DetourProxy(
        args.bind, args.bind_port, args.proxy, args.proxy_port, resolver,
        whitelist, ipv4_only=args.ipv4_only, ipv6_only=args.ipv6_only,
        ipv6_first=args.ipv6_first, loop=loop)
    if args.dns_detour:
        querier.connector = proxy.open_connection_detour

    dns_poison_path = args.poison_ip or DEFAULT_DNS_POISON_FILE
    try:
        with open(dns_poison_path, 'rt') as dpf:
            proxy.load_dns_poison_ip(l.strip() for l in dpf)
    except OSError as e:
        logging.warning('loading DNS poison IP list failed: %r', e)
        if args.poison_ip:
            raise
    else:
        logging.info('DNS poison IP list loaded')

    windows_async_signal_helper(loop)
    with suppress(NotImplementedError):
        loop.add_signal_handler(signal.SIGTERM, sigterm_handler)

    loop.run_until_complete(proxy.start())
    try:
        loop.run_forever()
    except (SystemExit, KeyboardInterrupt) as e:
        logging.warning('Received %r', e)
        loop.run_until_complete(proxy.stop())
    finally:
        whitelist.dump_state_file(args.state)
        loop.close()


if __name__ == '__main__':
    relay()
