# detour-proxy-advance

A piece of software that makes circumventing Internet censorship more convenient. This does not provide circumvention by itself, but it can be used to automatically detour connections to blocked websites.

## Motivation

There are many useful tools that help people visit websites blocked by a national censor. [Lantern](https://getlantern.org/) is an interesting "batteries included" solution, in that it handles all requests, tries to connect directly first, and only use their relay if the website is detected to be blocked. This way, connections to non-blocked websites are not needlessly routed through the relay, and there's no need to manually maintain a list of blocked sites.

For people who don't want to use Lantern, perhaps those who prefer to roll their own circumvention solution, but still want the convenience of automatic detouring, I present to you this project, Detour Proxy Advance. 

## What it does

### Censorship threat model

Two types of website censorship are considered here:

- DNS poisoning. When a DNS lookup is done for the censored website, wrong IP addresses are returned, and connections to these erroneous IP addresses naturally fail. If the correct IP addresses are obtained by another method, however, connections to those addresses complete successfully.

- TCP connection interruption. When a TCP connection to the website is made, the censor interrupts the connection, either by blocking packets or sending RST packets to the client, causing the connection to fail.

(Note that this tool currently does not recognize TCP hijacking, where the censor inserts false data into the connection in order to display a notice or redirect the client's browser. Such methods are known to be used in Iran and South Korea, for example.)

### Circumvention logic

This tool makes 3 types of outgoing TCP connections:

- Direct connection. Do name resolution using OS-provided methods, and connect directly to the resolved address(es).
- Alternate DNS connection. Do name resolution using a DNS server guaranteed to return authentic results, and connect directly to the resolved address(es).
- Detoured connection. Make the connection through a relay, known to be unaffected by censorship.

When connecting to a host name, this tool attempts to connect using all 3 methods, in this order, with a delay in between. Whichever connection succeeds is used. If one type of connection succeeds multiple times consistently, it is remembered, and connection types before the winning one is no longer attempted.

If a connection succeeds, but is then interrupted, this connection method is marked temporarily unavailable, and the next connection attempt will only try methods after the current method.

There is some additional logic to deal with the case where DNS for a certain host is known to be / known not to be poisoned, when connecting to an IP address where DNS resolution is not necessary, and to occasionally re-learn the best connection method.

The end result is that, most censored websites will simply work, and those that doesn't work the first time starts working after a few refreshes.

## Usage

### Requirements

The following are required to use Detour Proxy Advance:

- Python 3.5 or higher.
- The `aiodns` Python package.
- A DNS server known to return authentic, non-poisoned IP addresses. This can be a DNS server across a VPN link, a DNSCrypt Proxy, etc.
- A SOCKS5 proxy server known to reach censored websites. This can be a SOCKS5 proxy server across a VPN link, a SOCKS5 proxy tunneled using `stunnel` or `obfs4proxy`, a SSH connection with dynamic forwarding, etc. (Currently only non-authenticated proxies are supported.)
- Some experience in Python.

### Configuration

Complete these configuration steps before using:

- Edit variables in the configuration section near the top of the script to set (at least) your DNS server, upstream proxy, and the local address / port to listen on.
- Optionally, prepare a list of known IP addresses used in poisoned DNS replies and put it in `dns_poison_ip.txt` in the same directory as the script.
- Optionally, prepare a file `persistent.txt` that contains domains / IP addresses that should always use a certain connection method.
- Configure your browser's SOCKS5 proxy setting to point to the listen address set above, and make sure to turn on "remote DNS resolution" or any similar option.

### Running the script

Just run it!

Some files will be saved to the same directory as the script by default.

## Some out-of-scope stuff

Occasionally I may add new features to this script. Here I list a few features that I believe should *not* be part of this script, and how they can be achieved using other tools.

#### HTTP proxy support

HTTP proxies are *complicated*. There are so many corner cases this thing must have a fractal shape, so I am not going to try cramming it into a single script.

To use Detour Proxy Advance with things that can only use an HTTP proxy, put an HTTP proxy in front, and set Detour Proxy Advance as its upstream. [TinyProxy](https://tinyproxy.github.io/) (git version), [Privoxy](https://www.privoxy.org/), [Polipo](https://www.irif.fr/~jch/software/polipo/), [3proxy](https://3proxy.ru/) should all work. (Just a note: none of these support non-TLS WebSocket connections. Privoxy and Polipo both fall on their faces if the upstream proxy returns an IPv6 bind address.)