# detour-proxy-advance

Makes circumventing Internet censorship more convenient. Blocked sites are automatically detected and routed through a proxy, while unblocked sites are visited directly.

## Motivation

There are many useful tools that help people visit websites blocked by a national censor. [Lantern](https://getlantern.org/) is an interesting solution, in that it handles all requests, tries to connect directly first, and only use their relay if the website is detected to be blocked. This way, connections to non-blocked websites are not needlessly routed through the relay, and the user do no have to manually maintain a list of blocked sites.

For people who want to roll their own circumvention solution, but still desire Lantern's convenience, this project might be the missing piece of the puzzle.

## What it does

### Censorship threat model

Two types of website censorship are considered here:

- DNS poisoning. When a user attempts to visit a censored website, the browser does a DNS lookup for the website's host name, and the censor injects incorrect "poisoned" IP addresses in the response, so that the browser connects to a wrong address and fail. If the correct IP addresses are obtained by another method, however, direct connections to those addresses complete successfully.

- TCP connection interruption. When a TCP connection to the website is made, the censor interrupts the connection, either by dropping packets or sending TCP RST packets to the client, causing the connection to fail.

(Note that this tool currently does not recognize TCP hijacking, where the censor inserts false data into the connection in order to display a notice or redirect the client's browser. Such methods are known to be used in Iran and South Korea, for example.)

### Circumvention logic

In order to fight the cersorship methods outlined above, this tool attemtps 3 different methods of connecting to the target website:

- Direct connection. Do name resolution using OS-provided methods, and connect directly to the resolved address(es).
- Alternate DNS connection. Do name resolution using a DNS server guaranteed to return authentic results, and connect directly to the resolved address(es). This defeats DNS poisoning.
- Detoured connection. Make the connection through a relay, known to be unaffected by censorship. This defeats connection interruption.

When connecting to a given host name, this tool attempts all 3 methods, in the given order, with a delay in between. Whichever connection succeeds first is used, and the method that works consistently is learned. Future connections to the same site will skip methods that don't work.

There is some additional logic to deal with the case where DNS for a certain host is known to be / known not to be poisoned, when connecting to an IP address where DNS resolution is not necessary, and to occasionally re-learn the best connection method.

The end result is that, censored websites either work right away, or starts working after a few refreshes. Uncensored sites work just like before, with no slowdowns.

## How to use it

### Requirements

The following are required to use Detour Proxy Advance:

- Python 3.5 or higher. **Using the latest Python 3 release is STRONGLY RECOMMENDED**, since this project gets very little testing on  older Python versions.
- The `dnspython` Python package.
- A SOCKS5 proxy server that can reach censored websites. This can be anything that presents a SOCKS5 server with no user authentication: a plain proxy server, a proxy server tunneled through a VPN, `stunnel` or `obfs4proxy`, a SSH connection with dynamic forwarding, etc. (Proxies with user authentication are not supported.)
- Optional: A DNS server that returns authentic, non-poisoned IP addresses. This can be a local DNS proxy utilizing one of the encrypted protocols (DNSCrypt, DNS over TLS, DNS over HTTPS, etc.), a DNS server across a VPN link, a DNS server that supports TLS, etc. Detour Proxy Advance can also use the upstream SOCKS5 proxy to reach a public DNS service.

### Configuration and usage

The script is now configured using command line arguments. Run the script with argument "--help" to see detailed usage. At the very least, the IP address / host name of the upstream SOCKS5 proxy must be specified.

By default, the script reads and writes several files in the working directory. Different paths / filenames can be specified as command line arguments.

- `dns_poison_ip.txt` contains a list of known IP addresses used in poisoned DNS replies. If a DNS lookup done by the OS returns one of these addresses, it is assumed that the host name is under DNS poisoning. (This file is located in the same directory as the script by default.)
- `persistent.txt` contains host names / IP addresses that should always use a certain connection method. See the provided file for examples and comments.
- `state.csv` stores information learned about censored sites.

Run the script with the appropriate arguments, set your browser to use a SOCKS5 / SOCKS4A proxy at 127.0.0.1:1080 or whatever address:port specified using `--bind` and `--bind-port` arguments, and browse away.

Note: the client software must be configured to send the host name to the proxy, instead of resolving the host name and sending the IP address to the proxy. For example, in Firefox, "Proxy DNS when using SOCKS v5" must be turned on. If in doubt, turn on "`--verbose`" and observe the logging output.

### If a convenient uncensored DNS server is not available

The script supports DNS over TLS, and can also use a DNS server through the upstream proxy. If the `--dns` argument is not specified, the script will use CloudFlare's public DNS service over TLS (1dot1dot1dot1.cloudflare-dns.com, more commonly known as 1.1.1.1). This can be combined with `--dns-detour` to tunnel the DNS connection through the upstream SOCKS proxy. With DNS TCP pipelining, the overhead should be minimized.

## Future plans

DNS over TLS is now implemented! I'll have to think of some other Todo item here.

### Features that will not be added

Here are a few features I believe should *not* be part of this script, and how they can be achieved using other tools.

#### HTTP proxy support

HTTP proxies are *complicated*. There are so many corner cases, it's probably shaped after a Koch snowflake (hehe), so I am not going to try cramming it into a single script.

To use Detour Proxy Advance with clients that can only use an HTTP proxy, put an HTTP proxy in front, and set Detour Proxy Advance as its upstream. [TinyProxy](https://tinyproxy.github.io/) (git version), [Privoxy](https://www.privoxy.org/), [Polipo](https://www.irif.fr/~jch/software/polipo/), [3proxy](https://3proxy.ru/) should all work. (Just a note: none of these support non-TLS WebSocket connections. Privoxy and Polipo both fall on their faces if the upstream proxy returns an IPv6 bind address.)
