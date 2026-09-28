# net-analyzer

A raw-socket packet sniffer and protocol analyzer for Linux, written in C11.
It captures Ethernet frames with `AF_PACKET`, dissects L2/L3/L4 headers with
strict bounds checking, and prints one line per packet.

```
16:53:19.374512 OUT ICMP 127.0.0.1 -> 127.0.0.1 len=98 ttl=64 type=8 code=0 payload=56
16:53:20.411799 OUT UDP  127.0.0.1:59941 -> 127.0.0.1:9999 len=47 ttl=64 payload=5
16:53:20.430572 OUT TCP  127.0.0.1:42062 -> 127.0.0.1:47123 len=74 ttl=64 flags=[S] payload=0
16:53:20.430580 OUT TCP  127.0.0.1:47123 -> 127.0.0.1:42062 len=74 ttl=64 flags=[SA] payload=0
16:53:20.430584 OUT TCP  127.0.0.1:42062 -> 127.0.0.1:47123 len=84 ttl=64 flags=[PA] payload=18
```

## Status

This is Phase 1 of the roadmap: the protocol dissector and a single-threaded
capture loop. The ring buffer and threading, the port-scan detector, PCAP
export, and the ncurses dashboard are planned. Their headers under
`net-analyzer/include/` are placeholders for now.

| Layer | Supported |
|-------|-----------|
| L2    | Ethernet II: MACs and EtherType. IPv6 and ARP are recognised but not dissected |
| L3    | IPv4: addresses, TTL, protocol, header length, fragmentation |
| L4    | TCP (ports, flags, header length, payload size), UDP (ports, length, payload size), ICMP (type, code) |

Truncated or malformed frames never cause out-of-bounds reads. The parser
reports them as `[truncated]` or `[malformed]` and keeps every field it could
decode safely. Non-first IPv4 fragments are shown as `FRAG` and their L4 is
not parsed.

## Requirements

- Linux with glibc
- GCC or Clang with C11 support, `make` (or CMake 3.16 or newer)
- Root or `CAP_NET_RAW` to capture

## Build

```sh
cd net-analyzer
make                    # produces build/net-analyzer
```

Or with CMake:

```sh
cmake -S net-analyzer -B build
cmake --build build
```

Everything is compiled with `-std=c11 -Wall -Wextra -Wpedantic -Werror -O2 -pthread`.

## Run

```sh
sudo ./build/net-analyzer -i lo              # loopback only
sudo ./build/net-analyzer -i eth0 -p         # eth0 in promiscuous mode
sudo ./build/net-analyzer -c 100             # all interfaces, stop after 100 packets
```

| Option     | Meaning |
|------------|---------|
| `-i IFACE` | Capture only on `IFACE`. By default all interfaces are captured |
| `-c COUNT` | Stop after `COUNT` packets |
| `-p`       | Enable promiscuous mode on `IFACE` (requires `-i`) |
| `-h`       | Show help |

To run without sudo, grant the capability once:

```sh
sudo setcap cap_net_raw+ep ./build/net-analyzer
```

Stop with Ctrl-C or `SIGTERM`. The program closes the socket, prints a summary
(ok / truncated / malformed counts) and exits with code 0. On `lo` every packet
appears twice, once as `OUT` and once as `IN`, because the kernel loops it back.

## Test

```sh
cd net-analyzer
make test               # parser unit tests
make sanitize           # the same tests under AddressSanitizer + UBSan
```

With CMake, run `ctest --test-dir build`.

The tests use handcrafted frames: valid TCP, UDP, and ICMP, IP and TCP
options, Ethernet padding, fragments, and IPv6 and ARP EtherTypes. They also
cover malformed input: `ihl < 5`, `doff < 5`, bad IP versions, inconsistent
length fields, and truncation at every layer. Every prefix of each valid frame
is parsed from an exact-size heap buffer, and 200,000 random frames are fuzzed
through the parser, so the sanitizer build catches any over-read.

On some Clang installs the sanitizer runtime is missing. If `make sanitize`
fails to link, use `make CC=gcc sanitize`.

## Layout

```
net-analyzer/
├── Makefile, CMakeLists.txt
├── include/   parser.h, config.h (+ placeholder headers for later phases)
├── src/       main.c (capture loop), parser.c (dissector)
└── tests/     test_parser.c
```

## License

[MIT](LICENSE) © Efe Güner
