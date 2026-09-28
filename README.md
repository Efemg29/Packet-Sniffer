# net-analyzer

A raw-socket packet sniffer and protocol analyzer for Linux, written in C11.
It captures Ethernet frames with `AF_PACKET`, dissects L2/L3/L4 headers with
strict bounds checking, and prints one line per packet. Capture and
dissection run on separate threads connected by a lockless ring buffer.

```
16:53:19.374512 OUT ICMP 127.0.0.1 -> 127.0.0.1 len=98 ttl=64 type=8 code=0 payload=56
16:53:20.411799 OUT UDP  127.0.0.1:59941 -> 127.0.0.1:9999 len=47 ttl=64 payload=5
16:53:20.430572 OUT TCP  127.0.0.1:42062 -> 127.0.0.1:47123 len=74 ttl=64 flags=[S] payload=0
16:53:20.430580 OUT TCP  127.0.0.1:47123 -> 127.0.0.1:42062 len=74 ttl=64 flags=[SA] payload=0
16:53:20.430584 OUT TCP  127.0.0.1:42062 -> 127.0.0.1:47123 len=84 ttl=64 flags=[PA] payload=18
```

## Status

Phases 1 and 2 of the roadmap are done: the protocol dissector, and a
two-thread capture pipeline built on a lockless ring buffer. The port-scan
detector, PCAP export, and the ncurses dashboard are planned. Their headers
under `net-analyzer/include/` are placeholders for now.

| Layer | Supported |
|-------|-----------|
| L2    | Ethernet II: MACs and EtherType. IPv6 and ARP are recognised but not dissected |
| L3    | IPv4: addresses, TTL, protocol, header length, fragmentation |
| L4    | TCP (ports, flags, header length, payload size), UDP (ports, length, payload size), ICMP (type, code) |

Truncated or malformed frames never cause out-of-bounds reads. The parser
reports them as `[truncated]` or `[malformed]` and keeps every field it could
decode safely. Non-first IPv4 fragments are shown as `FRAG` and their L4 is
not parsed.

## Architecture

```
AF_PACKET socket ──recvfrom──> [Thread 1: ingestion] ──> ring buffer ──> [Thread 2: dissector] ──> stdout
                                                                          parse_packet + print
[main thread: sigtimedwait(SIGINT, SIGTERM)] ── sets stop flag, joins both threads
```

- **Ring buffer** (`src/ring_buffer.c`): a single-producer / single-consumer
  ring with a power-of-two number of slots. Each slot holds a full
  `MAX_PACKET_LEN` (64 KiB) frame plus its captured length, on-wire length,
  capture timestamp, and packet type. All slots are allocated once with
  `mmap(MAP_POPULATE)` at startup, so the hot path never calls `malloc` and
  never page-faults. Head and tail are C11 atomics on separate cache lines,
  with acquire/release ordering, and each side caches the other's index.
- **Thread 1** reserves a slot and calls `recvfrom` directly into it, so there
  is one copy per frame. If the ring is full, the frame is read into a scratch
  buffer. If a slot has freed up by the time `recvfrom` returns, the frame is
  copied into it. Otherwise it is counted as a ring drop.
- **Thread 2** pops slots, parses and prints them, then releases them. When
  the ring is empty it yields, then sleeps for 100 µs.
- **Signals**: `SIGINT` and `SIGTERM` are blocked in every thread, and the
  main thread alone receives them with `sigtimedwait`. On a stop request,
  Thread 1 exits within one 250 ms `SO_RCVTIMEO` tick. Thread 2 then drains
  whatever is still queued, both threads are joined, and the program prints a
  summary and exits with code 0.

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
sudo ./build/net-analyzer -i lo -q -b 1024   # no per-packet output, 1024-slot ring
```

| Option     | Meaning |
|------------|---------|
| `-i IFACE` | Capture only on `IFACE`. By default all interfaces are captured |
| `-c COUNT` | Stop after `COUNT` packets |
| `-b SLOTS` | Ring buffer slots, rounded up to a power of two, 2 to 16384 (default 256, which is 16 MiB) |
| `-p`       | Enable promiscuous mode on `IFACE` (requires `-i`) |
| `-q`       | Quiet: dissect and count packets but do not print them |
| `-h`       | Show help |

To run without sudo, grant the capability once:

```sh
sudo setcap cap_net_raw+ep ./build/net-analyzer
```

Stop with Ctrl-C or `SIGTERM`. The program drains the ring, closes the
socket, prints a summary and exits with code 0. On `lo` every packet appears
twice, once as `OUT` and once as `IN`, because the kernel loops it back.

```
3100 packets dissected: 3100 ok, 0 truncated, 0 malformed
ring (8 slots): 3100 queued, 16 dropped (0.513%), 0 left unprocessed
kernel: 3116 packets, 0 dropped by socket
```

`ring ... dropped` counts frames Thread 1 read but had no free slot for.
`kernel ... dropped by socket` comes from `PACKET_STATISTICS` and counts frames
the kernel discarded because the socket receive buffer was full, meaning
Thread 1 was not calling `recvfrom` fast enough. `left unprocessed` is
non-zero only when `-c` stops the worker with frames still queued.

## Test

```sh
cd net-analyzer
make test               # parser and ring buffer unit tests
make sanitize           # the same tests under AddressSanitizer + UBSan
make tsan               # ring buffer tests under ThreadSanitizer
```

With CMake, run `ctest --test-dir build`.

The tests use handcrafted frames: valid TCP, UDP, and ICMP, IP and TCP
options, Ethernet padding, fragments, and IPv6 and ARP EtherTypes. They also
cover malformed input: `ihl < 5`, `doff < 5`, bad IP versions, inconsistent
length fields, and truncation at every layer. Every prefix of each valid frame
is parsed from an exact-size heap buffer, and 200,000 random frames are fuzzed
through the parser, so the sanitizer build catches any over-read.

The ring buffer tests cover power-of-two rounding, FIFO order, full-ring
behaviour and drop accounting, wraparound, and full 64 KiB slots. They also
include a two-thread producer/consumer stress test. In lossless mode (8 and 2
slots) it pushes 1,000,000 frames and checks every one arrives in order with
intact contents and metadata. In lossy mode the producer drops when the ring
is full, and the test checks that `delivered + dropped == offered`. Set
`RB_STRESS_ITERS` to change the frame count; `make tsan` uses 200,000.

On some Clang installs the sanitizer runtimes are missing. If `make sanitize`
or `make tsan` fails to link, use `make CC=gcc sanitize` or `make CC=gcc tsan`.

## Benchmark

`scripts/bench_loopback.sh` runs the analyzer on `lo` while `iperf3` pushes
traffic for a few seconds, then prints the drop summary. It covers several
ring sizes, with per-packet output either off (`-q`) or sent to `/dev/null`.

```sh
cd net-analyzer
make && sudo scripts/bench_loopback.sh 5          # SLOTS="8 256 1024" by default
```

Results from a 4-vCPU cloud VM (Intel Xeon, kernel 6.12, iperf3 3.16), with
iperf3 running on the same machine, 5 seconds per run. `TCP max` is a single
TCP stream at full speed; loopback GSO produces frames of up to 64 KiB, at
about 54 Gbit/s. `UDP 64B` is `-u -b 0 -l 64`, the smallest frames at the
highest packet rate, about 100 Mbit/s of payload. Frames per run were about
2.0 to 2.3 million, counting both `OUT` and `IN` copies. Ring and kernel drops
are percentages of the frames the socket saw.

| Traffic  | Slots | Output    | Ring drops | Kernel drops | Total loss |
|----------|------:|-----------|-----------:|-------------:|-----------:|
| TCP max  |     8 | quiet     |     13.10% |        0.41% |     13.46% |
| TCP max  |     8 | /dev/null |     17.59% |        0.50% |     18.00% |
| UDP 64B  |     8 | quiet     |      9.31% |        0.26% |      9.55% |
| UDP 64B  |     8 | /dev/null |     11.52% |        0.25% |     11.74% |
| TCP max  |   256 | quiet     |      0.14% |       18.33% |     18.45% |
| TCP max  |   256 | /dev/null |      0.03% |       14.29% |     14.32% |
| UDP 64B  |   256 | quiet     |      0.59% |        0.66% |      1.24% |
| UDP 64B  |   256 | /dev/null |      1.53% |        0.32% |      1.85% |
| TCP max  |  1024 | quiet     |     0.003% |       13.78% |     13.78% |
| TCP max  |  1024 | /dev/null |     0.005% |       10.19% |     10.20% |
| UDP 64B  |  1024 | quiet     |     0.018% |        0.85% |      0.86% |
| UDP 64B  |  1024 | /dev/null |      0.19% |        0.31% |      0.50% |

What this shows:

- An 8-slot ring overflows on short bursts. At 256 slots or more, ring drops
  fall below 2% for small frames and to almost zero for TCP, so the dissector
  keeps up with the ingestion thread.
- At 256 slots or more, TCP loss happens in the kernel, not the ring.
  Thread 1 makes one `recvfrom` syscall per frame and copies up to 64 KiB into
  a slot. At about 54 Gbit/s the default socket receive buffer (about 208 KiB,
  or 3 frames) overflows. The 8-slot run has lower kernel drops because its
  512 KiB of slots stays in cache, while 256 slots are 16 MiB.
- Output to `/dev/null` costs little. Printing to a real terminal is much
  slower and pushes ring drops up.
- Run-to-run variance is several percentage points, because iperf3 shares the
  same 4 vCPUs. Treat the numbers as orders of magnitude.

The next steps for ingestion are a larger `SO_RCVBUF` and, eventually, a
`PACKET_RX_RING` (TPACKET_V3) memory-mapped ring to remove the per-frame
syscall and copy.

## Layout

```
net-analyzer/
├── Makefile, CMakeLists.txt
├── include/   parser.h, ring_buffer.h, config.h (+ placeholder headers for later phases)
├── src/       main.c (threads, signals), parser.c (dissector), ring_buffer.c (SPSC ring)
├── scripts/   bench_loopback.sh (iperf3 drop-rate benchmark)
└── tests/     test_parser.c, test_ring_buffer.c
```

## License

[MIT](LICENSE) © Efe Güner
