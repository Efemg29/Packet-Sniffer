#ifndef NET_ANALYZER_PCAP_WRITER_H
#define NET_ANALYZER_PCAP_WRITER_H

#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>

/*
 * Classic libpcap file writer (spec 4.4), no libpcap dependency.
 *
 * Global header (24 bytes): magic 0xa1b2c3d4 (microsecond timestamps),
 * version 2.4, thiszone 0, sigfigs 0, snaplen PCAP_SNAPLEN, linktype
 * PCAP_LINKTYPE_ETHERNET. Record header (16 bytes): ts_sec, ts_usec,
 * incl_len, orig_len. All fields are in host byte order, as libpcap itself
 * writes them; readers detect the order from the magic.
 *
 * Frames longer than the snaplen are truncated to it (incl_len) while
 * orig_len keeps the on-wire length.
 *
 * The stdio buffer lives inside the struct, so pcap_write() never
 * allocates. One thread owns a writer.
 */

#define PCAP_MAGIC             0xa1b2c3d4u
#define PCAP_VERSION_MAJOR     2
#define PCAP_VERSION_MINOR     4
#define PCAP_LINKTYPE_ETHERNET 1
#define PCAP_GLOBAL_HDR_LEN    24
#define PCAP_RECORD_HDR_LEN    16
#define PCAP_IO_BUF            (256 * 1024)

struct pcap_writer {
    FILE *fp;
    uint64_t packets;          /* records written */
    uint64_t bytes;            /* file bytes written, headers included */
    uint64_t unflushed;        /* records since the last pcap_flush() */
    int err;                   /* first errno seen; writes stop after it */
    char iobuf[PCAP_IO_BUF];
};

/* Create/truncate path and write the global header. Returns 0 or an errno. */
int pcap_open(struct pcap_writer *w, const char *path);

/*
 * Append one frame captured at ts. cap_len bytes of data are available;
 * orig_len is the on-wire length. Returns 0, or the sticky errno.
 */
int pcap_write(struct pcap_writer *w, const struct timespec *ts,
               const void *data, uint32_t cap_len, uint32_t orig_len);

/* Push buffered records to the kernel. Returns 0 or the sticky errno. */
int pcap_flush(struct pcap_writer *w);

/* Flush and close. Safe to call on a writer that failed or never opened.
 * Returns 0 or the first errno seen over the writer's lifetime. */
int pcap_close(struct pcap_writer *w);

/* Serialise headers into out (exposed for tests). */
void pcap_encode_global_header(uint8_t out[PCAP_GLOBAL_HDR_LEN]);
void pcap_encode_record_header(uint8_t out[PCAP_RECORD_HDR_LEN],
                               const struct timespec *ts, uint32_t cap_len,
                               uint32_t orig_len);

#endif
