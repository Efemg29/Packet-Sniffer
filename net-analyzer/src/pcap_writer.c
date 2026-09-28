#include "pcap_writer.h"

#include <errno.h>
#include <string.h>

static void put_u16(uint8_t *p, uint16_t v)
{
    memcpy(p, &v, sizeof(v));
}

static void put_u32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, sizeof(v));
}

void pcap_encode_global_header(uint8_t out[PCAP_GLOBAL_HDR_LEN])
{
    put_u32(out + 0, PCAP_MAGIC);
    put_u16(out + 4, PCAP_VERSION_MAJOR);
    put_u16(out + 6, PCAP_VERSION_MINOR);
    put_u32(out + 8, 0);                     /* thiszone: UTC */
    put_u32(out + 12, 0);                    /* sigfigs */
    put_u32(out + 16, PCAP_SNAPLEN);
    put_u32(out + 20, PCAP_LINKTYPE_ETHERNET);
}

void pcap_encode_record_header(uint8_t out[PCAP_RECORD_HDR_LEN],
                               const struct timespec *ts, uint32_t cap_len,
                               uint32_t orig_len)
{
    uint32_t incl = cap_len < PCAP_SNAPLEN ? cap_len : PCAP_SNAPLEN;
    uint32_t usec = 0;
    uint32_t sec = 0;

    if (ts != NULL && ts->tv_sec >= 0) {
        sec = (uint32_t)ts->tv_sec;
        if (ts->tv_nsec >= 0 && ts->tv_nsec < 1000000000L)
            usec = (uint32_t)(ts->tv_nsec / 1000L);
    }
    if (orig_len < incl)
        orig_len = incl;
    put_u32(out + 0, sec);
    put_u32(out + 4, usec);
    put_u32(out + 8, incl);
    put_u32(out + 12, orig_len);
}

static int fail(struct pcap_writer *w, int e)
{
    if (w->err == 0)
        w->err = e != 0 ? e : EIO;
    return w->err;
}

int pcap_open(struct pcap_writer *w, const char *path)
{
    uint8_t hdr[PCAP_GLOBAL_HDR_LEN];

    w->fp = NULL;
    w->packets = 0;
    w->bytes = 0;
    w->unflushed = 0;
    w->err = 0;
    if (path == NULL)
        return w->err = EINVAL;

    w->fp = fopen(path, "wb");
    if (w->fp == NULL)
        return w->err = errno;
    if (setvbuf(w->fp, w->iobuf, _IOFBF, sizeof(w->iobuf)) != 0) {
        fail(w, errno);
        fclose(w->fp);
        w->fp = NULL;
        return w->err;
    }

    pcap_encode_global_header(hdr);
    if (fwrite(hdr, 1, sizeof(hdr), w->fp) != sizeof(hdr) ||
        fflush(w->fp) != 0) {
        fail(w, errno);
        fclose(w->fp);
        w->fp = NULL;
        return w->err;
    }
    w->bytes = sizeof(hdr);
    return 0;
}

int pcap_write(struct pcap_writer *w, const struct timespec *ts,
               const void *data, uint32_t cap_len, uint32_t orig_len)
{
    uint8_t hdr[PCAP_RECORD_HDR_LEN];
    uint32_t incl = cap_len < PCAP_SNAPLEN ? cap_len : PCAP_SNAPLEN;

    if (w->err != 0)
        return w->err;
    if (w->fp == NULL || (data == NULL && incl != 0))
        return fail(w, EINVAL);

    pcap_encode_record_header(hdr, ts, cap_len, orig_len);
    if (fwrite(hdr, 1, sizeof(hdr), w->fp) != sizeof(hdr) ||
        (incl != 0 && fwrite(data, 1, incl, w->fp) != incl))
        return fail(w, errno);

    w->packets++;
    w->unflushed++;
    w->bytes += sizeof(hdr) + incl;
    return 0;
}

int pcap_flush(struct pcap_writer *w)
{
    if (w->fp == NULL)
        return w->err;
    if (w->unflushed != 0 && w->err == 0 && fflush(w->fp) != 0)
        fail(w, errno);
    w->unflushed = 0;
    return w->err;
}

int pcap_close(struct pcap_writer *w)
{
    if (w->fp != NULL) {
        if (w->err == 0 && fflush(w->fp) != 0)
            fail(w, errno);
        if (fclose(w->fp) != 0)
            fail(w, errno);
        w->fp = NULL;
    }
    return w->err;
}
