#include "ui.h"

#include "detector.h"

#include <arpa/inet.h>
#include <curses.h>
#include <locale.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define UI_FRAME_NS      100000000ULL        /* 10 Hz */
#define UI_ALERT_HOT_NS  5000000000ULL       /* badge + reverse video */
#define UI_MIN_COLS      60
#define UI_MIN_LINES     16
#define UI_LINE_MAX      512

enum {
    PAIR_TITLE = 1,
    PAIR_ALERT,
    PAIR_TCP,
    PAIR_UDP,
    PAIR_ICMP,
    PAIR_OTHER,
    PAIR_DIM,
    PAIR_OK
};

struct ui_state {
    struct feed_entry hist[FEED_CAP];    /* indexed by seq & (FEED_CAP - 1) */
    struct feed_entry fetch[FEED_CAP];
    uint64_t newest;                     /* newest seq in hist, 0 = none */
    uint64_t anchor;                     /* seq on the bottom row; 0 = follow */
    int paused;
    int feed_rows;

    struct ana_alert_rec alerts[ANA_ALERT_CAP];   /* oldest first */
    size_t n_alerts;
    uint64_t alert_seq;
    uint64_t alert_hot_until;            /* CLOCK_MONOTONIC ns */

    int colors;
};

static uint64_t mono_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int stop_set(const struct ui *u)
{
    return atomic_load_explicit(u->cfg.stop, memory_order_relaxed);
}

static attr_t pair(const struct ui_state *st, short p)
{
    return st->colors ? (attr_t)COLOR_PAIR(p) : A_NORMAL;
}

#if defined(__GNUC__)
__attribute__((format(printf, 4, 5)))
#endif
static void put(int y, int x, attr_t attr, const char *fmt, ...)
{
    char buf[UI_LINE_MAX];
    va_list ap;

    if (y < 0 || y >= LINES || x >= COLS)
        return;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    attron(attr);
    mvaddnstr(y, x, buf, COLS - x);
    attroff(attr);
}

static void human_bytes(double v, const char *suffix, char *out, size_t len)
{
    static const char *const units[] = { "B", "KB", "MB", "GB", "TB" };
    size_t u = 0;

    while (v >= 1024.0 && u + 1 < sizeof(units) / sizeof(units[0])) {
        v /= 1024.0;
        u++;
    }
    if (u == 0)
        snprintf(out, len, "%.0f %s%s", v, units[u], suffix);
    else
        snprintf(out, len, "%.1f %s%s", v, units[u], suffix);
}

static uint64_t feed_oldest(const struct ui_state *st)
{
    return st->newest >= FEED_CAP ? st->newest - FEED_CAP + 1 : 1;
}

/* Lowest seq the bottom row may show while keeping the panel full. */
static uint64_t min_bottom(const struct ui_state *st)
{
    uint64_t b = feed_oldest(st) + (uint64_t)(st->feed_rows > 0 ?
                                              st->feed_rows - 1 : 0);

    return b < st->newest ? b : st->newest;
}

static void scroll_up(struct ui_state *st, uint64_t n)
{
    uint64_t b;

    if (st->newest == 0)
        return;
    b = st->anchor ? st->anchor : st->newest;
    b = b > n ? b - n : 1;
    if (b < min_bottom(st))
        b = min_bottom(st);
    st->anchor = b >= st->newest ? 0 : b;
}

static void scroll_down(struct ui_state *st, uint64_t n)
{
    if (st->anchor == 0)
        return;
    st->anchor = st->anchor + n >= st->newest ? 0 : st->anchor + n;
}

static void poll_feed(struct ui *u)
{
    struct ui_state *st = u->st;
    size_t n, i;

    if (st->paused)
        return;
    n = feed_since(u->cfg.feed, st->newest, st->fetch, FEED_CAP, NULL);
    for (i = 0; i < n; i++)
        st->hist[st->fetch[i].seq & (FEED_CAP - 1)] = st->fetch[i];
    if (n != 0)
        st->newest = st->fetch[n - 1].seq;
    if (st->anchor != 0) {
        if (st->anchor < min_bottom(st))
            st->anchor = min_bottom(st);
        if (st->anchor >= st->newest)
            st->anchor = 0;
    }
}

static void poll_alerts(struct ui *u, uint64_t now)
{
    struct ui_state *st = u->st;
    struct ana_alert_rec fresh[ANA_ALERT_CAP];
    size_t n = ana_alerts_since(u->cfg.ana, st->alert_seq, fresh,
                                ANA_ALERT_CAP);
    size_t keep;

    if (n == 0)
        return;
    keep = ANA_ALERT_CAP - n;
    if (st->n_alerts > keep) {
        memmove(st->alerts, st->alerts + (st->n_alerts - keep),
                keep * sizeof(st->alerts[0]));
        st->n_alerts = keep;
    }
    memcpy(st->alerts + st->n_alerts, fresh, n * sizeof(fresh[0]));
    st->n_alerts += n;
    st->alert_seq = fresh[n - 1].seq;
    st->alert_hot_until = now + UI_ALERT_HOT_NS;
}

static void draw_separator(int y, const char *title)
{
    mvhline(y, 0, ACS_HLINE, COLS);
    put(y, 2, A_BOLD, " %s ", title);
}

static void draw_title(struct ui *u, uint64_t now)
{
    struct ui_state *st = u->st;
    char right[64], mode[32];
    time_t t = time(NULL);
    struct tm tm;
    attr_t bar = pair(st, PAIR_TITLE) | (st->colors ? A_BOLD : A_REVERSE);
    int x;

    localtime_r(&t, &tm);
    if (st->paused)
        snprintf(mode, sizeof(mode), "PAUSED");
    else if (st->anchor != 0)
        snprintf(mode, sizeof(mode), "SCROLL -%llu",
                 (unsigned long long)(st->newest - st->anchor));
    else
        snprintf(mode, sizeof(mode), "LIVE");
    snprintf(right, sizeof(right), "%s  %02d:%02d:%02d ", mode, tm.tm_hour,
             tm.tm_min, tm.tm_sec);

    attron(bar);
    mvhline(0, 0, ' ', COLS);
    attroff(bar);
    put(0, 0, bar, " net-analyzer | %s | %s%s%s",
        u->cfg.iface ? u->cfg.iface : "all interfaces",
        u->cfg.ingest ? u->cfg.ingest : "recvfrom",
        u->cfg.pcap_path ? " | pcap: " : "",
        u->cfg.pcap_path ? u->cfg.pcap_path : "");
    x = COLS - (int)strlen(right);
    if (now < st->alert_hot_until && x > 10) {
        x -= 8;
        put(0, x, pair(st, PAIR_ALERT) | A_REVERSE | A_BOLD, " ALERT ");
        x += 8;
    }
    if (x > 0)
        put(0, x, bar, "%s", right);
}

static void draw_bar(int y, int x, int width, const char *label, double pct,
                     attr_t color)
{
    int bar_w = width - 17;
    int fill, i;

    if (bar_w < 4)
        bar_w = 4;
    fill = (int)(pct / 100.0 * bar_w + 0.5);
    if (fill > bar_w)
        fill = bar_w;
    put(y, x, A_BOLD, "%-5s", label);
    if (x + 6 >= COLS)
        return;
    mvaddch(y, x + 6, '[');
    for (i = 0; i < bar_w && x + 7 + i < COLS; i++) {
        if (i < fill) {
            attron(color | A_BOLD);
            mvaddch(y, x + 7 + i, '#');
            attroff(color | A_BOLD);
        } else {
            mvaddch(y, x + 7 + i, ' ');
        }
    }
    if (x + 7 + bar_w < COLS)
        mvaddch(y, x + 7 + bar_w, ']');
    put(y, x + 9 + bar_w, A_NORMAL, "%5.1f%%", pct);
}

/* put() at *x, then advance *x past the text. */
#if defined(__GNUC__)
__attribute__((format(printf, 4, 5)))
#endif
static void seg(int y, int *x, attr_t attr, const char *fmt, ...)
{
    char buf[UI_LINE_MAX];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    put(y, *x, attr, "%s", buf);
    *x += n > 0 ? n : 0;
}

static void draw_stats(struct ui *u)
{
    struct ui_state *st = u->st;
    struct ana_snapshot sn;
    struct rb_stats rs;
    char rate[32], total[32];
    double denom;
    int half = COLS / 2;
    int x;

    ana_snapshot(u->cfg.ana, &sn);
    denom = sn.packets ? (double)sn.packets : 1.0;
    human_bytes(sn.bytes_per_sec, "/s", rate, sizeof(rate));
    human_bytes((double)sn.bytes, "", total, sizeof(total));

    x = 1;
    seg(1, &x, A_NORMAL, "Throughput ");
    seg(1, &x, A_BOLD, "%-11s", rate);
    seg(1, &x, A_NORMAL, " %7.0f pkt/s   Total ", sn.pps);
    seg(1, &x, A_BOLD, "%llu pkts / %s", (unsigned long long)sn.packets,
        total);
    seg(1, &x, A_NORMAL, "   ");
    seg(1, &x, sn.alerts ? pair(st, PAIR_ALERT) | A_BOLD : A_NORMAL,
        "Alerts %llu", (unsigned long long)sn.alerts);

    x = 1;
    seg(2, &x, A_NORMAL, "Parsed     ");
    seg(2, &x, pair(st, PAIR_OK), "%llu ok", (unsigned long long)sn.ok);
    seg(2, &x, A_NORMAL, ", %llu truncated, %llu malformed",
        (unsigned long long)sn.truncated, (unsigned long long)sn.malformed);
    if (u->cfg.ring != NULL) {
        uint64_t offered;

        rb_get_stats(u->cfg.ring, &rs);
        offered = rs.pushed + rs.dropped;
        seg(2, &x, A_NORMAL, "   Ring drops %llu (%.2f%%)",
            (unsigned long long)rs.dropped,
            offered ? 100.0 * (double)rs.dropped / (double)offered : 0.0);
    }

    draw_bar(3, 1, half - 1, "TCP",
             100.0 * (double)sn.proto[ANA_PROTO_TCP] / denom,
             pair(st, PAIR_TCP));
    draw_bar(3, half, half - 1, "UDP",
             100.0 * (double)sn.proto[ANA_PROTO_UDP] / denom,
             pair(st, PAIR_UDP));
    draw_bar(4, 1, half - 1, "ICMP",
             100.0 * (double)sn.proto[ANA_PROTO_ICMP] / denom,
             pair(st, PAIR_ICMP));
    draw_bar(4, half, half - 1, "Other",
             100.0 * (double)sn.proto[ANA_PROTO_OTHER] / denom,
             pair(st, PAIR_OTHER));
}

static attr_t proto_attr(const struct ui_state *st, const struct pkt_info *p)
{
    if (p->status != PKT_OK)
        return pair(st, PAIR_ALERT);
    if (p->l3 != PKT_L3_IPV4)
        return pair(st, PAIR_OTHER);
    switch (p->l4) {
    case PKT_L4_TCP:  return pair(st, PAIR_TCP);
    case PKT_L4_UDP:  return pair(st, PAIR_UDP);
    case PKT_L4_ICMP: return pair(st, PAIR_ICMP);
    case PKT_L4_OTHER:
    case PKT_L4_NONE: break;
    }
    return pair(st, PAIR_OTHER);
}

static void draw_feed(struct ui *u, int top, int rows)
{
    struct ui_state *st = u->st;
    char line[UI_LINE_MAX], title[64];
    uint64_t bottom, first, seq;
    int y;

    st->feed_rows = rows;
    snprintf(title, sizeof(title), "Packets (%llu buffered)",
             (unsigned long long)(st->newest - feed_oldest(st) + 1 -
                                  (st->newest == 0)));
    draw_separator(top, title);
    feed_format_header(line, sizeof(line));
    put(top + 1, 1, A_BOLD | A_UNDERLINE, "%s", line);
    top += 2;
    rows -= 2;
    if (rows <= 0)
        return;

    if (st->newest == 0) {
        put(top + rows / 2, 3, pair(st, PAIR_DIM),
            "Waiting for packets on %s ...",
            u->cfg.iface ? u->cfg.iface : "all interfaces");
        return;
    }

    bottom = st->anchor ? st->anchor : st->newest;
    first = feed_oldest(st);
    if (bottom - first + 1 > (uint64_t)rows)
        first = bottom - (uint64_t)rows + 1;
    for (seq = first, y = top; seq <= bottom && y < top + rows; seq++) {
        const struct feed_entry *e = &st->hist[seq & (FEED_CAP - 1)];

        /* feed_since() skips entries the writer lapped mid-copy. */
        if (e->seq != seq)
            continue;
        feed_format(e, line, sizeof(line));
        put(y, 1, A_NORMAL, "%s", line);
        /* Colour just the protocol column. */
        put(y, 1 + FEED_COL_TIME + 1 + FEED_COL_DIR + 1,
            proto_attr(st, &e->info) | A_BOLD, "%-*s", FEED_COL_PROTO,
            pkt_l4_str(&e->info));
        y++;
    }
}

static void draw_alerts(struct ui *u, int top, int rows, uint64_t now)
{
    struct ui_state *st = u->st;
    char title[48], src[INET_ADDRSTRLEN];
    size_t i;
    int y;

    snprintf(title, sizeof(title), "Alerts (%llu)",
             (unsigned long long)st->alert_seq);
    draw_separator(top, title);
    top++;
    if (st->n_alerts == 0) {
        put(top, 3, pair(st, PAIR_DIM),
            "No anomalies detected. Port-scan rule: >%u SYNs to >%u ports "
            "within %.1f s from one source.",
            DET_DEFAULT_SYN_THRESHOLD, DET_DEFAULT_PORT_THRESHOLD,
            (double)DET_DEFAULT_WINDOW_NS / 1e9);
        return;
    }

    for (i = 0, y = top; i < st->n_alerts && y < top + rows; i++, y++) {
        const struct ana_alert_rec *r = &st->alerts[st->n_alerts - 1 - i];
        const struct det_alert *a = &r->alert;
        time_t sec = (time_t)(a->ts_ns / 1000000000ULL);
        struct tm tm;
        attr_t attr = pair(st, PAIR_ALERT) | A_BOLD;

        if (i == 0 && now < st->alert_hot_until)
            attr |= A_REVERSE;
        localtime_r(&sec, &tm);
        inet_ntop(AF_INET, &a->src_ip, src, sizeof(src));
        attron(attr);
        mvhline(y, 0, ' ', COLS);
        attroff(attr);
        put(y, 1, attr, "!! %02d:%02d:%02d  %-18s  src=%-15s  syns=%-3u "
            "ports=%-3u last_dport=%u", tm.tm_hour, tm.tm_min, tm.tm_sec,
            det_event_str(a->type), src, a->syn_count, a->distinct_ports,
            a->last_dst_port);
    }
}

static void draw_help(void)
{
    attron(A_REVERSE);
    mvhline(LINES - 1, 0, ' ', COLS);
    put(LINES - 1, 0, A_REVERSE,
        " q quit | Up/Down j/k scroll | PgUp/PgDn page | g/G oldest/newest "
        "| p pause");
    attroff(A_REVERSE);
}

static void render(struct ui *u, uint64_t now)
{
    int alert_rows, feed_top = 5, feed_rows;

    erase();
    if (COLS < UI_MIN_COLS || LINES < UI_MIN_LINES) {
        put(LINES / 2, 0, A_BOLD, "Terminal too small (%dx%d); need %dx%d.",
            COLS, LINES, UI_MIN_COLS, UI_MIN_LINES);
        refresh();
        return;
    }

    alert_rows = LINES >= 30 ? 6 : LINES >= 22 ? 5 : 3;
    /* title + 4 stats rows, then feed, alert separator + rows, help row */
    feed_rows = LINES - feed_top - (alert_rows + 1) - 1;

    draw_title(u, now);
    draw_stats(u);
    draw_feed(u, feed_top, feed_rows);
    draw_alerts(u, feed_top + feed_rows, alert_rows, now);
    draw_help();
    refresh();
}

/*
 * SIGWINCH path only. resizeterm() queues a KEY_RESIZE, which handle_key()
 * treats as a plain redraw; calling resizeterm() from there as well turns
 * two quick resizes into an endless KEY_RESIZE loop.
 */
static void handle_resize(void)
{
    struct winsize ws;

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0 &&
        ws.ws_col > 0 && is_term_resized(ws.ws_row, ws.ws_col))
        resizeterm(ws.ws_row, ws.ws_col);
    clear();
}

/* Returns 1 if the key changed the view. */
static int handle_key(struct ui *u, int ch)
{
    struct ui_state *st = u->st;
    uint64_t page = st->feed_rows > 3 ? (uint64_t)st->feed_rows - 3 : 1;

    switch (ch) {
    case 'q':
    case 'Q':
        atomic_store_explicit(u->cfg.stop, 1, memory_order_relaxed);
        return 0;
    case KEY_UP:
    case 'k':
        scroll_up(st, 1);
        break;
    case KEY_DOWN:
    case 'j':
        scroll_down(st, 1);
        break;
    case KEY_PPAGE:
    case 'b':
        scroll_up(st, page);
        break;
    case KEY_NPAGE:
    case ' ':
        scroll_down(st, page);
        break;
    case KEY_HOME:
    case 'g':
        scroll_up(st, FEED_CAP);
        break;
    case KEY_END:
    case 'G':
        st->anchor = 0;
        break;
    case 'p':
    case 'P':
        st->paused = !st->paused;
        break;
    case KEY_RESIZE:
        clear();
        break;
    default:
        return 0;
    }
    return 1;
}

int ui_open(struct ui *u, const struct ui_config *cfg)
{
    SCREEN *scr;

    memset(u, 0, sizeof(*u));
    u->cfg = *cfg;
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        fprintf(stderr, "ui: stdin and stdout must be a terminal "
                        "(use -n for console mode)\n");
        return -1;
    }
    u->st = calloc(1, sizeof(*u->st));
    if (u->st == NULL) {
        perror("ui");
        return -1;
    }

    /* In a UTF-8 locale ncursesw draws ACS lines as Unicode, which every
     * terminal and multiplexer renders. */
    setlocale(LC_CTYPE, "");
    /* curses' own SIGTSTP handler would run on an arbitrary thread. */
    signal(SIGTSTP, SIG_IGN);
    scr = newterm(NULL, stdout, stdin);
    if (scr == NULL) {
        fprintf(stderr, "ui: cannot initialise terminal '%s'\n",
                getenv("TERM") ? getenv("TERM") : "(unset)");
        free(u->st);
        u->st = NULL;
        return -1;
    }
    set_term(scr);
    u->screen = scr;
    cbreak();
    noecho();
    nonl();
    intrflush(stdscr, FALSE);
    keypad(stdscr, TRUE);
    set_escdelay(25);
    curs_set(0);
    if (has_colors() && start_color() == OK) {
        short bg = COLOR_BLACK;

        if (use_default_colors() == OK)
            bg = -1;
        init_pair(PAIR_TITLE, COLOR_BLACK, COLOR_CYAN);
        init_pair(PAIR_ALERT, COLOR_RED, bg);
        init_pair(PAIR_TCP, COLOR_GREEN, bg);
        init_pair(PAIR_UDP, COLOR_CYAN, bg);
        init_pair(PAIR_ICMP, COLOR_YELLOW, bg);
        init_pair(PAIR_OTHER, COLOR_MAGENTA, bg);
        init_pair(PAIR_DIM, COLOR_BLUE, bg);
        init_pair(PAIR_OK, COLOR_GREEN, bg);
        u->st->colors = 1;
    }
    erase();
    refresh();
    return 0;
}

void *ui_run(void *arg)
{
    struct ui *u = arg;
    uint64_t next_frame = 0;

    while (!stop_set(u)) {
        uint64_t now = mono_ns();
        int ch, wait_ms;

        if (atomic_exchange_explicit(u->cfg.resize, 0,
                                     memory_order_relaxed)) {
            handle_resize();
            next_frame = 0;
        }
        if (now >= next_frame) {
            poll_feed(u);
            poll_alerts(u, now);
            render(u, now);
            next_frame = now + UI_FRAME_NS;
        }

        wait_ms = (int)((next_frame - now) / 1000000ULL);
        timeout(wait_ms > 0 ? wait_ms : 1);
        ch = getch();
        if (ch != ERR && handle_key(u, ch))
            next_frame = 0;
    }
    return NULL;
}

void ui_close(struct ui *u)
{
    if (u->screen != NULL) {
        curs_set(1);
        endwin();
        delscreen((SCREEN *)u->screen);
        u->screen = NULL;
    }
    free(u->st);
    u->st = NULL;
}
