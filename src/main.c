/*
 * cake-autorate – C rewrite for OpenWrt
 *
 * Standalone CAKE autorate daemon: no SQM scripts required.
 *
 * Lifecycle managed entirely in-process via tc_netlink.c:
 *   Startup  → tc_dl_setup() + tc_ul_setup()
 *   Runtime  → tc_cake_set_bandwidth()
 *   Shutdown → tc_dl_teardown() + tc_ul_teardown()
 *
 * Algorithm mirrors cake-autorate.sh:
 *   • ICMP ping via raw IPv4 socket (in-process, no external pinger binary)
 *     – ping_type 0: ICMP Echo (type 8/0) – RTT/2, symmetric assumption
 *     – ping_type 1: ICMP Timestamp (type 13/14) – true per-direction OWD
 *   • Rate monitor via /sys/class/net polling
 *   • OWD EWMA baseline + delta sliding window for bufferbloat detection
 *   • Reflector health monitoring with automatic replacement
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <libubox/uloop.h>

#include "config.h"
#include "rate_monitor.h"
#include "tc_netlink.h"
#include "traffic_detector.h"

/* ────────────────────────────────────────────────────────────── */
/*  Constants                                                     */
/* ────────────────────────────────────────────────────────────── */
#define DIR_DL 0
#define DIR_UL 1

#define LOAD_IDLE 0
#define LOAD_LOW  1
#define LOAD_HIGH 2
#define LOAD_BB   3

#define STATE_RUNNING 0
#define STATE_IDLE    1
#define STATE_STALL   2

#define MAX_OFFENCE_WINDOW 64

/* ────────────────────────────────────────────────────────────── */
/*  ICMP Timestamp (type 13/14) definitions                       */
/* ────────────────────────────────────────────────────────────── */

#ifndef ICMP_TIMESTAMP
#define ICMP_TIMESTAMP      13
#define ICMP_TIMESTAMPREPLY 14
#endif

struct icmp_ts_body {
    uint32_t originate;
    uint32_t receive;
    uint32_t transmit;
};

#define MS_PER_DAY 86400000UL

/*
 * PING_SEQ_RING – sequence number ring for correlating type-13 replies.
 *
 * 512 slots × ~50 ms interval = 25.6 s wrap period, safely covering
 * any real-world reflector RTT and preventing stale-reply collisions.
 */
#define PING_SEQ_RING 512

typedef struct {
    int64_t  t_sent_us;
    uint32_t originate_ms;
    int      reflector_idx;
    uint16_t expected_seq;  /* reject heavily delayed out-of-order replies */
} ping_seq_slot_t;

/* ────────────────────────────────────────────────────────────── */
/*  Per-reflector runtime state                                   */
/* ────────────────────────────────────────────────────────────── */
typedef struct {
    char    addr[64];
    uint32_t addr_be;
    int64_t dl_owd_baseline_us;
    int64_t ul_owd_baseline_us;
    int64_t dl_owd_delta_ewma_us;
    int64_t ul_owd_delta_ewma_us;
    int64_t last_response_us;
    int     offences[MAX_OFFENCE_WINDOW];
    int     offences_idx;
    int     sum_offences;
    /*
     * baseline_valid guards the initial OWD baseline assignment.
     * Using (baseline == 0) as a sentinel fails when the first measured
     * OWD is exactly 0 µs (LAN reflector, or type-13 receive == originate),
     * causing all subsequent deltas to be computed from zero and inflating
     * them into false bufferbloat detections.
     */
    int     baseline_valid;
} reflector_t;

/* ────────────────────────────────────────────────────────────── */
/*  Global application state                                      */
/* ────────────────────────────────────────────────────────────── */
typedef struct {
    cake_config_t   cfg;
    rate_monitor_t  rm;
    tc_nl_ctx_t    *tc_nl;

    uint32_t shaper_rate_kbps[2];
    uint32_t last_shaper_rate_kbps[2];

    uint32_t achieved_rate_kbps[2];
    int      achieved_rate_updated[2];

    int      load_condition[2];
    int      bufferbloat_detected[2];
    int64_t  t_last_bufferbloat_us[2];
    int64_t  t_last_decay_us[2];

    int     *dl_delays;
    int     *ul_delays;
    int64_t *dl_owd_deltas_us;
    int64_t *ul_owd_deltas_us;
    int      delays_idx;
    int      delays_fill;
    int64_t  sum_dl_delays;
    int64_t  sum_ul_delays;
    int64_t  sum_dl_owd_deltas_us;
    int64_t  sum_ul_owd_deltas_us;
    int64_t  avg_owd_delta_us[2];

    reflector_t reflectors[MAX_REFLECTORS];
    int         no_active_reflectors;
    int         spare_idx;
    int64_t     t_last_reflector_health_us;
    int64_t     global_last_response_us;

    int               icmp_sock;
    struct uloop_fd   icmp_ufd;
    struct uloop_timeout ping_timer;
    uint16_t          ping_id;
    uint16_t          ping_seq;
    int               ping_rr_idx;

    ping_seq_slot_t   ping_seq_ring[PING_SEQ_RING];

    struct uloop_timeout rate_timer;
    struct uloop_timeout health_timer;

    int main_state;

    int64_t ping_response_interval_us;

    int dl_setup_done;
    int ul_setup_done;

    struct uloop_timeout if_up_timer;
    int                  link_up;

    int64_t t_started_us;
    int64_t t_pinger_started_us;

    traffic_detector_t  td;
    int                 shaping_bypassed;

    int                 offload_cap;
    int                 offload_active;
} autorate_t;

/* ────────────────────────────────────────────────────────────── */
/*  Helpers                                                       */
/* ────────────────────────────────────────────────────────────── */
static int64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000LL;
}

/*
 * sleep_us – portable sleep via nanosleep.
 * Handles values ≥ 1 s correctly and resumes after EINTR.
 */
static void sleep_us(int64_t us)
{
    if (us <= 0)
        return;
    struct timespec ts;
    ts.tv_sec  = us / 1000000LL;
    ts.tv_nsec = (us % 1000000LL) * 1000LL;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
        ;
}

static void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ────────────────────────────────────────────────────────────── */
/*  Runtime status file  (/var/run/darkmoon.json)                 */
/* ────────────────────────────────────────────────────────────── */

static const char *load_str(int cond)
{
    switch (cond) {
        case LOAD_LOW:  return "low";
        case LOAD_HIGH: return "high";
        case LOAD_BB:   return "bufferbloat";
        default:        return "idle";
    }
}

static const char *state_str(int s)
{
    switch (s) {
        case STATE_IDLE:  return "idle";
        case STATE_STALL: return "stall";
        default:          return "running";
    }
}

static void write_status_file(autorate_t *ar)
{
    static const char *path     = "/var/run/darkmoon.json";
    static const char *path_tmp = "/var/run/darkmoon.json.tmp";

    FILE *f = fopen(path_tmp, "w");
    if (!f)
        return;

    int64_t uptime_s = (now_us() - ar->t_started_us) / 1000000LL;

    /*
     * Round avg_owd_delta_us to 0.1 ms units with correct sign handling.
     * (val + 50) / 100 rounds toward zero for negative values, e.g.
     * -75 µs → 0 instead of -1.  Apply the bias in the direction of val.
     */
    int64_t dl_raw = ar->avg_owd_delta_us[DIR_DL];
    int64_t ul_raw = ar->avg_owd_delta_us[DIR_UL];
    long dl_owd_ms10 = (long)((dl_raw >= 0) ? (dl_raw + 50LL) / 100LL
                                             : (dl_raw - 50LL) / 100LL);
    long ul_owd_ms10 = (long)((ul_raw >= 0) ? (ul_raw + 50LL) / 100LL
                                             : (ul_raw - 50LL) / 100LL);

    fprintf(f,
        "{\n"
        "  \"instance\": \"%s\",\n"
        "  \"state\": \"%s\",\n"
        "  \"link_up\": %d,\n"
        "  \"dl_if\": \"%s\",\n"
        "  \"ul_if\": \"%s\",\n"
        "  \"shaper_dl_kbps\": %u,\n"
        "  \"shaper_ul_kbps\": %u,\n"
        "  \"achieved_dl_kbps\": %u,\n"
        "  \"achieved_ul_kbps\": %u,\n"
        "  \"load_dl\": \"%s\",\n"
        "  \"load_ul\": \"%s\",\n"
        "  \"bb_dl\": %d,\n"
        "  \"bb_ul\": %d,\n"
        "  \"avg_owd_dl_ms10\": %ld,\n"
        "  \"avg_owd_ul_ms10\": %ld,\n"
        "  \"active_reflectors\": %d,\n"
        "  \"smart_shaping_enabled\": %d,\n"
        "  \"smart_shaping_active\": %d,\n"
        "  \"shaping_bypassed\": %d,\n"
        "  \"offload_capability\": %d,\n"
        "  \"offload_active\": %d,\n"
        "  \"uptime_s\": %lld\n"
        "}\n",
        ar->cfg.instance_id,
        state_str(ar->main_state),
        ar->link_up,
        ar->cfg.dl_if,
        ar->cfg.ul_if,
        ar->shaper_rate_kbps[DIR_DL],
        ar->shaper_rate_kbps[DIR_UL],
        ar->achieved_rate_kbps[DIR_DL],
        ar->achieved_rate_kbps[DIR_UL],
        load_str(ar->load_condition[DIR_DL]),
        load_str(ar->load_condition[DIR_UL]),
        ar->bufferbloat_detected[DIR_DL],
        ar->bufferbloat_detected[DIR_UL],
        dl_owd_ms10,
        ul_owd_ms10,
        ar->no_active_reflectors,
        ar->cfg.smart_shaping_enabled,
        traffic_detector_is_active(&ar->td),
        ar->shaping_bypassed,
        ar->offload_cap,
        ar->offload_active,
        (long long)uptime_s
    );

    fclose(f);

    if (rename(path_tmp, path) < 0)
        syslog(LOG_WARNING, "write_status_file: rename failed: %m");
}

/* ────────────────────────────────────────────────────────────── */
/*  Build cake_qdisc_opts_t from config                           */
/* ────────────────────────────────────────────────────────────── */

static cake_qdisc_opts_t make_dl_opts(const cake_config_t *c)
{
    cake_qdisc_opts_t o;
    memset(&o, 0, sizeof(o));
    o.overhead   = c->cake_overhead;
    o.mpu        = c->cake_mpu;
    o.nat        = c->cake_nat;
    o.wash       = 0;
    o.ingress    = 1;
    o.ack_filter = 0;
    o.diffserv   = (uint32_t)c->cake_diffserv;
    o.flow_mode  = (uint32_t)c->cake_dl_flow_mode;
    o.atm        = (uint32_t)c->cake_atm;
    o.rtt_us     = c->cake_rtt_us;
    o.split_gso  = (uint32_t)c->cake_split_gso;
    o.use_cake_mq = (uint32_t)c->cake_mq;
    return o;
}

static cake_qdisc_opts_t make_ul_opts(const cake_config_t *c)
{
    cake_qdisc_opts_t o;
    memset(&o, 0, sizeof(o));
    o.overhead   = c->cake_overhead;
    o.mpu        = c->cake_mpu;
    o.nat        = c->cake_nat;
    o.wash       = (uint32_t)c->cake_wash;
    o.ingress    = 0;
    o.ack_filter = (uint32_t)c->cake_ack_filter;
    o.diffserv   = (uint32_t)c->cake_diffserv;
    o.flow_mode  = (uint32_t)c->cake_ul_flow_mode;
    o.atm        = (uint32_t)c->cake_atm;
    o.rtt_us     = c->cake_rtt_us;
    o.split_gso  = (uint32_t)c->cake_split_gso;
    o.use_cake_mq = (uint32_t)c->cake_mq;
    return o;
}

/* ────────────────────────────────────────────────────────────── */
/*  darkmoon-shaper: nftables DSCP marking rules                  */
/* ────────────────────────────────────────────────────────────── */

#define DSCP_NFT_TABLE  "darkmoon_dscp"
#define DSCP_NFT_FILE   "/var/run/darkmoon-dscp.nft"

static int dscp_name_to_val(const char *s)
{
    struct { const char *name; int val; } tbl[] = {
        { "ef",   46 }, { "va",   44 }, { "cs7",  56 }, { "cs6",  48 },
        { "cs5",  40 }, { "cs4",  32 }, { "cs3",  24 }, { "cs2",  16 },
        { "cs1",   8 }, { "cs0",   0 }, { "be",    0 },
        { "af41", 34 }, { "af42", 36 }, { "af43", 38 },
        { "af31", 26 }, { "af32", 28 }, { "af33", 30 },
        { "af21", 18 }, { "af22", 20 }, { "af23", 22 },
        { "af11", 10 }, { "af12", 12 }, { "af13", 14 },
        { NULL,   -1 }
    };
    for (int i = 0; tbl[i].name; i++)
        if (strcasecmp(s, tbl[i].name) == 0)
            return tbl[i].val;
    char *end;
    long v = strtol(s, &end, 10);
    if (end != s && *end == '\0' && v >= 0 && v <= 63)
        return (int)v;
    return -1;
}

static int dscp_rules_load(const cake_config_t *c, uint64_t *out_mask)
{
    const char *rules_path = c->gaming_rules_file;
    *out_mask = 0;

    if (!rules_path || rules_path[0] == '\0') {
        syslog(LOG_INFO, "dscp_rules: no gaming_rules_file configured");
        return 0;
    }

    FILE *rules = fopen(rules_path, "r");
    if (!rules) {
        syslog(LOG_WARNING, "dscp_rules: cannot open '%s': %s",
               rules_path, strerror(errno));
        return -1;
    }

    FILE *nft = fopen(DSCP_NFT_FILE, "w");
    if (!nft) {
        fclose(rules);
        syslog(LOG_ERR, "dscp_rules: cannot write '%s': %s",
               DSCP_NFT_FILE, strerror(errno));
        return -1;
    }

    fprintf(nft,
        "# Auto-generated by darkmoon – do not edit\n"
        "# Source: %s\n"
        "table inet " DSCP_NFT_TABLE " {\n"
        "    counter " TDETECT_NFT_COUNTER " { }\n"
        "    chain forward {\n"
        "        type filter hook forward priority mangle; policy accept;\n\n",
        rules_path);

    char line[256];
    int  rule_count = 0;
    int  line_num   = 0;

    while (fgets(line, sizeof(line), rules)) {
        line_num++;
        int len = (int)strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' ||
                           line[len-1] == ' '  || line[len-1] == '\t'))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#')
            continue;

        if (strcasecmp(line, "small-udp-ef") == 0) {
            fprintf(nft,
                "        # small UDP → EF (game state updates)\n"
                "        ip protocol udp meta length < 200 ip dscp set ef\n\n");
            *out_mask |= (1ULL << 46);
            rule_count++;
            continue;
        }

        char tok_proto[16], tok_port[32], tok_dscp[16];
        if (sscanf(line, "%15s %31s %15s", tok_proto, tok_port, tok_dscp) != 3) {
            syslog(LOG_WARNING, "dscp_rules: parse error at line %d: '%s'",
                   line_num, line);
            continue;
        }

        int do_udp = 0, do_tcp = 0;
        if      (strcasecmp(tok_proto, "udp")  == 0) do_udp = 1;
        else if (strcasecmp(tok_proto, "tcp")  == 0) do_tcp = 1;
        else if (strcasecmp(tok_proto, "both") == 0) { do_udp = do_tcp = 1; }
        else {
            syslog(LOG_WARNING, "dscp_rules: unknown proto '%s' line %d",
                   tok_proto, line_num);
            continue;
        }

        int dscp_val = dscp_name_to_val(tok_dscp);
        if (dscp_val < 0) {
            syslog(LOG_WARNING, "dscp_rules: unknown DSCP '%s' line %d",
                   tok_dscp, line_num);
            continue;
        }

        *out_mask |= (1ULL << dscp_val);

        if (do_udp)
            fprintf(nft,
                "        ip protocol udp udp dport %s ip dscp set %s\n"
                "        ip protocol udp udp sport %s ip dscp set %s\n",
                tok_port, tok_dscp, tok_port, tok_dscp);
        if (do_tcp)
            fprintf(nft,
                "        ip protocol tcp tcp dport %s ip dscp set %s\n"
                "        ip protocol tcp tcp sport %s ip dscp set %s\n",
                tok_port, tok_dscp, tok_port, tok_dscp);
        rule_count++;
    }

    fclose(rules);

    fprintf(nft,
        "\n"
        "        ip dscp != cs0 counter name " TDETECT_NFT_COUNTER "\n"
        "    }\n\n");

    fprintf(nft,
        "    chain postrouting {\n"
        "        type filter hook postrouting priority srcnat + 1; policy accept;\n"
        "        oifname \"%s\" ip dscp set cs0\n"
        "    }\n"
        "}\n",
        c->ul_if);

    fclose(nft);

    if (rule_count == 0) {
        syslog(LOG_WARNING, "dscp_rules: no valid rules in '%s'", rules_path);
        unlink(DSCP_NFT_FILE);
        return -1;
    }

    int rc = system("nft -f " DSCP_NFT_FILE);
    if (rc != 0) {
        syslog(LOG_ERR, "dscp_rules: nft -f failed (rc=%d)", rc);
        unlink(DSCP_NFT_FILE);
        return -1;
    }

    syslog(LOG_INFO, "dscp_rules: loaded %d rules from '%s'",
           rule_count, rules_path);
    return 0;
}

static void dscp_rules_unload(void)
{
    system("nft delete table inet " DSCP_NFT_TABLE " 2>/dev/null");
    unlink(DSCP_NFT_FILE);
}

/*
 * dscp_rules_load_minimal – load marking rules without the postrouting
 * wash chain, used during hardware/software flow offload.  The postrouting
 * chain prevents PPE offload because netfilter marks any flow it modifies
 * as requiring software processing.
 */
static void dscp_rules_load_minimal(const cake_config_t *c)
{
    const char *rules_path = c->gaming_rules_file;
    if (!rules_path || rules_path[0] == '\0') return;

    FILE *rules = fopen(rules_path, "r");
    if (!rules) return;

    FILE *nft = fopen(DSCP_NFT_FILE, "w");
    if (!nft) { fclose(rules); return; }

    fprintf(nft,
        "# Auto-generated by darkmoon (minimal/offload mode) – do not edit\n"
        "table inet " DSCP_NFT_TABLE " {\n"
        "    counter " TDETECT_NFT_COUNTER " { }\n"
        "    chain forward {\n"
        "        type filter hook forward priority mangle; policy accept;\n\n");

    char line[256];
    while (fgets(line, sizeof(line), rules)) {
        int len = (int)strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' ||
                           line[len-1] == ' '  || line[len-1] == '\t'))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;

        if (strcasecmp(line, "small-udp-ef") == 0) {
            fprintf(nft,
                "        ip protocol udp meta length < 200 ip dscp set ef\n");
            continue;
        }

        char tok_proto[16], tok_port[32], tok_dscp[16];
        if (sscanf(line, "%15s %31s %15s", tok_proto, tok_port, tok_dscp) != 3)
            continue;

        int do_udp = 0, do_tcp = 0;
        if      (strcasecmp(tok_proto, "udp")  == 0) do_udp = 1;
        else if (strcasecmp(tok_proto, "tcp")  == 0) do_tcp = 1;
        else if (strcasecmp(tok_proto, "both") == 0) { do_udp = do_tcp = 1; }
        else continue;

        if (dscp_name_to_val(tok_dscp) < 0) continue;

        if (do_udp)
            fprintf(nft,
                "        ip protocol udp udp dport %s ip dscp set %s\n"
                "        ip protocol udp udp sport %s ip dscp set %s\n",
                tok_port, tok_dscp, tok_port, tok_dscp);
        if (do_tcp)
            fprintf(nft,
                "        ip protocol tcp tcp dport %s ip dscp set %s\n"
                "        ip protocol tcp tcp sport %s ip dscp set %s\n",
                tok_port, tok_dscp, tok_port, tok_dscp);
    }
    fclose(rules);

    fprintf(nft,
        "\n        ip dscp != cs0 counter name " TDETECT_NFT_COUNTER "\n"
        "    }\n"
        "}\n");
    fclose(nft);

    system("nft delete table inet " DSCP_NFT_TABLE " 2>/dev/null");
    if (system("nft -f " DSCP_NFT_FILE) != 0)
        syslog(LOG_WARNING, "darkmoon-shaper: minimal dscp table load failed");
}

/* ────────────────────────────────────────────────────────────── */
/*  darkmoon-shaper: flow offload                                 */
/* ────────────────────────────────────────────────────────────── */

/*
 * detect_offload_capability – probe firewall flow offload support.
 *
 * Only called when smart_shaping_offload_enabled = 1.  Performs live
 * firewall reloads so must not run when the user has offloading disabled.
 *
 * Returns: 2 = hardware (PPE), 1 = software, 0 = not available.
 */
static int detect_offload_capability(void)
{
    if (system("uci -q get firewall.@defaults[0] >/dev/null 2>&1") != 0) {
        syslog(LOG_INFO, "darkmoon-shaper: firewall UCI not found, "
               "offload not available");
        return 0;
    }

    system("uci -q set firewall.@defaults[0].flow_offloading=1");
    system("uci -q set firewall.@defaults[0].flow_offloading_hw=1");
    system("uci -q commit firewall");
    int hw = system("/etc/init.d/firewall reload >/dev/null 2>&1");

    if (hw == 0) {
        system("uci -q set firewall.@defaults[0].flow_offloading=0");
        system("uci -q set firewall.@defaults[0].flow_offloading_hw=0");
        system("uci -q commit firewall");
        system("/etc/init.d/firewall reload >/dev/null 2>&1");
        syslog(LOG_INFO, "darkmoon-shaper: hardware flow offload (PPE) available");
        return 2;
    }

    system("uci -q set firewall.@defaults[0].flow_offloading=1");
    system("uci -q set firewall.@defaults[0].flow_offloading_hw=0");
    system("uci -q commit firewall");
    int sw = system("/etc/init.d/firewall reload >/dev/null 2>&1");

    system("uci -q set firewall.@defaults[0].flow_offloading=0");
    system("uci -q set firewall.@defaults[0].flow_offloading_hw=0");
    system("uci -q commit firewall");
    system("/etc/init.d/firewall reload >/dev/null 2>&1");

    if (sw == 0) {
        syslog(LOG_INFO, "darkmoon-shaper: software flow offload available");
        return 1;
    }

    syslog(LOG_INFO, "darkmoon-shaper: flow offload not available");
    return 0;
}

static void offload_enable(const cake_config_t *c, int cap)
{
    if (cap == 0) return;

    dscp_rules_load_minimal(c);

    system("uci -q set firewall.@defaults[0].flow_offloading=1");
    if (cap == 2)
        system("uci -q set firewall.@defaults[0].flow_offloading_hw=1");
    else
        system("uci -q set firewall.@defaults[0].flow_offloading_hw=0");
    system("uci -q commit firewall");

    if (system("/etc/init.d/firewall reload >/dev/null 2>&1") != 0)
        syslog(LOG_WARNING, "darkmoon-shaper: firewall reload failed during "
               "offload enable");
    else
        syslog(LOG_INFO, "darkmoon-shaper: %s flow offload enabled",
               cap == 2 ? "hardware" : "software");
}

static void offload_disable(const cake_config_t *c)
{
    system("uci -q set firewall.@defaults[0].flow_offloading=0");
    system("uci -q set firewall.@defaults[0].flow_offloading_hw=0");
    system("uci -q commit firewall");
    system("/etc/init.d/firewall reload >/dev/null 2>&1");

    uint64_t dummy_mask = 0;
    dscp_rules_load(c, &dummy_mask);
}

/* ────────────────────────────────────────────────────────────── */
/*  CAKE setup / teardown                                         */
/* ────────────────────────────────────────────────────────────── */

static int cake_setup(autorate_t *ar)
{
    cake_config_t *c = &ar->cfg;

    if (c->adjust_dl_shaper_rate && c->dl_if[0]) {
        cake_qdisc_opts_t dl_opts = make_dl_opts(c);
        if (tc_dl_setup(ar->tc_nl,
                        c->ul_if,
                        c->dl_if,
                        ar->shaper_rate_kbps[DIR_DL],
                        &dl_opts) < 0) {
            syslog(LOG_ERR, "cake_setup: DL path failed: %m");
            return -1;
        }
        ar->dl_setup_done = 1;
        ar->last_shaper_rate_kbps[DIR_DL] = ar->shaper_rate_kbps[DIR_DL];
    }

    if (c->adjust_ul_shaper_rate && c->ul_if[0]) {
        cake_qdisc_opts_t ul_opts = make_ul_opts(c);
        if (tc_ul_setup(ar->tc_nl,
                        c->ul_if,
                        ar->shaper_rate_kbps[DIR_UL],
                        &ul_opts) < 0) {
            syslog(LOG_WARNING, "cake_setup: UL path deferred (will retry): %m");
        } else {
            ar->ul_setup_done = 1;
            ar->last_shaper_rate_kbps[DIR_UL] = ar->shaper_rate_kbps[DIR_UL];
        }
    }

    return 0;
}

static void cake_teardown(autorate_t *ar)
{
    cake_config_t *c = &ar->cfg;

    if (ar->dl_setup_done) {
        tc_dl_teardown(ar->tc_nl, c->ul_if, c->dl_if);
        ar->dl_setup_done = 0;
    }

    if (ar->ul_setup_done) {
        tc_ul_teardown(ar->tc_nl, c->ul_if);
        ar->ul_setup_done = 0;
    }
}

/* ────────────────────────────────────────────────────────────── */
/*  CAKE rate control                                             */
/* ────────────────────────────────────────────────────────────── */
static void clamp_shaper_rate(autorate_t *ar, int dir)
{
    uint32_t mn = (dir == DIR_DL) ? ar->cfg.min_dl_shaper_rate_kbps
                                  : ar->cfg.min_ul_shaper_rate_kbps;
    uint32_t mx = (dir == DIR_DL) ? ar->cfg.max_dl_shaper_rate_kbps
                                  : ar->cfg.max_ul_shaper_rate_kbps;
    if (ar->shaper_rate_kbps[dir] < mn) ar->shaper_rate_kbps[dir] = mn;
    if (ar->shaper_rate_kbps[dir] > mx) ar->shaper_rate_kbps[dir] = mx;
}

static void set_shaper_rate(autorate_t *ar, int dir)
{
    uint32_t rate     = ar->shaper_rate_kbps[dir];
    uint32_t old_rate = ar->last_shaper_rate_kbps[dir];

    if (rate == old_rate)
        return;

    uint32_t min_limit = (dir == DIR_DL) ? ar->cfg.min_dl_shaper_rate_kbps
                                         : ar->cfg.min_ul_shaper_rate_kbps;
    uint32_t max_limit = (dir == DIR_DL) ? ar->cfg.max_dl_shaper_rate_kbps
                                         : ar->cfg.max_ul_shaper_rate_kbps;

    uint32_t diff      = (rate > old_rate) ? (rate - old_rate) : (old_rate - rate);
    uint32_t base      = old_rate ? old_rate : rate;
    uint32_t threshold = base / 200;
    uint32_t floor_val = (base < 5000) ? (base / 100) : 50;
    if (threshold < floor_val) threshold = floor_val;

    if (diff < threshold && rate != min_limit && rate != max_limit)
        return;

    const char *iface  = (dir == DIR_DL) ? ar->cfg.dl_if : ar->cfg.ul_if;
    int         adjust = (dir == DIR_DL) ? ar->cfg.adjust_dl_shaper_rate
                                         : ar->cfg.adjust_ul_shaper_rate;

    if (adjust && iface[0] != '\0') {
        if (tc_cake_set_bandwidth(ar->tc_nl, iface, rate) < 0)
            return;
    }

    ar->last_shaper_rate_kbps[dir] = rate;
}

/* ────────────────────────────────────────────────────────────── */
/*  Rate adjustment                                               */
/* ────────────────────────────────────────────────────────────── */
static void adjust_shaper_rate(autorate_t *ar, int dir, int64_t t_now_us)
{
    if (ar->cfg.smart_shaping_enabled && ar->shaping_bypassed)
        return;

    cake_config_t *c    = &ar->cfg;
    uint32_t base       = (dir == DIR_DL) ? c->base_dl_shaper_rate_kbps
                                           : c->base_ul_shaper_rate_kbps;
    int64_t delay_thr   = (dir == DIR_DL) ? c->dl_owd_delta_delay_thr_us
                                           : c->ul_owd_delta_delay_thr_us;
    int64_t max_up_thr  = (dir == DIR_DL) ? c->dl_avg_owd_delta_max_adjust_up_thr_us
                                           : c->ul_avg_owd_delta_max_adjust_up_thr_us;
    int64_t max_down_thr = (dir == DIR_DL) ? c->dl_avg_owd_delta_max_adjust_down_thr_us
                                            : c->ul_avg_owd_delta_max_adjust_down_thr_us;

    switch (ar->load_condition[dir]) {

    case LOAD_BB: {
        if (t_now_us - ar->t_last_bufferbloat_us[dir] <
                c->bufferbloat_refractory_period_us)
            break;

        int64_t avg = ar->avg_owd_delta_us[dir];
        int64_t factor;
        if (max_down_thr <= delay_thr) {
            factor = c->shaper_rate_max_adjust_down_bufferbloat;
        } else if (avg > delay_thr) {
            factor = c->shaper_rate_min_adjust_down_bufferbloat
                + (c->shaper_rate_max_adjust_down_bufferbloat
                   - c->shaper_rate_min_adjust_down_bufferbloat)
                * (avg - delay_thr)
                / (max_down_thr - delay_thr);
        } else {
            factor = c->shaper_rate_min_adjust_down_bufferbloat;
        }

        /* A bufferbloat-down factor must be in (0, 1]. Clamp against
         * misconfiguration; a negative or zero value would wrap the
         * rate to ~UINT32_MAX kbps when cast to uint64_t. */
        if (factor <= 0)
            factor = c->shaper_rate_min_adjust_down_bufferbloat;
        if (factor > 1000000LL)
            factor = 1000000LL;

        ar->shaper_rate_kbps[dir] =
            (uint32_t)((uint64_t)ar->shaper_rate_kbps[dir]
                       * (uint64_t)factor / 1000000ULL);
        ar->t_last_bufferbloat_us[dir] = t_now_us;
        ar->t_last_decay_us[dir]       = t_now_us;
        break;
    }

    case LOAD_HIGH: {
        if (!ar->achieved_rate_updated[dir])
            break;
        if (t_now_us - ar->t_last_bufferbloat_us[dir] <
                c->bufferbloat_refractory_period_us)
            break;

        int64_t avg = ar->avg_owd_delta_us[dir];
        int64_t factor;
        if (avg <= max_up_thr) {
            factor = c->shaper_rate_max_adjust_up_load_high;
        } else if (avg < delay_thr && max_up_thr < delay_thr) {
            factor = c->shaper_rate_max_adjust_up_load_high
                - (c->shaper_rate_max_adjust_up_load_high
                   - c->shaper_rate_min_adjust_up_load_high)
                * (avg - max_up_thr)
                / (delay_thr - max_up_thr);
        } else {
            factor = c->shaper_rate_min_adjust_up_load_high;
        }

        /* A load-high-up factor must be >= 1× to actually increase rate. */
        if (factor < 1000000LL)
            factor = 1000000LL;
        if (factor > 2000000LL)
            factor = 2000000LL;

        ar->shaper_rate_kbps[dir] =
            (uint32_t)((uint64_t)ar->shaper_rate_kbps[dir]
                       * (uint64_t)factor / 1000000ULL);
        ar->achieved_rate_updated[dir] = 0;
        ar->t_last_decay_us[dir]       = t_now_us;
        break;
    }

    case LOAD_LOW:
    case LOAD_IDLE: {
        if (t_now_us - ar->t_last_decay_us[dir] < c->decay_refractory_period_us)
            break;

        uint32_t rate = ar->shaper_rate_kbps[dir];
        if (rate > base) {
            int64_t f = c->shaper_rate_adjust_down_load_low;
            if (f <= 0) f = 990000LL;
            if (f > 1000000LL) f = 1000000LL;
            rate = (uint32_t)((uint64_t)rate * (uint64_t)f / 1000000ULL);
            ar->shaper_rate_kbps[dir] = (rate < base) ? base : rate;
        } else if (rate < base) {
            int64_t f = c->shaper_rate_adjust_up_load_low;
            if (f < 1000000LL) f = 1000000LL;
            if (f > 2000000LL) f = 2000000LL;
            rate = (uint32_t)((uint64_t)rate * (uint64_t)f / 1000000ULL);
            ar->shaper_rate_kbps[dir] = (rate > base) ? base : rate;
        }
        ar->t_last_decay_us[dir] = t_now_us;
        break;
    }
    }

    clamp_shaper_rate(ar, dir);
    set_shaper_rate(ar, dir);
}

/* ────────────────────────────────────────────────────────────── */
/*  OWD processing                                                */
/* ────────────────────────────────────────────────────────────── */
static void process_owd(autorate_t *ar,
                        int reflector_idx,
                        int64_t dl_owd_us,
                        int64_t ul_owd_us,
                        int64_t t_now_us)
{
    cake_config_t *c = &ar->cfg;
    reflector_t   *r = &ar->reflectors[reflector_idx];

    if (!r->baseline_valid) {
        r->dl_owd_baseline_us = dl_owd_us;
        r->ul_owd_baseline_us = ul_owd_us;
        r->baseline_valid     = 1;
        r->last_response_us   = t_now_us;
        return;
    }

    if (dl_owd_us - r->dl_owd_baseline_us < -3000000LL ||
        ul_owd_us - r->ul_owd_baseline_us < -3000000LL) {
        r->dl_owd_baseline_us = dl_owd_us;
        r->ul_owd_baseline_us = ul_owd_us;
        r->last_response_us   = t_now_us;
        return;
    }

    int64_t dl_alpha = (dl_owd_us > r->dl_owd_baseline_us)
        ? c->alpha_baseline_increase : c->alpha_baseline_decrease;
    int64_t ul_alpha = (ul_owd_us > r->ul_owd_baseline_us)
        ? c->alpha_baseline_increase : c->alpha_baseline_decrease;

    r->dl_owd_baseline_us =
          dl_alpha * dl_owd_us               / 1000000LL
        + (1000000LL - dl_alpha) * r->dl_owd_baseline_us / 1000000LL;
    r->ul_owd_baseline_us =
          ul_alpha * ul_owd_us               / 1000000LL
        + (1000000LL - ul_alpha) * r->ul_owd_baseline_us / 1000000LL;

    int64_t dl_delta = dl_owd_us - r->dl_owd_baseline_us;
    int64_t ul_delta = ul_owd_us - r->ul_owd_baseline_us;

    if (ar->load_condition[DIR_DL] == LOAD_HIGH ||
        ar->load_condition[DIR_UL] == LOAD_HIGH) {
        int64_t ae = c->alpha_delta_ewma;
        r->dl_owd_delta_ewma_us =
              ae * dl_delta                    / 1000000LL
            + (1000000LL - ae) * r->dl_owd_delta_ewma_us / 1000000LL;
        r->ul_owd_delta_ewma_us =
              ae * ul_delta                    / 1000000LL
            + (1000000LL - ae) * r->ul_owd_delta_ewma_us / 1000000LL;
    }

    int bdw = c->bufferbloat_detection_window;
    int idx = ar->delays_idx;

    ar->sum_dl_delays -= ar->dl_delays[idx];
    ar->dl_delays[idx] = (dl_delta > c->dl_owd_delta_delay_thr_us) ? 1 : 0;
    ar->sum_dl_delays += ar->dl_delays[idx];

    ar->sum_ul_delays -= ar->ul_delays[idx];
    ar->ul_delays[idx] = (ul_delta > c->ul_owd_delta_delay_thr_us) ? 1 : 0;
    ar->sum_ul_delays += ar->ul_delays[idx];

    ar->sum_dl_owd_deltas_us -= ar->dl_owd_deltas_us[idx];
    ar->dl_owd_deltas_us[idx] = dl_delta;
    ar->sum_dl_owd_deltas_us += dl_delta;

    ar->sum_ul_owd_deltas_us -= ar->ul_owd_deltas_us[idx];
    ar->ul_owd_deltas_us[idx] = ul_delta;
    ar->sum_ul_owd_deltas_us += ul_delta;

    ar->delays_idx = (idx + 1) % bdw;

    if (ar->delays_fill < bdw)
        ar->delays_fill++;
    int divisor = ar->delays_fill;

    ar->avg_owd_delta_us[DIR_DL] = ar->sum_dl_owd_deltas_us / divisor;
    ar->avg_owd_delta_us[DIR_UL] = ar->sum_ul_owd_deltas_us / divisor;

    ar->bufferbloat_detected[DIR_DL] =
        (ar->sum_dl_delays >= c->bufferbloat_detection_thr);
    ar->bufferbloat_detected[DIR_UL] =
        (ar->sum_ul_delays >= c->bufferbloat_detection_thr);

    uint32_t high_thr_dl = (uint32_t)((uint64_t)ar->shaper_rate_kbps[DIR_DL]
                                      * (uint64_t)c->high_load_thr / 1000000ULL);
    uint32_t high_thr_ul = (uint32_t)((uint64_t)ar->shaper_rate_kbps[DIR_UL]
                                      * (uint64_t)c->high_load_thr / 1000000ULL);

    for (int d = 0; d < 2; d++) {
        uint32_t ach = ar->achieved_rate_kbps[d];
        uint32_t thr = (d == DIR_DL) ? high_thr_dl : high_thr_ul;
        if (ar->bufferbloat_detected[d])
            ar->load_condition[d] = LOAD_BB;
        else if (ach >= thr)
            ar->load_condition[d] = LOAD_HIGH;
        else if (ach >= c->connection_active_thr_kbps)
            ar->load_condition[d] = LOAD_LOW;
        else
            ar->load_condition[d] = LOAD_IDLE;
    }

    r->last_response_us         = t_now_us;
    ar->global_last_response_us = t_now_us;

    adjust_shaper_rate(ar, DIR_DL, t_now_us);
    adjust_shaper_rate(ar, DIR_UL, t_now_us);
}

/* ────────────────────────────────────────────────────────────── */
/*  ICMP pinger                                                   */
/* ────────────────────────────────────────────────────────────── */

#define PING_PAYLOAD_MAGIC 0xCACEB00Bu

static uint16_t csum16(const void *data, size_t len)
{
    const uint16_t *word = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *word++;
        len -= 2;
    }
    if (len == 1) {
        uint16_t last = 0;
        *(uint8_t *)&last = *(const uint8_t *)word;
        sum += last;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

static void write_be64(uint8_t out[8], uint64_t v)
{
    out[0]=(uint8_t)(v>>56); out[1]=(uint8_t)(v>>48);
    out[2]=(uint8_t)(v>>40); out[3]=(uint8_t)(v>>32);
    out[4]=(uint8_t)(v>>24); out[5]=(uint8_t)(v>>16);
    out[6]=(uint8_t)(v>> 8); out[7]=(uint8_t)(v);
}

static uint64_t read_be64(const uint8_t in[8])
{
    return ((uint64_t)in[0]<<56)|((uint64_t)in[1]<<48)|
           ((uint64_t)in[2]<<40)|((uint64_t)in[3]<<32)|
           ((uint64_t)in[4]<<24)|((uint64_t)in[5]<<16)|
           ((uint64_t)in[6]<< 8)|((uint64_t)in[7]);
}

static uint32_t ms_since_midnight_realtime(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL
                + (uint64_t)ts.tv_nsec / 1000000ULL;
    return (uint32_t)(ms % MS_PER_DAY);
}

static int32_t ts_diff_ms(uint32_t later, uint32_t earlier)
{
    int32_t d = (int32_t)((int64_t)later - (int64_t)earlier);
    if (d >  43200000) d -= (int32_t)MS_PER_DAY;
    if (d < -43200000) d += (int32_t)MS_PER_DAY;
    return d;
}

struct ping_payload {
    uint32_t magic_be;
    uint16_t ridx_be;
    uint16_t reserved_be;
    uint8_t  t_sent_be64[8];
};

static void icmp_reply_cb(struct uloop_fd *ufd, unsigned int events)
{
    (void)events;
    autorate_t *ar = container_of(ufd, autorate_t, icmp_ufd);

    for (;;) {
        /*
         * Must be at least 4-byte aligned.  ip_hlen is always a multiple of 4
         * (IHL × 4), so buf+ip_hlen and any nested struct pointer are safe to
         * dereference on MIPS/ARM without triggering a bus error.  A plain
         * uint8_t[] has no guaranteed alignment beyond 1 byte.
         */
        uint8_t buf[1500] __attribute__((aligned(4)));
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);

        ssize_t n = recvfrom(ufd->fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &slen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return;
        }
        if ((size_t)n < sizeof(struct iphdr)) continue;

        struct iphdr *iph = (struct iphdr *)buf;
        int ip_hlen = iph->ihl * 4;
        if (ip_hlen < 20 ||
            (size_t)n < (size_t)ip_hlen + sizeof(struct icmphdr))
            continue;

        struct icmphdr *icmph = (struct icmphdr *)(buf + ip_hlen);

        if (ntohs(icmph->un.echo.id) != ar->ping_id) continue;

        int64_t t_now_us = now_us();

        if (icmph->type == ICMP_ECHOREPLY) {

            const uint8_t *payload = (const uint8_t *)(icmph + 1);
            size_t plen = (size_t)n - (size_t)ip_hlen - sizeof(*icmph);
            if (plen < sizeof(struct ping_payload)) continue;

            const struct ping_payload *pl = (const struct ping_payload *)payload;
            if (pl->magic_be != htonl(PING_PAYLOAD_MAGIC)) continue;

            uint32_t src_be = src.sin_addr.s_addr;
            int ridx = -1;
            for (int i = 0; i < ar->no_active_reflectors; i++) {
                if (ar->reflectors[i].addr_be == src_be) { ridx = i; break; }
            }
            if (ridx < 0) continue;

            int64_t t_sent_us = (int64_t)read_be64(pl->t_sent_be64);
            int64_t rtt_us    = t_now_us - t_sent_us;
            if (rtt_us <= 0) continue;

            int64_t owd_us = rtt_us / 2;
            process_owd(ar, ridx, owd_us, owd_us, t_now_us);
        }

        else if (icmph->type == ICMP_TIMESTAMPREPLY) {

            size_t ts_body_off = (size_t)ip_hlen + sizeof(*icmph);
            if ((size_t)n < ts_body_off + sizeof(struct icmp_ts_body)) continue;

            const struct icmp_ts_body *tsb =
                (const struct icmp_ts_body *)(buf + ts_body_off);

            uint16_t seq = ntohs(icmph->un.echo.sequence);
            ping_seq_slot_t *slot = &ar->ping_seq_ring[seq % PING_SEQ_RING];

            if (slot->reflector_idx < 0 || slot->t_sent_us == 0) continue;
            if (slot->expected_seq != seq) continue;  /* delayed collision */

            int ridx = slot->reflector_idx;
            if (ridx >= ar->no_active_reflectors ||
                ar->reflectors[ridx].addr_be != src.sin_addr.s_addr)
                continue;

            uint32_t orig_ms  = slot->originate_ms;
            uint32_t recv_ms  = ntohl(tsb->receive);
            uint32_t tx_ms    = ntohl(tsb->transmit);
            uint32_t local_ms = ms_since_midnight_realtime();

            int32_t ul_ms = ts_diff_ms(recv_ms, orig_ms);
            int32_t dl_ms = ts_diff_ms(local_ms, tx_ms);

            if (ul_ms < -5000 || ul_ms > 30000) continue;
            if (dl_ms < -5000 || dl_ms > 30000) continue;

            int64_t ul_owd_us = (int64_t)ul_ms * 1000LL;
            int64_t dl_owd_us = (int64_t)dl_ms * 1000LL;

            slot->t_sent_us     = 0;
            slot->reflector_idx = -1;

            process_owd(ar, ridx, dl_owd_us, ul_owd_us, t_now_us);
        }
    }
}

static void ping_timer_cb(struct uloop_timeout *t)
{
    autorate_t    *ar = container_of(t, autorate_t, ping_timer);
    cake_config_t *c  = &ar->cfg;

    if (ar->no_active_reflectors <= 0 || ar->icmp_sock < 0) {
        uloop_timeout_set(&ar->ping_timer, 1000);
        return;
    }

    if (ar->ping_rr_idx >= ar->no_active_reflectors)
        ar->ping_rr_idx = 0;

    int ridx = ar->ping_rr_idx++;
    reflector_t *r = &ar->reflectors[ridx];

    if (r->addr_be == 0) goto out;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = r->addr_be;

    uint16_t seq       = ++ar->ping_seq;
    int64_t  t_sent_us = now_us();

    if (c->ping_type == 1) {
        uint8_t pkt[sizeof(struct icmphdr) + sizeof(struct icmp_ts_body)];
        memset(pkt, 0, sizeof(pkt));

        struct icmphdr      *h   = (struct icmphdr *)pkt;
        struct icmp_ts_body *tsb = (struct icmp_ts_body *)(h + 1);

        h->type             = ICMP_TIMESTAMP;
        h->code             = 0;
        h->un.echo.id       = htons(ar->ping_id);
        h->un.echo.sequence = htons(seq);

        uint32_t orig_ms = ms_since_midnight_realtime();
        tsb->originate = htonl(orig_ms);
        tsb->receive   = 0;
        tsb->transmit  = 0;

        h->checksum = 0;
        h->checksum = csum16(pkt, sizeof(pkt));

        ping_seq_slot_t *slot = &ar->ping_seq_ring[seq % PING_SEQ_RING];
        slot->t_sent_us     = t_sent_us;
        slot->originate_ms  = orig_ms;
        slot->reflector_idx = ridx;
        slot->expected_seq  = seq;

        (void)sendto(ar->icmp_sock, pkt, sizeof(pkt), 0,
                     (struct sockaddr *)&dst, sizeof(dst));

    } else {
        uint8_t pkt[sizeof(struct icmphdr) + sizeof(struct ping_payload)];
        memset(pkt, 0, sizeof(pkt));

        struct icmphdr      *h  = (struct icmphdr *)pkt;
        struct ping_payload *pl = (struct ping_payload *)(h + 1);

        h->type             = ICMP_ECHO;
        h->code             = 0;
        h->un.echo.id       = htons(ar->ping_id);
        h->un.echo.sequence = htons(seq);

        pl->magic_be    = htonl(PING_PAYLOAD_MAGIC);
        pl->ridx_be     = htons((uint16_t)ridx);
        pl->reserved_be = 0;
        write_be64(pl->t_sent_be64, (uint64_t)t_sent_us);

        h->checksum = 0;
        h->checksum = csum16(pkt, sizeof(pkt));

        (void)sendto(ar->icmp_sock, pkt, sizeof(pkt), 0,
                     (struct sockaddr *)&dst, sizeof(dst));
    }

out:
    {
        int interval_ms = (int)((c->reflector_ping_interval_us / 1000)
                                / ar->no_active_reflectors);
        if (interval_ms < 10) interval_ms = 10;
        uloop_timeout_set(&ar->ping_timer, interval_ms);
    }
}

static void refresh_reflector_addrs(autorate_t *ar)
{
    for (int i = 0; i < ar->no_active_reflectors; i++) {
        struct in_addr a;
        if (inet_pton(AF_INET, ar->reflectors[i].addr, &a) == 1)
            ar->reflectors[i].addr_be = a.s_addr;
        else
            ar->reflectors[i].addr_be = 0;
    }
}

static int start_pinger(autorate_t *ar)
{
    ar->icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ar->icmp_sock < 0)
        return -1;

    set_nonblocking(ar->icmp_sock);

    ar->icmp_ufd.fd = ar->icmp_sock;
    ar->icmp_ufd.cb = icmp_reply_cb;
    uloop_fd_add(&ar->icmp_ufd, ULOOP_READ | ULOOP_EDGE_TRIGGER);

    ar->ping_id     = (uint16_t)(getpid() & 0xFFFF);
    ar->ping_seq    = 0;
    ar->ping_rr_idx = 0;

    for (int i = 0; i < PING_SEQ_RING; i++) {
        ar->ping_seq_ring[i].t_sent_us     = 0;
        ar->ping_seq_ring[i].reflector_idx = -1;
        ar->ping_seq_ring[i].expected_seq  = 0;
    }

    refresh_reflector_addrs(ar);

    ar->t_pinger_started_us = now_us();
    ar->ping_timer.cb = ping_timer_cb;
    uloop_timeout_set(&ar->ping_timer, 1);
    return 0;
}

static void stop_pinger(autorate_t *ar)
{
    uloop_timeout_cancel(&ar->ping_timer);

    if (ar->icmp_ufd.registered)
        uloop_fd_delete(&ar->icmp_ufd);

    if (ar->icmp_sock >= 0) {
        close(ar->icmp_sock);
        ar->icmp_sock = -1;
    }
}

/* ────────────────────────────────────────────────────────────── */
/*  Reflector health check                                        */
/* ────────────────────────────────────────────────────────────── */
static void health_timer_cb(struct uloop_timeout *t)
{
    autorate_t    *ar  = container_of(t, autorate_t, health_timer);
    cake_config_t *c   = &ar->cfg;
    int64_t        now = now_us();
    int            win = c->reflector_misbehaving_detection_window;
    int            replaced = 0;

    if (win <= 0 || win > MAX_OFFENCE_WINDOW)
        win = MAX_OFFENCE_WINDOW;

    for (int i = 0; i < ar->no_active_reflectors; i++) {
        reflector_t *r = &ar->reflectors[i];

        if (r->last_response_us == 0)
            continue;

        int offence = (now - r->last_response_us >
                       c->reflector_response_deadline_us) ? 1 : 0;

        int widx = r->offences_idx;
        r->sum_offences  -= r->offences[widx];
        r->offences[widx] = offence;
        r->sum_offences  += offence;
        r->offences_idx   = (widx + 1) % win;

        if (r->sum_offences >= c->reflector_misbehaving_detection_thr) {
            if (ar->spare_idx >= c->no_reflectors) {
                syslog(LOG_WARNING,
                       "reflector %s misbehaving (%d/%d misses) but no "
                       "spare reflectors remain – keeping current set",
                       r->addr, r->sum_offences, win);
                continue;
            }

            syslog(LOG_WARNING,
                   "replacing misbehaving reflector %s with %s "
                   "(%d/%d misses)",
                   r->addr, c->reflectors[ar->spare_idx],
                   r->sum_offences, win);

            snprintf(r->addr, sizeof(r->addr),
                     "%s", c->reflectors[ar->spare_idx++]);

            /*
             * Warm-start the new reflector's baseline from the median of
             * surviving active reflectors.  DL and UL are sorted
             * independently so ul_vals[n/2] is the true median UL latency,
             * not the UL value of the reflector with the median DL latency
             * (these differ on asymmetric links).
             */
            {
                int64_t dl_vals[MAX_REFLECTORS];
                int64_t ul_vals[MAX_REFLECTORS];
                int n = 0;
                for (int j = 0; j < ar->no_active_reflectors; j++) {
                    if (j == i) continue;
                    if (ar->reflectors[j].baseline_valid) {
                        dl_vals[n] = ar->reflectors[j].dl_owd_baseline_us;
                        ul_vals[n] = ar->reflectors[j].ul_owd_baseline_us;
                        n++;
                    }
                }
                if (n > 0) {
                    for (int a = 0; a < n - 1; a++)
                        for (int b = a + 1; b < n; b++)
                            if (dl_vals[b] < dl_vals[a]) {
                                int64_t tmp = dl_vals[a];
                                dl_vals[a] = dl_vals[b];
                                dl_vals[b] = tmp;
                            }
                    for (int a = 0; a < n - 1; a++)
                        for (int b = a + 1; b < n; b++)
                            if (ul_vals[b] < ul_vals[a]) {
                                int64_t tmp = ul_vals[a];
                                ul_vals[a] = ul_vals[b];
                                ul_vals[b] = tmp;
                            }
                    r->dl_owd_baseline_us = dl_vals[n / 2];
                    r->ul_owd_baseline_us = ul_vals[n / 2];
                    r->baseline_valid     = 1;
                } else {
                    r->dl_owd_baseline_us = 0;
                    r->ul_owd_baseline_us = 0;
                    r->baseline_valid     = 0;
                }
            }

            r->dl_owd_delta_ewma_us = 0;
            r->ul_owd_delta_ewma_us = 0;
            r->last_response_us     = 0;
            memset(r->offences, 0, sizeof(r->offences));
            r->sum_offences = 0;
            r->offences_idx = 0;
            replaced = 1;
        }
    }

    if (replaced)
        refresh_reflector_addrs(ar);

    uloop_timeout_set(t, (int)(c->reflector_health_check_interval_us / 1000));
}

/* ────────────────────────────────────────────────────────────── */
/*  Rate-monitor timer (~200 ms)                                  */
/* ────────────────────────────────────────────────────────────── */
static void rate_timer_cb(struct uloop_timeout *t)
{
    autorate_t    *ar = container_of(t, autorate_t, rate_timer);
    cake_config_t *c  = &ar->cfg;

    int64_t elapsed = rate_monitor_update(&ar->rm,
                                          &ar->achieved_rate_kbps[DIR_DL],
                                          &ar->achieved_rate_kbps[DIR_UL]);

    ar->achieved_rate_updated[DIR_DL] = 1;
    ar->achieved_rate_updated[DIR_UL] = 1;

    if (ar->cfg.smart_shaping_enabled) {
        int64_t t_poll  = now_us();
        int was_active  = traffic_detector_is_active(&ar->td);
        int is_active   = traffic_detector_poll(&ar->td, t_poll);

        if (was_active && !is_active && !ar->shaping_bypassed) {
            ar->shaping_bypassed = 1;
            if (ar->cfg.smart_shaping_offload_enabled && ar->offload_cap > 0) {
                cake_teardown(ar);
                offload_enable(&ar->cfg, ar->offload_cap);
                ar->offload_active = 1;
                syslog(LOG_INFO, "darkmoon-shaper: bypass active (%s offload)",
                       ar->offload_cap == 2 ? "hardware" : "software");
            } else {
                if (ar->cfg.adjust_dl_shaper_rate && ar->cfg.dl_if[0])
                    tc_cake_set_bandwidth(ar->tc_nl, ar->cfg.dl_if, 0);
                if (ar->cfg.adjust_ul_shaper_rate && ar->cfg.ul_if[0])
                    tc_cake_set_bandwidth(ar->tc_nl, ar->cfg.ul_if, 0);
                syslog(LOG_INFO, "darkmoon-shaper: shaping bypassed (unlimited)");
            }
        } else if (!was_active && is_active && ar->shaping_bypassed) {
            ar->shaping_bypassed = 0;
            if (ar->offload_active) {
                offload_disable(&ar->cfg);
                ar->offload_active = 0;
                if (cake_setup(ar) < 0)
                    syslog(LOG_ERR, "darkmoon-shaper: cake_setup failed on "
                           "game detection");
            }

            ar->shaper_rate_kbps[DIR_DL]      = ar->cfg.base_dl_shaper_rate_kbps;
            ar->shaper_rate_kbps[DIR_UL]      = ar->cfg.base_ul_shaper_rate_kbps;
            ar->last_shaper_rate_kbps[DIR_DL] = 0;
            ar->last_shaper_rate_kbps[DIR_UL] = 0;

            /* Apply base rate immediately rather than waiting for the next
             * ICMP reply, which could be up to one ping interval away. */
            set_shaper_rate(ar, DIR_DL);
            set_shaper_rate(ar, DIR_UL);

            syslog(LOG_INFO, "darkmoon-shaper: shaping engaged");
        }
    }

    int64_t target = c->monitor_achieved_rates_interval_us;
    int64_t next   = target - (elapsed - target);
    if (next < target) next = target;

    /* Stall detection.
     *
     * Two paths to stall state:
     *  1. No response at all since startup and global_ping_response_timeout_us
     *     has elapsed – useful for catching a completely wrong reflector list
     *     or a ping_type mismatch (e.g. type-13 blocked by firewall).
     *  2. Normal stall: last response is older than stall_detection_thr
     *     intervals and both achieved rates are below the stall threshold.
     */
    int64_t now = now_us();
    {
        int64_t per_reflector_interval_us = c->reflector_ping_interval_us;
        int64_t stall_thr_us =
            (int64_t)c->stall_detection_thr * per_reflector_interval_us;

        int64_t last_response = ar->global_last_response_us > 0
            ? ar->global_last_response_us
            : ar->t_pinger_started_us;

        int startup_timeout_hit =
            (ar->global_last_response_us == 0 &&
             c->global_ping_response_timeout_us > 0 &&
             (now - ar->t_pinger_started_us) > c->global_ping_response_timeout_us);

        if (startup_timeout_hit ||
            (now - last_response > stall_thr_us &&
             ar->achieved_rate_kbps[DIR_DL] < c->connection_stall_thr_kbps &&
             ar->achieved_rate_kbps[DIR_UL] < c->connection_stall_thr_kbps)) {
            if (ar->main_state != STATE_STALL) {
                ar->main_state = STATE_STALL;
                if (ar->global_last_response_us == 0)
                    syslog(LOG_WARNING,
                           "no ping responses since startup "
                           "(ping_type=%d, timeout=%.1fs) – "
                           "check reflector list or try ping_type=0",
                           c->ping_type,
                           (double)c->global_ping_response_timeout_us / 1e6);
                else
                    syslog(LOG_WARNING, "connection stall detected");
            }
        } else if (ar->main_state == STATE_STALL &&
                   ar->global_last_response_us > 0) {
            ar->main_state = STATE_RUNNING;
            syslog(LOG_INFO, "connection recovered from stall");
        }
    }

    write_status_file(ar);

    int ms = (int)((next / 1000) & 0x7FFFFFFF);
    uloop_timeout_set(t, ms);
}

/* ────────────────────────────────────────────────────────────── */
/*  Sliding-window allocation                                     */
/* ────────────────────────────────────────────────────────────── */
static int init_windows(autorate_t *ar)
{
    int w = ar->cfg.bufferbloat_detection_window;
    ar->dl_delays        = calloc((size_t)w, sizeof(int));
    ar->ul_delays        = calloc((size_t)w, sizeof(int));
    ar->dl_owd_deltas_us = calloc((size_t)w, sizeof(int64_t));
    ar->ul_owd_deltas_us = calloc((size_t)w, sizeof(int64_t));
    return (ar->dl_delays && ar->ul_delays &&
            ar->dl_owd_deltas_us && ar->ul_owd_deltas_us) ? 0 : -1;
}

/* ────────────────────────────────────────────────────────────── */
/*  Signal handler                                                */
/* ────────────────────────────────────────────────────────────── */
static void handle_signal(int sig)
{
    (void)sig;
    uloop_end();
}

/* ────────────────────────────────────────────────────────────── */
/*  Interface up/down recovery                                    */
/* ────────────────────────────────────────────────────────────── */
static void if_up_timer_cb(struct uloop_timeout *t)
{
    autorate_t    *ar = container_of(t, autorate_t, if_up_timer);
    cake_config_t *c  = &ar->cfg;

    int iface_present = (if_nametoindex(c->ul_if) != 0);

    if (!iface_present && ar->link_up) {
        ar->link_up = 0;
        syslog(LOG_WARNING, "WAN interface '%s' disappeared", c->ul_if);

        stop_pinger(ar);
        cake_teardown(ar);

        ar->shaper_rate_kbps[DIR_DL] = c->base_dl_shaper_rate_kbps;
        ar->shaper_rate_kbps[DIR_UL] = c->base_ul_shaper_rate_kbps;

    } else if (iface_present && !ar->link_up) {
        syslog(LOG_INFO, "WAN interface '%s' reappeared", c->ul_if);

        if (cake_setup(ar) < 0) {
            syslog(LOG_ERR, "if_up: CAKE re-setup failed on '%s', will retry",
                   c->ul_if);
        } else {
            ar->link_up = 1;

            int bdw = c->bufferbloat_detection_window;
            memset(ar->dl_delays,        0, (size_t)bdw * sizeof(*ar->dl_delays));
            memset(ar->ul_delays,        0, (size_t)bdw * sizeof(*ar->ul_delays));
            memset(ar->dl_owd_deltas_us, 0, (size_t)bdw * sizeof(*ar->dl_owd_deltas_us));
            memset(ar->ul_owd_deltas_us, 0, (size_t)bdw * sizeof(*ar->ul_owd_deltas_us));
            ar->delays_idx             = 0;
            ar->delays_fill            = 0;
            ar->sum_dl_delays          = 0;
            ar->sum_ul_delays          = 0;
            ar->sum_dl_owd_deltas_us   = 0;
            ar->sum_ul_owd_deltas_us   = 0;
            ar->global_last_response_us = 0;
            /* t_pinger_started_us is reset inside start_pinger() so the
             * stall detector's startup_timeout_hit check begins counting
             * fresh from this link-up event, not from the original daemon
             * start time. */

            for (int i = 0; i < ar->no_active_reflectors; i++) {
                reflector_t *r = &ar->reflectors[i];
                r->dl_owd_baseline_us   = 0;
                r->ul_owd_baseline_us   = 0;
                r->baseline_valid       = 0;
                r->dl_owd_delta_ewma_us = 0;
                r->ul_owd_delta_ewma_us = 0;
                r->last_response_us     = 0;
                memset(r->offences, 0, sizeof(r->offences));
                r->sum_offences = 0;
                r->offences_idx = 0;
            }

            if (start_pinger(ar) < 0)
                syslog(LOG_ERR, "if_up: failed to restart pinger: %m");
        }

    } else if (iface_present && ar->link_up && !ar->ul_setup_done &&
               c->adjust_ul_shaper_rate && c->ul_if[0]) {
        cake_qdisc_opts_t ul_opts = make_ul_opts(c);
        if (tc_ul_setup(ar->tc_nl, c->ul_if,
                        ar->shaper_rate_kbps[DIR_UL], &ul_opts) == 0) {
            ar->ul_setup_done = 1;
            ar->last_shaper_rate_kbps[DIR_UL] = ar->shaper_rate_kbps[DIR_UL];
            syslog(LOG_INFO, "if_up: UL path ready on '%s'", c->ul_if);
        }
    }

    int interval_ms = (int)(c->if_up_check_interval_us / 1000);
    if (interval_ms < 1000) interval_ms = 1000;
    uloop_timeout_set(t, interval_ms);
}

/* ────────────────────────────────────────────────────────────── */
/*  main                                                          */
/* ────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    const char *section = (argc > 1) ? argv[1] : "primary";

    openlog("cake-autorate", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    /*
     * autorate_t is ~18 KB.  Declaring it as a local variable would
     * overflow the 8 KB default stack on low-end routers.  Static
     * storage is zero-initialised and avoids this entirely.
     */
    static autorate_t ar;
    ar.icmp_sock = -1;
    ar.rm.rx_fd  = -1;
    ar.rm.tx_fd  = -1;

    if (config_load(section, &ar.cfg) < 0) {
        fprintf(stderr, "cake-autorate: failed to load UCI config '%s'\n",
                section);
        syslog(LOG_ERR, "failed to load UCI config section '%s'", section);
        return 1;
    }

    if (!ar.cfg.enabled) {
        syslog(LOG_INFO, "instance '%s' disabled, exiting", section);
        return 0;
    }

    if (ar.cfg.no_pingers < 1) {
        syslog(LOG_ERR, "no_pingers must be >= 1");
        return 1;
    }

    if (ar.cfg.bufferbloat_detection_window < 1) {
        syslog(LOG_WARNING,
               "bufferbloat_detection_window was %d, clamped to 1",
               ar.cfg.bufferbloat_detection_window);
        ar.cfg.bufferbloat_detection_window = 1;
    }

    if (init_windows(&ar) < 0) {
        syslog(LOG_ERR, "out of memory allocating OWD windows");
        return 1;
    }

    ar.no_active_reflectors =
        (ar.cfg.no_pingers < ar.cfg.no_reflectors)
        ? ar.cfg.no_pingers
        : ar.cfg.no_reflectors;
    ar.spare_idx = ar.no_active_reflectors;

    for (int i = 0; i < ar.no_active_reflectors; i++)
        snprintf(ar.reflectors[i].addr, 64, "%s", ar.cfg.reflectors[i]);

    ar.shaper_rate_kbps[DIR_DL] = ar.cfg.base_dl_shaper_rate_kbps;
    ar.shaper_rate_kbps[DIR_UL] = ar.cfg.base_ul_shaper_rate_kbps;
    ar.link_up      = 1;
    ar.t_started_us = now_us();

    ar.ping_response_interval_us =
        ar.cfg.reflector_ping_interval_us / ar.no_active_reflectors;

    ar.tc_nl = tc_nl_open();
    if (!ar.tc_nl) {
        syslog(LOG_ERR, "tc_netlink: failed to open netlink socket");
        goto err_free_windows;
    }

    if (cake_setup(&ar) < 0) {
        syslog(LOG_ERR, "CAKE setup failed");
        goto err_teardown;
    }

    if (ar.cfg.startup_wait_us > 0)
        sleep_us(ar.cfg.startup_wait_us);

    rate_monitor_init(&ar.rm, ar.cfg.dl_if, ar.cfg.ul_if);

    if (ar.cfg.smart_shaping_enabled) {
        uint64_t dscp_mask = 0;
        dscp_rules_load(&ar.cfg, &dscp_mask);

        traffic_detector_init(&ar.td,
                              ar.cfg.smart_shaping_enable_delay_us,
                              ar.cfg.smart_shaping_disable_delay_us);

        if (ar.cfg.smart_shaping_offload_enabled)
            ar.offload_cap = detect_offload_capability();
        else
            ar.offload_cap = 0;

        ar.shaping_bypassed = 1;
        if (ar.cfg.smart_shaping_offload_enabled && ar.offload_cap > 0) {
            cake_teardown(&ar);
            offload_enable(&ar.cfg, ar.offload_cap);
            ar.offload_active = 1;
            syslog(LOG_INFO, "darkmoon-shaper: idle bypass with %s offload",
                   ar.offload_cap == 2 ? "hardware" : "software");
        } else {
            if (ar.cfg.adjust_dl_shaper_rate && ar.cfg.dl_if[0])
                tc_cake_set_bandwidth(ar.tc_nl, ar.cfg.dl_if, 0);
            if (ar.cfg.adjust_ul_shaper_rate && ar.cfg.ul_if[0])
                tc_cake_set_bandwidth(ar.tc_nl, ar.cfg.ul_if, 0);
            syslog(LOG_INFO, "darkmoon-shaper: idle bypass active");
        }
    }

    uloop_init();
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    if (start_pinger(&ar) < 0) {
        syslog(LOG_ERR, "failed to start integrated pinger");
        goto err_teardown;
    }

    ar.rate_timer.cb = rate_timer_cb;
    uloop_timeout_set(&ar.rate_timer,
        (int)(ar.cfg.monitor_achieved_rates_interval_us / 1000));

    ar.health_timer.cb = health_timer_cb;
    uloop_timeout_set(&ar.health_timer,
        (int)(ar.cfg.reflector_health_check_interval_us / 1000));

    if (ar.cfg.if_up_check_interval_us > 0) {
        ar.if_up_timer.cb = if_up_timer_cb;
        int if_up_ms = (int)(ar.cfg.if_up_check_interval_us / 1000);
        if (if_up_ms < 1000) if_up_ms = 1000;
        uloop_timeout_set(&ar.if_up_timer, if_up_ms);
    }

    syslog(LOG_INFO, "started instance '%s' dl=%s ul=%s ping=%s",
           section, ar.cfg.dl_if, ar.cfg.ul_if,
           ar.cfg.ping_type == 1 ? "icmp-ts" : "icmp-echo");

    uloop_run();
    uloop_done();

    syslog(LOG_INFO, "shutting down instance '%s'", section);

    uloop_timeout_cancel(&ar.rate_timer);
    uloop_timeout_cancel(&ar.health_timer);
    uloop_timeout_cancel(&ar.if_up_timer);
    stop_pinger(&ar);

    traffic_detector_cleanup(&ar.td);
    if (ar.offload_active) {
        system("uci -q set firewall.@defaults[0].flow_offloading=0");
        system("uci -q set firewall.@defaults[0].flow_offloading_hw=0");
        system("uci -q commit firewall");
        system("/etc/init.d/firewall reload >/dev/null 2>&1");
    }
    if (ar.cfg.smart_shaping_enabled)
        dscp_rules_unload();

    unlink("/var/run/darkmoon.json");

err_teardown:
    cake_teardown(&ar);
    tc_nl_close(ar.tc_nl);
    ar.tc_nl = NULL;
    rate_monitor_cleanup(&ar.rm);

err_free_windows:
    free(ar.dl_delays);
    free(ar.ul_delays);
    free(ar.dl_owd_deltas_us);
    free(ar.ul_owd_deltas_us);

    closelog();
    return 0;
}
