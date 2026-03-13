/*
 * traffic_detector.c  –  nftables counter-based latency-sensitive traffic detector
 */

#include "traffic_detector.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

/* ── internal helpers ───────────────────────────────────────── */

static uint64_t read_gaming_pkt_count(void)
{
    int fd[2];
    if (pipe(fd) < 0) return UINT64_MAX;

    pid_t pid = fork();
    if (pid < 0) {
        close(fd[0]);
        close(fd[1]);
        return UINT64_MAX;
    }

    if (pid == 0) {
        close(fd[0]);
        dup2(fd[1], STDOUT_FILENO);
        close(fd[1]);
        
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDERR_FILENO);
            close(null_fd);
        }
        
        execlp("nft", "nft", "list", "counter", "inet", TDETECT_NFT_TABLE, TDETECT_NFT_COUNTER, NULL);
        exit(1);
    }

    close(fd[1]);

    FILE *fp = fdopen(fd[0], "r");
    if (!fp) {
        waitpid(pid, NULL, 0);
        close(fd[0]);
        return UINT64_MAX;
    }

    char line[256];
    uint64_t count = UINT64_MAX;

    while (fgets(line, sizeof(line), fp)) {
        char *p = strstr(line, "packets");
        if (p) {
            p += 7;
            while (*p == ' ' || *p == '\t') p++;
            char *end;
            unsigned long long v = strtoull(p, &end, 10);
            if (end != p) {
                count = (uint64_t)v;
                break;
            }
        }
    }

    fclose(fp);
    waitpid(pid, NULL, 0);

    return count;
}

static int nft_counter_exists(void)
{
    uint64_t v = read_gaming_pkt_count();
    return (v != UINT64_MAX);
}

/* ── Public API ──────────────────────────────────────────────── */

int traffic_detector_init(traffic_detector_t *td,
                          int64_t             enable_delay_us,
                          int64_t             disable_delay_us)
{
    memset(td, 0, sizeof(*td));
    td->ready              = -1;
    td->state              = TDETECT_IDLE;
    td->enable_delay_us    = enable_delay_us;
    td->disable_delay_us   = disable_delay_us;
    td->prev_pkt_count     = 0;
    td->t_last_traffic_us  = 0;

    if (!nft_counter_exists()) {
        syslog(LOG_WARNING,
               "traffic_detector: nft counter '" TDETECT_NFT_TABLE
               "/" TDETECT_NFT_COUNTER "' not found – "
               "is smart_shaping_enabled=1 and gaming_rules_file set? "
               "Falling back to always-shaping mode.");
        return -1;
    }

    uint64_t initial = read_gaming_pkt_count();
    td->prev_pkt_count = (initial != UINT64_MAX) ? initial : 0;

    td->ready = 0;
    syslog(LOG_INFO,
           "traffic_detector: nft counter active "
           "(enable=%.1fs disable=%.1fs baseline_pkts=%llu)",
           (double)enable_delay_us  / 1e6,
           (double)disable_delay_us / 1e6,
           (unsigned long long)td->prev_pkt_count);
    return 0;
}

void traffic_detector_cleanup(traffic_detector_t *td)
{
    if (td)
        memset(td, 0, sizeof(*td));
}

int traffic_detector_poll(traffic_detector_t *td, int64_t t_now_us)
{
    if (td->ready != 0)
        return 1;

    if (td->t_last_poll_us != 0 &&
        (t_now_us - td->t_last_poll_us) < TDETECT_COUNTER_POLL_US)
        return traffic_detector_is_active(td);

    td->t_last_poll_us = t_now_us;

    uint64_t curr = read_gaming_pkt_count();
    if (curr == UINT64_MAX) {
        syslog(LOG_DEBUG, "traffic_detector: nft counter read failed, retrying");
        return traffic_detector_is_active(td);
    }

    int saw_traffic = (curr > td->prev_pkt_count);
    td->counter_active = saw_traffic;
    td->prev_pkt_count = curr;

    if (saw_traffic)
        td->t_last_traffic_us = t_now_us;

    int arm_gone = (td->t_last_traffic_us > 0 &&
                    (t_now_us - td->t_last_traffic_us) > TDETECT_ARM_GRACE_US);

    int active_gone = (td->t_last_traffic_us > 0 &&
                       (t_now_us - td->t_last_traffic_us) > TDETECT_ACTIVE_GRACE_US);

    tdetect_state_t prev_state = td->state;

    switch (td->state) {

    case TDETECT_IDLE:
        if (saw_traffic) {
            td->state          = TDETECT_ARMING;
            td->t_arm_start_us = t_now_us;
        }
        break;

    case TDETECT_ARMING:
        if (arm_gone) {
            td->state = TDETECT_IDLE;
        } else if (t_now_us - td->t_arm_start_us >= td->enable_delay_us) {
            td->state = TDETECT_ACTIVE;
            td->activations++;
            syslog(LOG_INFO,
                   "darkmoon-shaper: latency-sensitive traffic detected "
                   "(active for %.1fs), engaging CAKE shaping",
                   (double)td->enable_delay_us / 1e6);
        }
        break;

    case TDETECT_ACTIVE:
        if (active_gone) {
            td->state           = TDETECT_COOLING;
            td->t_cool_start_us = t_now_us;
        }
        break;

    case TDETECT_COOLING:
        if (saw_traffic) {
            td->state = TDETECT_ACTIVE;
        } else if (t_now_us - td->t_cool_start_us >= td->disable_delay_us) {
            td->state = TDETECT_IDLE;
            syslog(LOG_INFO,
                   "darkmoon-shaper: no latency-sensitive traffic for %.1fs, "
                   "bypassing CAKE shaping (full line speed)",
                   (double)td->disable_delay_us / 1e6);
        }
        break;
    }

    if (prev_state != td->state)
        syslog(LOG_DEBUG,
               "traffic_detector: state %d→%d (counter=%llu saw_traffic=%d)",
               (int)prev_state, (int)td->state,
               (unsigned long long)curr, saw_traffic);

    return traffic_detector_is_active(td);
}
